"""Command line entry point for the Detection-as-Code pipeline."""

import os
from pathlib import Path

import typer

from dac import __version__
from dac import lab as lab_mod
from dac.config import ENV_FILE, Settings

app = typer.Typer(
    help="Detection-as-Code pipeline: Sigma -> CI tests -> Elastic.",
    no_args_is_help=True,
)
lab_app = typer.Typer(help="Manage the local Elastic lab.", no_args_is_help=True)
app.add_typer(lab_app, name="lab")

RULES_DIR = Path("rules")
BUILD_DIR = Path("build")


def _not_implemented(stage: str) -> None:
    typer.secho(f"[{stage}] not implemented yet", fg=typer.colors.YELLOW)
    raise typer.Exit(code=1)


@app.command()
def validate(
    rules: Path = typer.Option(RULES_DIR, help="Directory with Sigma rules."),
    cases: Path = typer.Option(Path("tests/cases"), help="Directory with test case manifests."),
    strict: bool = typer.Option(False, "--strict", help="Treat warnings as errors."),
) -> None:
    """Check Sigma syntax, required metadata and ATT&CK tags."""
    from dac.validate import Severity
    from dac.validate import validate as run_validate

    issues, total = run_validate(rules, cases)
    in_ci = os.environ.get("GITHUB_ACTIONS") == "true"
    for issue in issues:
        is_error = issue.severity == Severity.ERROR or strict
        if in_ci:
            level = "error" if is_error else "warning"
            typer.echo(
                f"::{level} file={issue.path.as_posix()},title={issue.code}::{issue.message}"
            )
        else:
            color = typer.colors.RED if is_error else typer.colors.YELLOW
            typer.secho(str(issue), fg=color)

    errors = sum(1 for i in issues if i.severity == Severity.ERROR or strict)
    warnings = len(issues) - errors
    bad_files = len({i.path for i in issues if i.severity == Severity.ERROR or strict})
    summary = f"{total} rules checked: {total - bad_files} ok, {errors} errors, {warnings} warnings"
    typer.secho(summary, fg=typer.colors.RED if errors else typer.colors.GREEN, bold=True)
    if errors:
        raise typer.Exit(code=1)


@app.command()
def convert(
    rules: Path = typer.Option(RULES_DIR, help="Directory with Sigma rules."),
    output: Path = typer.Option(BUILD_DIR / "rules.ndjson", help="Output ndjson file."),
    index: list[str] = typer.Option(
        None, "--index", help="Override target indices (repeatable), e.g. dac-test-*."
    ),
    show: bool = typer.Option(False, "--show", help="Print each generated EQL query."),
) -> None:
    """Convert Sigma rules into Elastic detection rules (ndjson)."""
    from dac.convert import convert as run_convert
    from dac.convert import write_ndjson
    from dac.validate import discover

    result = run_convert(discover(rules), index_override=index or None)
    for path, message in result.errors:
        typer.secho(f"{path.as_posix()}: error: {message}", fg=typer.colors.RED, err=True)
    for r in result.rules:
        typer.echo(f"  {r.rule_id}  {r.title}")
        if show:
            typer.secho(f"    {r.query}", fg=typer.colors.CYAN)
    write_ndjson(result.rules, output)
    color = typer.colors.RED if result.errors else typer.colors.GREEN
    typer.secho(
        f"{len(result.rules)} rules written to {output.as_posix()}, {len(result.errors)} errors",
        fg=color,
        bold=True,
    )
    if result.errors:
        raise typer.Exit(code=1)


@app.command()
def test(
    rules: Path = typer.Option(RULES_DIR, help="Directory with Sigma rules."),
    cases: Path = typer.Option(Path("tests/cases"), help="Directory with test case manifests."),
    report: Path = typer.Option(BUILD_DIR / "test-report.json", help="JSON report output."),
    reload: bool = typer.Option(False, "--reload", help="Re-index every dataset."),
) -> None:
    """Run converted rules against attack and benign telemetry."""
    from dac import testing

    try:
        result = testing.run(Settings.load(), rules, cases, force_reload=reload, log=typer.echo)
    except (testing.TestSetupError, OSError) as exc:
        typer.secho(str(exc), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc

    colors = {
        "pass": typer.colors.GREEN,
        "fail": typer.colors.RED,
        "untested": typer.colors.YELLOW,
        "error": typer.colors.RED,
    }
    in_ci = os.environ.get("GITHUB_ACTIONS") == "true"
    for r in result.rules:
        typer.secho(
            f"[{r.status.upper():8}] {r.title}  (TP hits {r.tp_hits}, FP hits "
            f"{r.fp_hits}, unlabeled {r.hits_of('unlabeled')})",
            fg=colors.get(r.status),
        )
        for d in r.results:
            if d.hits or d.expected == "detects":
                typer.echo(f"      {d.expected:15} {d.dataset:48} {d.hits:6}  {d.note}")
        for m in r.messages:
            typer.secho(f"      ! {m}", fg=colors.get(r.status))
            if in_ci and r.status in ("fail", "error"):
                typer.echo(f"::error file={r.path},title=dac test::{m}")

    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(result.to_json(), encoding="utf-8")
    summary_md = testing.markdown_summary(result)
    if step_summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(step_summary, "a", encoding="utf-8") as fh:
            fh.write(summary_md)
    s = result.summary
    failed = s["failed"] + s["errors"]
    typer.secho(
        f"{s['passed']}/{s['rules']} rules passed, {s['failed']} failed, "
        f"{s['untested']} untested | detection rate {testing._pct(s['detection_rate'])} | "
        f"FP hits {s['false_positive_hits']} | precision {testing._pct(s['alert_precision'])} | "
        f"{s['events']:,} events",
        fg=typer.colors.RED if failed else typer.colors.GREEN,
        bold=True,
    )
    if failed:
        raise typer.Exit(code=1)


datasets_app = typer.Typer(help="Manage test datasets.", no_args_is_help=True)
app.add_typer(datasets_app, name="datasets")


@datasets_app.command("fetch")
def datasets_fetch() -> None:
    """Download and verify every dataset in tests/datasets/sources.yml."""
    from dac.datasets import DatasetError, fetch, load_manifest

    failed = False
    for ds in load_manifest():
        try:
            digest = fetch(ds, log=typer.echo)
        except (DatasetError, OSError) as exc:
            typer.secho(f"  {ds.id}: {exc}", fg=typer.colors.RED)
            failed = True
            continue
        if not ds.sha256 and not ds.local_path:
            typer.secho(f"  {ds.id}: not pinned, sha256: {digest}", fg=typer.colors.YELLOW)
            failed = True
        else:
            typer.echo(f"  {ds.id}: ok")
    if failed:
        raise typer.Exit(code=1)


@app.command()
def coverage(
    rules: Path = typer.Option(RULES_DIR, help="Directory with Sigma rules."),
    cases: Path = typer.Option(Path("tests/cases"), help="Directory with test case manifests."),
    report: Path = typer.Option(
        BUILD_DIR / "test-report.json", help="`dac test` report (optional, adds test status)."
    ),
    output: Path = typer.Option(BUILD_DIR / "site", help="Output directory (static site)."),
    site_url: str = typer.Option(
        None, envvar="DAC_SITE_URL", help="Public URL of the site (Navigator layer link)."
    ),
) -> None:
    """Generate the ATT&CK Navigator layer and the coverage report."""
    from dac import coverage as cov

    if not report.exists():
        typer.secho(f"{report} not found: coverage without test status", fg=typer.colors.YELLOW)
    model = cov.build(rules, cases, report)
    written = cov.write_site(model, output, site_url or cov.DEFAULT_SITE_URL, report)
    s = model.summary
    for t in model.tactics:
        if t.covered:
            typer.echo(
                f"  {t.name:22} {t.covered:>2}/{t.total:<3} {', '.join(x.id for x in t.techniques)}"
            )
    if step_summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(step_summary, "a", encoding="utf-8") as fh:
            fh.write(cov.markdown(model, site_url))
    typer.secho(
        f"{s['techniques']} techniques ({s['techniques_tested']} tested) in "
        f"{s['tactics_covered']}/{s['tactics_total']} tactics -> {len(written)} files in "
        f"{output.as_posix()}",
        fg=typer.colors.GREEN,
        bold=True,
    )


@app.command()
def deploy(
    rules: Path = typer.Option(RULES_DIR, help="Directory with Sigma rules."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show changes without applying them."),
    prune: bool = typer.Option(
        False, "--prune", help="Delete managed rules no longer in the repo (default: disable)."
    ),
    index: list[str] = typer.Option(None, "--index", help="Override target indices (repeatable)."),
    force: bool = typer.Option(
        False, "--force", help="Redeploy every rule (e.g. after rotating the API key)."
    ),
) -> None:
    """Sync rules with Kibana Detection Engine (the repository is the source of truth)."""
    from dac import deploy as dep
    from dac.convert import convert as run_convert
    from dac.validate import discover

    conversion = run_convert(discover(rules), index_override=index or None)
    if conversion.errors:
        for path, message in conversion.errors:
            typer.secho(f"{path.as_posix()}: error: {message}", fg=typer.colors.RED, err=True)
        typer.secho("Conversion failed: nothing deployed.", fg=typer.colors.RED, bold=True)
        raise typer.Exit(code=1)

    try:
        api = dep.KibanaRulesApi(Settings.load())
        current = api.find_managed()
    except (dep.DeployError, OSError) as exc:
        typer.secho(str(exc), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc

    the_plan = dep.plan(conversion.rules, current, prune=prune, force=force)
    colors = {
        "create": typer.colors.GREEN,
        "update": typer.colors.CYAN,
        "drift": typer.colors.MAGENTA,
        "disable": typer.colors.YELLOW,
        "delete": typer.colors.RED,
    }
    for a in the_plan.actions:
        if a.kind == "unchanged" and not a.detail:
            continue
        typer.secho(
            f"  {a.kind:9} {a.name}" + (f"  ({a.detail})" if a.detail else ""),
            fg=colors.get(a.kind),
        )
    summary = ", ".join(
        f"{the_plan.count(k)} {k}"
        for k in ("create", "update", "drift", "disable", "delete", "unchanged")
        if the_plan.count(k)
    )
    if dry_run or not the_plan.changes:
        prefix = "Dry run" if dry_run else "Kibana is in sync"
        typer.secho(f"{prefix}: {summary}", bold=True)
        return

    errors = dep.apply(the_plan, api, log=lambda _: None)
    for e in errors:
        typer.secho(f"  {e}", fg=typer.colors.RED)
    typer.secho(
        f"Deployed to {Settings.load().kibana_url}: {summary}"
        + (f", {len(errors)} errors" if errors else ""),
        fg=typer.colors.RED if errors else typer.colors.GREEN,
        bold=True,
    )
    if errors:
        raise typer.Exit(code=1)


@app.command()
def version() -> None:
    """Show version."""
    typer.echo(__version__)


@lab_app.command("init")
def lab_init(force: bool = typer.Option(False, "--force", help="Overwrite lab/.env.")) -> None:
    """Create lab/.env with random secrets."""
    if lab_mod.init_env(force=force):
        typer.secho(f"Created {ENV_FILE} with random secrets.", fg=typer.colors.GREEN)
        typer.echo("Next: docker compose -f lab/docker-compose.yml up -d && dac lab setup")
    else:
        typer.echo(f"{ENV_FILE} already exists (use --force to regenerate).")


@lab_app.command("setup")
def lab_setup(
    timeout: int = typer.Option(300, help="Seconds to wait for Elasticsearch/Kibana."),
    rotate_key: bool = typer.Option(
        False, "--rotate-key", help="Create a new API key and invalidate the old ones."
    ),
) -> None:
    """Create pipeline role, user, API key and index templates (idempotent)."""
    try:
        lab_mod.setup(Settings.load(), log=typer.echo, timeout=timeout, rotate_key=rotate_key)
    except lab_mod.LabError as exc:
        typer.secho(str(exc), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from exc
    typer.secho("Lab ready. Verify with: dac lab check", fg=typer.colors.GREEN)


@lab_app.command("replay")
def lab_replay(
    datasets: list[str] = typer.Argument(None, help="Dataset ids from tests/datasets/sources.yml."),
    clean: bool = typer.Option(False, "--clean", help="Delete all replay indices."),
) -> None:
    """Replay datasets with current timestamps so deployed rules raise alerts in Kibana."""
    from dac import replay as rep
    from dac.datasets import load_manifest
    from dac.testing import es_client

    es = es_client(Settings.load())
    if clean:
        typer.echo(f"Deleted {rep.clean(es)} replay indices.")
        return
    known = {d.id: d for d in load_manifest()}
    if not datasets:
        typer.echo("Available datasets:")
        for ds_id in sorted(known):
            typer.echo(f"  {ds_id}")
        raise typer.Exit(code=1)
    for ds_id in datasets:
        if ds_id not in known:
            typer.secho(f"unknown dataset {ds_id}", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=1)
        index, n = rep.replay(es, known[ds_id], log=typer.echo)
        typer.secho(
            f"  {n} events -> {index} (last {rep.WINDOW.seconds // 60} min)", fg=typer.colors.GREEN
        )
    typer.echo("Alerts appear in Kibana > Security > Alerts after the next rule run (<= 5 min).")


@lab_app.command("check")
def lab_check() -> None:
    """Verify the lab is reachable with the pipeline API key."""
    results = lab_mod.check(Settings.load())
    for name, ok, detail in results:
        mark = typer.style(
            "OK  " if ok else "FAIL", fg=typer.colors.GREEN if ok else typer.colors.RED
        )
        typer.echo(f"[{mark}] {name}: {detail}")
    if not all(ok for _, ok, _ in results):
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
