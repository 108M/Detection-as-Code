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
    output: Path = typer.Option(BUILD_DIR, help="Output directory for reports."),
) -> None:
    """Generate ATT&CK Navigator layer and coverage report."""
    _not_implemented("coverage")


@app.command()
def deploy(
    dry_run: bool = typer.Option(False, "--dry-run", help="Show changes without applying them."),
) -> None:
    """Sync rules with Kibana Detection Engine."""
    _not_implemented("deploy")


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
) -> None:
    """Create pipeline role, user, API key and test index template (idempotent)."""
    try:
        lab_mod.setup(Settings.load(), log=typer.echo, timeout=timeout)
    except lab_mod.LabError as exc:
        typer.secho(str(exc), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from exc
    typer.secho("Lab ready. Verify with: dac lab check", fg=typer.colors.GREEN)


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
