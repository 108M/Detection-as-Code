"""Command line entry point for the Detection-as-Code pipeline."""

from pathlib import Path

import typer

from dac import __version__

app = typer.Typer(
    help="Detection-as-Code pipeline: Sigma -> CI tests -> Elastic.",
    no_args_is_help=True,
)

RULES_DIR = Path("rules")
BUILD_DIR = Path("build")


def _not_implemented(stage: str) -> None:
    typer.secho(f"[{stage}] not implemented yet", fg=typer.colors.YELLOW)
    raise typer.Exit(code=1)


@app.command()
def validate(rules: Path = typer.Option(RULES_DIR, help="Directory with Sigma rules.")) -> None:
    """Check Sigma syntax, required metadata and ATT&CK tags."""
    _not_implemented("validate")


@app.command()
def convert(
    rules: Path = typer.Option(RULES_DIR, help="Directory with Sigma rules."),
    output: Path = typer.Option(BUILD_DIR / "rules.ndjson", help="Output ndjson file."),
) -> None:
    """Convert Sigma rules into Elastic detection rules (ndjson)."""
    _not_implemented("convert")


@app.command()
def test(
    cases: Path = typer.Option(Path("tests/cases"), help="Directory with test case manifests."),
) -> None:
    """Run converted rules against attack and benign telemetry."""
    _not_implemented("test")


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


if __name__ == "__main__":
    app()
