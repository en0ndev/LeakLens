"""Typer CLI for LeakLens scanning workflows."""

from __future__ import annotations

from pathlib import Path
from typing import Literal, Optional, Tuple

import typer

from . import __version__
from .baseline import baseline_payload
from .config import LeakLensConfig, discover_config_path, load_config
from .engine import ScanEngine, should_fail
from .models import ScanResult, Severity
from .reporters import render_json, render_sarif, render_terminal
from .rules import format_rule_listing
from .verification import verify_findings

app = typer.Typer(
    help="LeakLens: Git credential and secret detection.",
    no_args_is_help=True,
    invoke_without_command=True,
)
rules_app = typer.Typer(help="Inspect active detection rules.")
app.add_typer(rules_app, name="rules")

OutputFormat = Literal["terminal", "json", "sarif"]
ReportFormat = Literal["json", "sarif"]


@app.callback()
def main_callback(
    version: bool = typer.Option(
        False,
        "--version",
        help="Show LeakLens version and exit.",
        is_eager=True,
    ),
) -> None:
    """Global CLI options."""
    if version:
        typer.echo(f"leaklens {__version__}")
        raise typer.Exit(0)


@app.command()
def scan(
    target: Path = typer.Argument(Path("."), exists=True, readable=True, resolve_path=True),
    staged: bool = typer.Option(False, "--staged", help="Scan staged changes from git index."),
    commit: Optional[str] = typer.Option(None, "--commit", help="Scan a single commit hash."),
    diff: Optional[Tuple[str, str]] = typer.Option(
        None,
        "--diff",
        metavar="BASE HEAD",
        help="Scan git diff range from BASE to HEAD.",
    ),
    config: Optional[Path] = typer.Option(None, "--config", help="Path to leaklens.yml."),
    output_format: Optional[OutputFormat] = typer.Option(
        None, "--format", "-f", help="Output format (terminal/json/sarif)."
    ),
    fail_on: Optional[Severity] = typer.Option(None, "--fail-on", help="Fail threshold severity."),
    baseline: Optional[Path] = typer.Option(None, "--baseline", help="Baseline file path override."),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Write report to file instead of stdout."
    ),
    write_baseline: Optional[Path] = typer.Option(
        None, "--write-baseline", help="Write current findings as baseline fingerprints."
    ),
    verify: bool = typer.Option(
        False,
        "--verify",
        help="Attempt provider checks for supported secret types (network calls; secrets are never printed).",
    ),
) -> None:
    """Run a scan in repository, staged, commit, or diff mode."""
    result, cfg = _run_scan(target, staged=staged, commit=commit, diff=diff, config_path=config, baseline=baseline)
    if verify and result.findings:
        verify_findings(result.findings)

    selected_format = output_format or cfg.default_output_format
    rendered = _render(result, selected_format)
    _emit(rendered, output)

    if write_baseline is not None:
        write_baseline.write_text(_render_baseline(result), encoding="utf-8")

    threshold = fail_on or cfg.severity_threshold
    raise typer.Exit(1 if should_fail(result.findings, threshold) else 0)


@app.command()
def report(
    output_format: ReportFormat = typer.Option("json", "--format", "-f", help="Report format."),
    target: Path = typer.Argument(Path("."), exists=True, readable=True, resolve_path=True),
    staged: bool = typer.Option(False, "--staged", help="Scan staged changes from git index."),
    commit: Optional[str] = typer.Option(None, "--commit", help="Scan a single commit hash."),
    diff: Optional[Tuple[str, str]] = typer.Option(
        None,
        "--diff",
        metavar="BASE HEAD",
        help="Scan git diff range from BASE to HEAD.",
    ),
    config: Optional[Path] = typer.Option(None, "--config", help="Path to leaklens.yml."),
    fail_on: Optional[Severity] = typer.Option(None, "--fail-on", help="Fail threshold severity."),
    baseline: Optional[Path] = typer.Option(None, "--baseline", help="Baseline file path override."),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Write report to file instead of stdout."
    ),
    verify: bool = typer.Option(
        False,
        "--verify",
        help="Attempt provider checks for supported secret types (network calls; secrets are never printed).",
    ),
) -> None:
    """Generate CI-oriented JSON or SARIF report output."""
    result, cfg = _run_scan(target, staged=staged, commit=commit, diff=diff, config_path=config, baseline=baseline)
    if verify and result.findings:
        verify_findings(result.findings)

    rendered = _render(result, output_format)
    _emit(rendered, output)

    threshold = fail_on or cfg.severity_threshold
    raise typer.Exit(1 if should_fail(result.findings, threshold) else 0)


@rules_app.command("list")
def list_rules(config: Optional[Path] = typer.Option(None, "--config", help="Path to leaklens.yml.")) -> None:
    """List active built-in and custom regex rules."""
    cfg_path = discover_config_path(config)
    cfg = load_config(cfg_path)
    typer.echo(format_rule_listing(cfg.all_rules))


def _run_scan(
    target: Path,
    *,
    staged: bool,
    commit: Optional[str],
    diff: Optional[Tuple[str, str]],
    config_path: Optional[Path],
    baseline: Optional[Path],
) -> tuple[ScanResult, LeakLensConfig]:
    cfg_file = discover_config_path(config_path)
    cfg = load_config(cfg_file)
    if baseline is not None:
        cfg.baseline_file = str(baseline)

    _validate_mode_flags(staged, commit, diff)

    engine = ScanEngine(cfg, repo_root=Path.cwd())

    if staged:
        _require_git_repo(engine)
        return engine.scan_staged(), cfg
    if commit:
        _require_git_repo(engine)
        return engine.scan_commit(commit), cfg
    if diff:
        _require_git_repo(engine)
        return engine.scan_diff(diff[0], diff[1]), cfg

    return engine.scan_repository(target), cfg


def _validate_mode_flags(staged: bool, commit: Optional[str], diff: Optional[Tuple[str, str]]) -> None:
    active = [bool(staged), bool(commit), bool(diff)]
    if sum(active) > 1:
        raise typer.BadParameter("Use only one of --staged, --commit, or --diff.")


def _require_git_repo(engine: ScanEngine) -> None:
    if not engine.git.is_repository():
        raise typer.BadParameter("Current directory is not a Git repository.")


def _render(result: ScanResult, fmt: OutputFormat | ReportFormat) -> str:
    if fmt == "json":
        return render_json(result)
    if fmt == "sarif":
        return render_sarif(result)
    return render_terminal(result)


def _render_baseline(result: ScanResult) -> str:
    import json

    return json.dumps(baseline_payload(result.findings), indent=2, sort_keys=True)


def _emit(content: str, output: Optional[Path]) -> None:
    if output is None:
        typer.echo(content)
        return
    output.write_text(content, encoding="utf-8")


def main() -> None:
    """Console script entrypoint."""
    app()
