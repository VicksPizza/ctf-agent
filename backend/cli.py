"""Click CLI entry point."""

from __future__ import annotations

import asyncio
import json
import logging
import re
import sys
from pathlib import Path

import click
from rich.console import Console

from backend.config import Settings

console = Console()


def _setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    for name in ("httpx", "httpcore", "botocore", "urllib3", "aiodocker"):
        logging.getLogger(name).setLevel(logging.WARNING)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)-8s %(message)s", datefmt="%X"))
    logging.basicConfig(level=level, handlers=[handler], force=True)


@click.command()
@click.option("--targets", default="targets.yml", help="Path to targets YAML file")
@click.option("--target", default=None, help="Target name to research")
@click.option("--image", default="vuln-research-sandbox", help="Docker sandbox image name")
@click.option("--models", multiple=True, help="Model specs")
@click.option("--max-swarms", default=10, type=int, help="Max concurrent scanner swarms")
@click.option("--max-iterations", default=1, type=int, help="Max iterations per scanner swarm")
@click.option("--output", default="report.md", help="Output report path")
@click.option("--json-output", default="report.json", help="Output JSON report path")
@click.option("--coordinator", default="claude", type=click.Choice(["claude", "codex"]), help="Coordinator backend")
@click.option("-v", "--verbose", is_flag=True, help="Verbose logging")
def main(
    targets: str,
    target: str | None,
    image: str,
    models: tuple[str, ...],
    max_swarms: int,
    max_iterations: int,
    output: str,
    json_output: str,
    coordinator: str,
    verbose: bool,
) -> None:
    """Run authorized AI vulnerability research against configured targets."""
    _setup_logging(verbose)
    settings = Settings(
        sandbox_image=image,
        targets_file=targets,
        max_concurrent_swarms=max_swarms,
        max_iterations_per_swarm=max_iterations,
    )
    model_specs = list(models) if models else []

    console.print("[bold cyan]Vuln Research Agent[/bold cyan]")
    console.print(f"  Targets: {targets}")
    console.print(f"  Models: {', '.join(model_specs) if model_specs else 'scanner swarm defaults'}")
    console.print(f"  Sandbox: {settings.sandbox_image}")
    console.print(f"  Max scanner swarms: {max_swarms}")
    console.print()

    if target:
        asyncio.run(_run_single_target(settings, target, model_specs, output, json_output, coordinator))
    else:
        asyncio.run(_run_all_targets(settings, model_specs, output, json_output, coordinator))


async def _run_single_target(
    settings: Settings,
    target_name: str,
    model_specs: list[str],
    output: str,
    json_output: str,
    coordinator_backend: str,
) -> None:
    from backend.sandbox import cleanup_orphan_containers, configure_semaphore
    from backend.target_loader import load_targets

    configure_semaphore(settings.max_concurrent_swarms * max(1, len(model_specs)))
    await cleanup_orphan_containers()

    try:
        targets = load_targets(settings.targets_file)
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"[red]Error loading targets: {exc}[/red]")
        sys.exit(1)

    selected = next((item for item in targets if item.name == target_name), None)
    if not selected:
        console.print(f"[red]Target {target_name!r} not found[/red]")
        console.print(f"[yellow]Available targets: {', '.join(item.name for item in targets)}[/yellow]")
        sys.exit(1)

    findings, tracker = await _run_research(settings, selected, model_specs, coordinator_backend)
    await _write_report(findings, selected, tracker, output, json_output)


async def _run_all_targets(
    settings: Settings,
    model_specs: list[str],
    output: str,
    json_output: str,
    coordinator_backend: str,
) -> None:
    from backend.reporter import CostTracker, generate_summary_report
    from backend.sandbox import cleanup_orphan_containers, configure_semaphore
    from backend.target_loader import load_targets

    configure_semaphore(settings.max_concurrent_swarms * max(1, len(model_specs)))
    await cleanup_orphan_containers()

    try:
        targets = load_targets(settings.targets_file)
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"[red]Error loading targets: {exc}[/red]")
        sys.exit(1)

    reports_dir = _reports_dir(output)
    reports_dir.mkdir(parents=True, exist_ok=True)
    json_reports_dir = _reports_dir(json_output)
    json_reports_dir.mkdir(parents=True, exist_ok=True)

    target_reports = []
    total_tracker = CostTracker()
    for item in targets:
        console.print(f"[bold]Researching:[/bold] {item.name}")
        findings, tracker = await _run_research(settings, item, model_specs, coordinator_backend)
        target_output = reports_dir / f"{_safe_filename(item.name)}.md"
        target_json_output = json_reports_dir / f"{_safe_filename(item.name)}.json"
        report = await _write_report(findings, item, tracker, str(target_output), str(target_json_output), quiet=True)
        target_reports.append(
            {
                "target": item,
                "report": report,
                "markdown_path": str(target_output),
                "json_path": str(target_json_output),
            }
        )
        for call in tracker.calls:
            total_tracker.record(call)

    summary = await generate_summary_report(target_reports, total_tracker)
    Path(output).write_text(summary["markdown"], encoding="utf-8")
    Path(json_output).write_text(json.dumps(summary["json"], indent=2), encoding="utf-8")

    console.print("\n[bold green]Research Complete[/bold green]")
    console.print(f"  Targets: {len(target_reports)}")
    console.print(f"  Confirmed: {summary['summary']['total_confirmed']}")
    console.print(f"  Critical: {summary['summary']['critical']}")
    console.print(f"  High: {summary['summary']['high']}")
    console.print(f"  Total Cost: ${summary['cost_summary']['total_usd']:.2f}")
    console.print(f"  Summary Report: {output}")
    console.print(f"  Summary JSON: {json_output}")
    console.print(f"  Per-target reports: {reports_dir}")


async def _run_research(settings: Settings, target, model_specs: list[str], coordinator_backend: str):
    if coordinator_backend == "codex":
        from backend.agents.codex_coordinator import run_codex_researcher

        return await run_codex_researcher(settings=settings, target=target, model_specs=model_specs)
    from backend.agents.claude_coordinator import run_claude_researcher

    return await run_claude_researcher(settings=settings, target=target, model_specs=model_specs)


def _reports_dir(path: str) -> Path:
    report_path = Path(path)
    stem = report_path.stem or "report"
    return report_path.with_name(stem)


def _safe_filename(value: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "-", value.strip()).strip(".-")
    return safe or "target"


async def _write_report(findings, target, tracker, output: str, json_output: str, quiet: bool = False):
    from backend.reporter import generate_report

    report = await generate_report(findings, target, tracker)
    Path(output).parent.mkdir(parents=True, exist_ok=True)
    Path(json_output).parent.mkdir(parents=True, exist_ok=True)
    Path(output).write_text(report["markdown"], encoding="utf-8")
    Path(json_output).write_text(json.dumps(report["json"], indent=2), encoding="utf-8")

    if quiet:
        return report

    console.print("\n[bold green]Research Complete[/bold green]")
    console.print(f"  Confirmed: {report['summary']['total_confirmed']}")
    console.print(f"  Critical: {report['summary']['critical']}")
    console.print(f"  High: {report['summary']['high']}")
    console.print(f"  Total Cost: ${report['cost_summary']['total_usd']:.2f}")
    console.print(f"  Report: {output}")
    console.print(f"  JSON: {json_output}")
    return report


@click.command()
@click.argument("message")
@click.option("--port", default=9400, type=int, help="Researcher message port")
@click.option("--host", default="127.0.0.1", help="Researcher host")
def msg(message: str, port: int, host: str) -> None:
    """Send a message to a running research session."""
    import urllib.request

    body = json.dumps({"message": message}).encode()
    req = urllib.request.Request(
        f"http://{host}:{port}/msg",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
            console.print(f"[green]Sent:[/green] {data.get('queued', message[:200])}")
    except Exception as exc:
        console.print(f"[red]Failed:[/red] {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
