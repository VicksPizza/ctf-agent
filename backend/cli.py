"""Click CLI entry point."""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from pathlib import Path

import click
from rich.console import Console

from backend.config import Settings
from backend.models import DEFAULT_MODELS

console = Console()


def _setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("botocore").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("aiodocker").setLevel(logging.WARNING)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)-8s %(message)s", datefmt="%X"))
    logging.basicConfig(level=level, handlers=[handler], force=True)


@click.command()
@click.option("--targets", default="targets.yml", help="Path to targets YAML file")
@click.option("--target", default=None, help="Target name to research (solves single target)")
@click.option("--image", default="ctf-sandbox", help="Docker sandbox image name")
@click.option("--models", multiple=True, help="Model specs (default: all configured)")
@click.option("--max-swarms", default=10, type=int, help="Max concurrent vulnerability swarms")
@click.option("--max-iterations", default=50, type=int, help="Max iterations per swarm")
@click.option("--output", default="report.md", help="Output report path (Markdown)")
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
    """Vulnerability Research Tool — AI-powered security analysis for open-source targets.

    Specify targets in a YAML file (default: targets.yml) or use --target for a single target.
    """
    _setup_logging(verbose)

    settings = Settings(
        sandbox_image=image,
        targets_file=targets,
        max_concurrent_swarms=max_swarms,
        max_iterations_per_swarm=max_iterations,
    )

    model_specs = list(models) if models else list(DEFAULT_MODELS)

    console.print("[bold cyan]Vulnerability Research Tool[/bold cyan]")
    console.print(f"  Targets: {targets}")
    console.print(f"  Models: {', '.join(model_specs)}")
    console.print(f"  Sandbox: {settings.sandbox_image}")
    console.print(f"  Max concurrent swarms: {max_swarms}")
    console.print()

    if target:
        asyncio.run(
            _run_single_target(
                settings, target, model_specs, output, json_output, coordinator
            )
        )
    else:
        asyncio.run(
            _run_all_targets(
                settings, model_specs, output, json_output, coordinator
            )
        )


async def _run_single_target(
    settings: Settings,
    target_name: str,
    model_specs: list[str],
    output: str,
    json_output: str,
    coordinator_backend: str,
) -> None:
    """Research a single target."""
    from backend.sandbox import cleanup_orphan_containers, configure_semaphore
    from backend.target_loader import load_targets

    max_containers = settings.max_concurrent_swarms * len(model_specs)
    configure_semaphore(max_containers)
    await cleanup_orphan_containers()

    # Load targets
    try:
        targets = load_targets(settings.targets_file)
    except (FileNotFoundError, ValueError) as e:
        console.print(f"[red]Error loading targets: {e}[/red]")
        sys.exit(1)

    # Find matching target
    target = next((t for t in targets if t.name == target_name), None)
    if not target:
        console.print(f"[red]Target '{target_name}' not found[/red]")
        console.print(f"[yellow]Available targets: {', '.join(t.name for t in targets)}[/yellow]")
        sys.exit(1)

    console.print(f"[bold cyan]Researching Target:[/bold cyan] {target.name}")
    console.print(f"  Type: {target.type.upper()}")
    if target.url:
        console.print(f"  URL: {target.url}")
    if target.repo_url:
        console.print(f"  Repository: {target.repo_url}")
    console.print(f"  Vulnerability Classes: {', '.join(target.vuln_classes)}")
    console.print()

    # Run research
    if coordinator_backend == "codex":
        from backend.agents.codex_coordinator import run_codex_researcher
        findings, tracker = await run_codex_researcher(
            settings=settings,
            target=target,
            model_specs=model_specs,
        )
    else:
        from backend.agents.claude_coordinator import run_claude_researcher
        findings, tracker = await run_claude_researcher(
            settings=settings,
            target=target,
            model_specs=model_specs,
        )

    # Generate report
    from backend.reporter import generate_report
    report = await generate_report(findings, target, tracker)

    # Write outputs
    Path(output).write_text(report["markdown"])
    Path(json_output).write_text(json.dumps(report["json"], indent=2))

    console.print(f"\n[bold green]Research Complete[/bold green]")
    console.print(f"  Findings: {report['summary']['total_findings']}")
    console.print(f"  Confirmed: {report['summary']['total_confirmed']}")
    console.print(f"  Critical: {report['summary']['critical']}")
    console.print(f"  High: {report['summary']['high']}")
    console.print(f"  Total Cost: ${report['cost_summary']['total_usd']:.2f}")
    console.print(f"  Report: {output}")
    console.print(f"  JSON: {json_output}")


async def _run_all_targets(
    settings: Settings,
    model_specs: list[str],
    output: str,
    json_output: str,
    coordinator_backend: str,
) -> None:
    """Research all targets sequentially."""
    from backend.sandbox import cleanup_orphan_containers, configure_semaphore
    from backend.target_loader import load_targets

    max_containers = settings.max_concurrent_swarms * len(model_specs)
    configure_semaphore(max_containers)
    await cleanup_orphan_containers()

    # Load targets
    try:
        targets = load_targets(settings.targets_file)
    except (FileNotFoundError, ValueError) as e:
        console.print(f"[red]Error loading targets: {e}[/red]")
        sys.exit(1)

    console.print(f"[bold cyan]Loaded {len(targets)} target(s)[/bold cyan]\n")

    all_findings = []
    total_tracker = None

    for target in targets:
        console.print(f"[bold]Researching:[/bold] {target.name}")

        # Run research
        if coordinator_backend == "codex":
            from backend.agents.codex_coordinator import run_codex_researcher
            findings, tracker = await run_codex_researcher(
                settings=settings,
                target=target,
                model_specs=model_specs,
            )
        else:
            from backend.agents.claude_coordinator import run_claude_researcher
            findings, tracker = await run_claude_researcher(
                settings=settings,
                target=target,
                model_specs=model_specs,
            )

        all_findings.extend(findings)
        if total_tracker is None:
            from backend.reporter import CostTracker
            total_tracker = CostTracker()
        for call in tracker.calls:
            total_tracker.record(call)

        console.print(f"  Found: {len(findings)} findings\n")

    # Generate combined report
    console.print("[bold]Generating final report...[/bold]")
    from backend.reporter import generate_report, CostTracker

    if total_tracker is None:
        total_tracker = CostTracker()

    # For combined report, use first target as reference
    report = await generate_report(all_findings, targets[0], total_tracker)

    # Write outputs
    Path(output).write_text(report["markdown"])
    Path(json_output).write_text(json.dumps(report["json"], indent=2))

    console.print(f"\n[bold green]All Research Complete[/bold green]")
    console.print(f"  Total Findings: {report['summary']['total_findings']}")
    console.print(f"  Confirmed: {report['summary']['total_confirmed']}")
    console.print(f"  Critical: {report['summary']['critical']}")
    console.print(f"  High: {report['summary']['high']}")
    console.print(f"  Total Cost: ${report['cost_summary']['total_usd']:.2f}")
    console.print(f"  Report: {output}")
    console.print(f"  JSON: {json_output}")

    configure_semaphore(max_containers)
    await cleanup_orphan_containers()

    challenge_path = Path(challenge_dir)
    meta_path = challenge_path / "metadata.yml"
    if not meta_path.exists():
        console.print(f"[red]No metadata.yml found in {challenge_dir}[/red]")
        sys.exit(1)



@click.command()
@click.argument("message")
@click.option("--port", default=9400, type=int, help="Researcher message port")
@click.option("--host", default="127.0.0.1", help="Researcher host")
def msg(message: str, port: int, host: str) -> None:
    """Send a message to the running vulnerability researcher."""
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
    except Exception as e:
        console.print(f"[red]Failed:[/red] {e}")
        console.print("Is the researcher running?")
        sys.exit(1)


if __name__ == "__main__":
    main()

