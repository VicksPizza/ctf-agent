"""Shared coordinator logic for authorized vulnerability research."""

from __future__ import annotations

import asyncio
import json
import logging

from backend.agents.solver import validate_finding
from backend.agents.swarm import ScannerSwarm
from backend.deps import CoordinatorDeps
from backend.finding import deduplicate

logger = logging.getLogger(__name__)

COORDINATOR_PROMPT = """
You are a security research coordinator managing authorized vulnerability
research on an open-source target.

Your responsibilities:
1. Analyze the target attack surface from its description and source.
2. Assign specialized scanner swarms to unexplored components.
3. Review scanner findings and request proof-of-concept confirmation when needed.
4. De-duplicate and prioritize findings by severity.
5. Stop a scanner swarm when it has exhausted its search space.
6. Compile a final vulnerability report when all scanner swarms complete.

Scope rules (STRICT):
- Scanners may ONLY interact with hosts in scope_allowlist.
- Never exfiltrate data outside the sandbox.
- Never modify target data during read-only testing.

A finding is valid only when confirmed=True and proof_of_concept is non-empty
and reproducible.
"""


async def do_get_research_status(deps: CoordinatorDeps) -> str:
    return json.dumps(
        {
            "target": deps.target.name,
            "active_swarms": {name: swarm.get_status() for name, swarm in deps.swarms.items()},
            "confirmed_findings": [finding.affected_component for finding in deps.findings if finding.confirmed],
        },
        indent=2,
    )


async def do_spawn_swarm(deps: CoordinatorDeps, vuln_class: str) -> str:
    if vuln_class in deps.swarms:
        return f"Scanner swarm already running for {vuln_class}"
    if len(deps.swarms) >= deps.max_concurrent_swarms:
        return "At scanner swarm capacity."
    swarm = ScannerSwarm(
        target=deps.target,
        vuln_class=vuln_class,
        cost_tracker=deps.cost_tracker,
        settings=deps.settings,
        model_specs=deps.model_specs,
        max_iterations=deps.max_iterations,
        coordinator_inbox=deps.coordinator_inbox,
    )
    deps.swarms[vuln_class] = swarm

    async def run_and_record() -> None:
        finding = await swarm.run()
        if finding and validate_finding(finding):
            deps.findings = deduplicate([*deps.findings, finding])

    deps.swarm_tasks[vuln_class] = asyncio.create_task(run_and_record(), name=f"swarm-{vuln_class}")
    return f"Scanner swarm spawned for {vuln_class}"


async def do_check_swarm_status(deps: CoordinatorDeps, vuln_class: str) -> str:
    swarm = deps.swarms.get(vuln_class)
    if not swarm:
        return f"No scanner swarm running for {vuln_class}"
    return json.dumps(swarm.get_status(), indent=2)


async def do_stop_swarm(deps: CoordinatorDeps, vuln_class: str) -> str:
    swarm = deps.swarms.get(vuln_class)
    if not swarm:
        return f"No scanner swarm running for {vuln_class}"
    swarm.kill()
    return f"Scanner swarm stopped for {vuln_class}"


async def run_research_session(deps: CoordinatorDeps) -> tuple[list, object]:
    for vuln_class in deps.target.vuln_classes:
        while len([task for task in deps.swarm_tasks.values() if not task.done()]) >= deps.max_concurrent_swarms:
            await asyncio.sleep(1)
        await do_spawn_swarm(deps, vuln_class)
    if deps.swarm_tasks:
        await asyncio.gather(*deps.swarm_tasks.values(), return_exceptions=True)
    deps.findings = deduplicate(deps.findings)
    return deps.findings, deps.cost_tracker
