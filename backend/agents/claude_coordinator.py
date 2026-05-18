"""Coordinator entry point for the default research workflow."""

from __future__ import annotations

from backend.agents.coordinator_core import COORDINATOR_PROMPT, run_research_session
from backend.deps import CoordinatorDeps
from backend.reporter import CostTracker


async def run_claude_researcher(settings, target, model_specs=None):
    _ = COORDINATOR_PROMPT, model_specs
    tracker = CostTracker()
    deps = CoordinatorDeps(
        cost_tracker=tracker,
        settings=settings,
        target=target,
        model_specs=list(model_specs or []),
        max_concurrent_swarms=getattr(settings, "max_concurrent_swarms", 10),
        max_iterations=getattr(settings, "max_iterations_per_swarm", 50),
    )
    return await run_research_session(deps)


run_claude_coordinator = run_claude_researcher
