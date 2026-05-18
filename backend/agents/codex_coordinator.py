"""Codex coordinator entry point for the default research workflow."""

from __future__ import annotations

from backend.agents.claude_coordinator import run_claude_researcher
from backend.agents.coordinator_core import COORDINATOR_PROMPT


async def run_codex_researcher(settings, target, model_specs=None):
    _ = COORDINATOR_PROMPT
    return await run_claude_researcher(settings, target, model_specs)


run_codex_coordinator = run_codex_researcher
