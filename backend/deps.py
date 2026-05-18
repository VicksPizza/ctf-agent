"""Shared dependency types for scanner tools."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Coroutine
from dataclasses import dataclass, field
from typing import Any

from backend.reporter import CostTracker
from backend.sandbox import DockerSandbox
from backend.target_loader import VulnTarget


@dataclass
class ScannerDeps:
    sandbox: DockerSandbox
    target: VulnTarget
    vuln_class: str
    workspace_dir: str
    use_vision: bool
    cost_tracker: CostTracker | None = None
    message_bus: Any | None = None
    model_spec: str = ""
    notify_coordinator: Callable[[str], Coroutine[Any, Any, None]] | None = None


@dataclass
class CoordinatorDeps:
    cost_tracker: CostTracker
    settings: Any
    target: VulnTarget
    model_specs: list[str] = field(default_factory=list)
    max_concurrent_swarms: int = 10
    max_iterations: int = 50
    coordinator_inbox: asyncio.Queue = field(default_factory=asyncio.Queue)
    swarms: dict[str, Any] = field(default_factory=dict)
    swarm_tasks: dict[str, asyncio.Task] = field(default_factory=dict)
    findings: list[Any] = field(default_factory=list)
