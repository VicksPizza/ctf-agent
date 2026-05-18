"""Scanner swarm orchestration."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field

from backend.agents.solver import Scanner, validate_finding
from backend.finding import Finding
from backend.message_bus import ScannerMessageBus
from backend.models import SWARM_CONFIGS
from backend.reporter import CostTracker
from backend.solver_base import ERROR, FINDING_CONFIRMED, QUOTA_ERROR, ScannerProtocol
from backend.target_loader import VulnTarget

logger = logging.getLogger(__name__)


MODEL_SPEC_MAP = {
    "claude-opus-4-6": "openai/gpt-5.4",
    "gpt-5.4": "openai/gpt-5.4",
    "gpt-5.4-mini": "openai/gpt-5.4-mini",
    "gpt-5.3-codex": "openai/gpt-5.3-codex",
}


def normalize_model_spec(model: str) -> str:
    return MODEL_SPEC_MAP.get(model, model)


@dataclass
class ScannerSwarm:
    target: VulnTarget
    vuln_class: str
    cost_tracker: CostTracker
    settings: object
    model_specs: list[str] = field(default_factory=list)
    max_iterations: int = 50
    coordinator_inbox: asyncio.Queue | None = None

    cancel_event: asyncio.Event = field(default_factory=asyncio.Event)
    scanners: dict[str, ScannerProtocol] = field(default_factory=dict)
    notes: dict[str, str] = field(default_factory=dict)
    finding: Finding | None = None
    message_bus: ScannerMessageBus = field(default_factory=ScannerMessageBus)

    def __post_init__(self) -> None:
        if not self.model_specs:
            configured = SWARM_CONFIGS.get(self.vuln_class, {}).get("models", ["gpt-5.4"])
            self.model_specs = [normalize_model_spec(model) for model in configured]

    def _make_notify_fn(self, model_spec: str):
        async def notify(message: str) -> None:
            if self.coordinator_inbox:
                self.coordinator_inbox.put_nowait(f"[{self.target.name}/{self.vuln_class}/{model_spec}] {message}")

        return notify

    def _create_scanner(self, model_spec: str) -> Scanner:
        return Scanner(
            model_spec=model_spec,
            target=self.target,
            vuln_class=self.vuln_class,
            cost_tracker=self.cost_tracker,
            settings=self.settings,
            cancel_event=self.cancel_event,
            message_bus=self.message_bus,
            notify_coordinator=self._make_notify_fn(model_spec),
        )

    async def _run_scanner(self, model_spec: str) -> Finding | None:
        scanner = self._create_scanner(model_spec)
        self.scanners[model_spec] = scanner
        try:
            await scanner.start()
            for _ in range(self.max_iterations):
                if self.cancel_event.is_set():
                    break
                result = await scanner.run_once()
                if result.notes:
                    self.notes[model_spec] = result.notes
                    await self.message_bus.post(model_spec, result.notes[:1000])
                if result.status == FINDING_CONFIRMED and result.finding and validate_finding(result.finding):
                    self.finding = result.finding
                    self.cancel_event.set()
                    logger.info("[%s/%s] confirmed by %s", self.target.name, self.vuln_class, model_spec)
                    return result.finding
                if result.status in (ERROR, QUOTA_ERROR):
                    logger.warning(
                        "[%s/%s] stopping %s after scanner error: %s",
                        self.target.name,
                        self.vuln_class,
                        model_spec,
                        result.notes[:300],
                    )
                    break
                scanner.bump("Continue expanding the search space. Prioritize reproducible evidence.")
            return None
        finally:
            await scanner.stop()

    async def run(self) -> Finding | None:
        tasks = [asyncio.create_task(self._run_scanner(spec), name=f"scanner-{self.vuln_class}-{spec}") for spec in self.model_specs]
        try:
            while tasks:
                done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                for task in done:
                    result = task.result()
                    if result:
                        self.cancel_event.set()
                        for pending_task in pending:
                            pending_task.cancel()
                        await asyncio.gather(*pending, return_exceptions=True)
                        return result
                tasks = list(pending)
            return self.finding
        finally:
            self.cancel_event.set()

    def get_status(self) -> dict:
        return {
            "target": self.target.name,
            "vuln_class": self.vuln_class,
            "done": self.cancel_event.is_set(),
            "confirmed": bool(self.finding and self.finding.confirmed),
            "models": list(self.scanners),
        }

    def kill(self) -> None:
        self.cancel_event.set()


ChallengeSwarm = ScannerSwarm
