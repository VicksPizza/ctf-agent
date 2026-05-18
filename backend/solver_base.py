"""Scanner result types shared by all backends."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from backend.finding import Finding

FINDING_CONFIRMED = "finding_confirmed"
NO_FINDING = "no_finding"
CANCELLED = "cancelled"
ERROR = "error"
QUOTA_ERROR = "quota_error"


@dataclass
class ScannerResult:
    finding: Finding | None
    status: str
    notes: str
    step_count: int
    cost_usd: float
    log_path: str


class ScannerProtocol(Protocol):
    model_spec: str
    agent_name: str
    sandbox: object

    async def start(self) -> None: ...
    async def run_once(self) -> ScannerResult: ...
    def bump(self, insights: str) -> None: ...
    async def stop(self) -> None: ...
