"""Vulnerability finding model and deduplication helpers."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal

Severity = Literal["critical", "high", "medium", "low", "info"]


@dataclass
class Finding:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    vuln_class: str = ""
    affected_component: str = ""
    severity: Severity = "medium"
    proof_of_concept: str = ""
    evidence: str = ""
    confirmed: bool = False
    solver_model: str = ""
    timestamp: datetime = field(default_factory=datetime.utcnow)
    description: str = ""


def deduplicate(findings: list[Finding]) -> list[Finding]:
    """Merge findings with the same vulnerability class and affected component."""
    merged: dict[tuple[str, str], Finding] = {}
    rank = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}

    for finding in findings:
        key = (finding.vuln_class.lower(), finding.affected_component.lower())
        existing = merged.get(key)
        if existing is None:
            merged[key] = finding
            continue

        if finding.confirmed and not existing.confirmed or rank.get(finding.severity, 0) > rank.get(existing.severity, 0):
            winner = finding
        else:
            winner = existing

        if not winner.proof_of_concept:
            winner.proof_of_concept = finding.proof_of_concept or existing.proof_of_concept
        if not winner.evidence:
            winner.evidence = finding.evidence or existing.evidence
        if not winner.description:
            winner.description = finding.description or existing.description
        winner.timestamp = max(existing.timestamp, finding.timestamp)
        merged[key] = winner

    return sorted(merged.values(), key=lambda item: (not item.confirmed, item.severity, item.timestamp))
