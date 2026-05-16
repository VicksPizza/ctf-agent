"""Vulnerability finding model and deduplication logic."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal


@dataclass
class Finding:
    """A single confirmed or suspected vulnerability."""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    vuln_class: str = "unknown"  # "XSS", "SQLi", "Buffer Overflow", "UAF", "Auth Bypass", etc.
    affected_component: str = "unknown"  # e.g. "file.py:42" or "/api/search" or "login form"
    severity: Literal["critical", "high", "medium", "low", "info"] = "medium"
    description: str = ""  # Detailed explanation of the vulnerability
    proof_of_concept: str = ""  # payload, exploit code, or test case
    evidence: str = ""  # crash output, DOM screenshot, HTTP response, stack trace
    confirmed: bool = False  # True only if PoC was successfully executed and validated
    solver_model: str = ""  # which model found this
    timestamp: datetime = field(default_factory=datetime.utcnow)

    def __hash__(self) -> int:
        """Hash by vuln_class + affected_component for deduplication."""
        return hash((self.vuln_class, self.affected_component))

    def __eq__(self, other: object) -> bool:
        """Equality check for deduplication."""
        if not isinstance(other, Finding):
            return NotImplemented
        return (
            self.vuln_class == other.vuln_class
            and self.affected_component == other.affected_component
        )


def deduplicate(findings: list[Finding]) -> list[Finding]:
    """
    Merge findings with identical vuln_class + affected_component.
    Prefers confirmed findings and keeps the most recent timestamp.
    """
    by_signature: dict[tuple[str, str], Finding] = {}

    for finding in findings:
        key = (finding.vuln_class, finding.affected_component)

        if key not in by_signature:
            by_signature[key] = finding
        else:
            existing = by_signature[key]

            # Prefer confirmed over unconfirmed
            if finding.confirmed and not existing.confirmed:
                by_signature[key] = finding
            # Prefer critical/high severity
            elif (
                finding.severity in ("critical", "high")
                and existing.severity not in ("critical", "high")
            ):
                by_signature[key] = finding
            # Merge PoC if current is empty
            elif not existing.proof_of_concept and finding.proof_of_concept:
                existing.proof_of_concept = finding.proof_of_concept
            # Merge evidence
            elif finding.evidence and not existing.evidence:
                existing.evidence = finding.evidence
            # Keep most recent timestamp
            if finding.timestamp > existing.timestamp:
                existing.timestamp = finding.timestamp

    return sorted(by_signature.values(), key=lambda f: f.timestamp, reverse=True)
