"""Structured output schema for scanner agents."""

from __future__ import annotations

from pydantic import BaseModel, Field


class FindingOutput(BaseModel):
    type: str = Field(default="finding")
    vuln_class: str
    affected_component: str
    severity: str
    proof_of_concept: str
    evidence: str
    confirmed: bool
    description: str = ""


def scanner_output_json_schema() -> dict:
    return {
        "type": "object",
        "properties": {
            "type": {"type": "string", "enum": ["finding", "no_finding"]},
            "vuln_class": {"type": "string"},
            "affected_component": {"type": "string"},
            "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
            "proof_of_concept": {"type": "string"},
            "evidence": {"type": "string"},
            "confirmed": {"type": "boolean"},
            "description": {"type": "string"},
        },
        "required": [
            "type",
            "vuln_class",
            "affected_component",
            "severity",
            "proof_of_concept",
            "evidence",
            "confirmed",
        ],
        "additionalProperties": False,
    }
