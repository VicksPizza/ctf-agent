"""Vulnerability report generation and cost tracking."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from backend.finding import Finding
from backend.target_loader import VulnTarget


@dataclass
class ModelCall:
    """Record of a single LLM API call."""

    model: str
    swarm_id: str
    vuln_class: str
    input_tokens: int
    output_tokens: int
    timestamp: datetime = field(default_factory=datetime.utcnow)


class CostTracker:
    """Track and calculate costs across all LLM calls in a research session."""

    # Pricing per million tokens (update as models change)
    PRICE_PER_MILLION = {
        "claude-opus-4-6": {"input": 15.00, "output": 75.00},
        "claude-sonnet-4-6": {"input": 3.00, "output": 15.00},
        "gpt-5.4": {"input": 10.00, "output": 30.00},
        "gpt-5.4-mini": {"input": 0.15, "output": 0.60},
        "gpt-5.3-codex": {"input": 3.00, "output": 15.00},
        "gpt-5.3-codex-spark": {"input": 0.50, "output": 2.00},
        "gemini-3-flash-preview": {"input": 0.075, "output": 0.30},
    }

    def __init__(self) -> None:
        self.calls: list[ModelCall] = []

    def record(self, call: ModelCall) -> None:
        """Record an LLM API call."""
        self.calls.append(call)

    def cost_for_call(self, call: ModelCall) -> float:
        """Calculate cost for a single call."""
        prices = self.PRICE_PER_MILLION.get(call.model, {"input": 0, "output": 0})
        input_cost = (call.input_tokens / 1_000_000) * prices["input"]
        output_cost = (call.output_tokens / 1_000_000) * prices["output"]
        return input_cost + output_cost

    def total_cost(self) -> float:
        """Total cost in USD for all recorded calls."""
        return sum(self.cost_for_call(c) for c in self.calls)

    def cost_by_swarm(self) -> dict[str, float]:
        """Cost breakdown by swarm (vulnerability class)."""
        result: dict[str, float] = {}
        for call in self.calls:
            swarm_key = f"{call.swarm_id}:{call.vuln_class}"
            result[swarm_key] = result.get(swarm_key, 0) + self.cost_for_call(call)
        return result

    def cost_by_model(self) -> dict[str, float]:
        """Cost breakdown by model."""
        result: dict[str, float] = {}
        for call in self.calls:
            result[call.model] = result.get(call.model, 0) + self.cost_for_call(call)
        return result

    def total_tokens(self) -> dict[str, int]:
        """Token usage totals."""
        return {
            "input": sum(c.input_tokens for c in self.calls),
            "output": sum(c.output_tokens for c in self.calls),
            "total": sum(c.input_tokens + c.output_tokens for c in self.calls),
        }

    def call_count(self) -> int:
        """Total number of LLM calls."""
        return len(self.calls)


async def generate_report(
    findings: list[Finding],
    target: VulnTarget,
    tracker: CostTracker,
) -> dict[str, Any]:
    """
    Generate a comprehensive vulnerability research report.

    Returns:
        {
            "markdown": str,           # Markdown report
            "json": dict,              # JSON report
            "summary": {...},          # Severity counts
            "cost_summary": {...},     # Cost breakdown
        }
    """
    # Count by severity
    severity_counts = {
        "critical": len([f for f in findings if f.severity == "critical"]),
        "high": len([f for f in findings if f.severity == "high"]),
        "medium": len([f for f in findings if f.severity == "medium"]),
        "low": len([f for f in findings if f.severity == "low"]),
        "info": len([f for f in findings if f.severity == "info"]),
    }
    confirmed_count = len([f for f in findings if f.confirmed])
    total_count = len(findings)

    # Generate Markdown report
    md_lines = [
        "# Vulnerability Research Report",
        "",
        f"**Target:** {target.name}",
        f"**Type:** {target.type.upper()}",
        f"**Date:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        f"**Total Findings:** {total_count}  ",
        f"**Confirmed:** {confirmed_count}  ",
        "",
        "---",
        "",
        "## Findings by Severity",
        "",
    ]

    for severity in ("critical", "high", "medium", "low", "info"):
        count = severity_counts[severity]
        md_lines.append(f"- **{severity.upper()}**: {count}")

    md_lines.extend(["", "---", "", "## Detailed Findings", ""])

    for finding in findings:
        status_badge = "✓ CONFIRMED" if finding.confirmed else "⚠ UNCONFIRMED"
        md_lines.extend([
            f"### [{finding.severity.upper()}] {finding.vuln_class} — {finding.affected_component}",
            "",
            f"**Status:** {status_badge}  ",
            f"**Severity:** {finding.severity.upper()}  ",
            f"**Found by:** {finding.solver_model}  ",
            f"**Timestamp:** {finding.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
            "",
        ])

        if finding.description:
            md_lines.extend(["**Description:**", f"{finding.description}", ""])

        if finding.proof_of_concept:
            md_lines.extend(["**Proof of Concept:**", "", "```", finding.proof_of_concept, "```", ""])

        if finding.evidence:
            md_lines.extend(["**Evidence:**", "", "```", finding.evidence[:500], "```", ""])

        md_lines.append("")

    # Cost Summary section
    tokens = tracker.total_tokens()
    total_cost = tracker.total_cost()
    cost_per_finding = total_cost / total_count if total_count > 0 else 0

    md_lines.extend([
        "---",
        "",
        "## Cost Summary",
        "",
        f"**Total Cost:** ${total_cost:.2f} USD  ",
        f"**Total API Calls:** {tracker.call_count()}  ",
        f"**Total Tokens:** {tokens['total']:,}  ",
        f"  - Input: {tokens['input']:,}  ",
        f"  - Output: {tokens['output']:,}  ",
        "",
        f"**Cost per Finding:** ${cost_per_finding:.4f} USD  ",
        "",
    ])

    # Cost by model
    if tracker.cost_by_model():
        md_lines.extend(["### Cost Breakdown by Model", ""])
        for model in sorted(tracker.cost_by_model().keys()):
            cost = tracker.cost_by_model()[model]
            md_lines.append(f"- **{model}:** ${cost:.2f}")
        md_lines.append("")

    # Cost by swarm
    if tracker.cost_by_swarm():
        md_lines.extend(["### Cost Breakdown by Vulnerability Class", ""])
        for swarm_key in sorted(tracker.cost_by_swarm().keys()):
            cost = tracker.cost_by_swarm()[swarm_key]
            md_lines.append(f"- **{swarm_key}:** ${cost:.2f}")
        md_lines.append("")

    markdown_report = "\n".join(md_lines)

    # JSON report
    json_report = {
        "metadata": {
            "target_name": target.name,
            "target_type": target.type,
            "target_url": target.url,
            "target_repo": target.repo_url,
            "timestamp": datetime.utcnow().isoformat(),
        },
        "summary": {
            "total_findings": total_count,
            "confirmed_findings": confirmed_count,
            "by_severity": severity_counts,
        },
        "findings": [
            {
                "id": f.id,
                "vuln_class": f.vuln_class,
                "affected_component": f.affected_component,
                "severity": f.severity,
                "confirmed": f.confirmed,
                "proof_of_concept": f.proof_of_concept,
                "evidence": f.evidence,
                "solver_model": f.solver_model,
                "timestamp": f.timestamp.isoformat(),
            }
            for f in findings
        ],
        "cost_analysis": {
            "total_cost_usd": total_cost,
            "cost_per_finding_usd": cost_per_finding,
            "total_api_calls": tracker.call_count(),
            "total_tokens": tokens,
            "cost_by_model": tracker.cost_by_model(),
            "cost_by_swarm": tracker.cost_by_swarm(),
        },
    }

    return {
        "markdown": markdown_report,
        "json": json_report,
        "summary": {
            "critical": severity_counts["critical"],
            "high": severity_counts["high"],
            "medium": severity_counts["medium"],
            "low": severity_counts["low"],
            "info": severity_counts["info"],
            "total_confirmed": confirmed_count,
            "total_findings": total_count,
        },
        "cost_summary": {
            "total_usd": total_cost,
            "cost_per_finding_usd": cost_per_finding,
            "by_model": tracker.cost_by_model(),
            "by_swarm": tracker.cost_by_swarm(),
            "total_input_tokens": tokens["input"],
            "total_output_tokens": tokens["output"],
            "total_tokens": tokens["total"],
        },
    }
