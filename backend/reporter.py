"""Vulnerability report generation and API cost accounting."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from pydantic_ai.usage import RunUsage

from backend.finding import Finding, deduplicate
from backend.models import model_id_from_spec
from backend.target_loader import VulnTarget


@dataclass
class ModelCall:
    model: str
    swarm_id: str
    vuln_class: str
    input_tokens: int
    output_tokens: int
    timestamp: datetime = field(default_factory=datetime.utcnow)


class CostTracker:
    PRICE_PER_MILLION = {
        "claude-opus-4-6": {"input": 15.00, "output": 75.00},
        "claude-sonnet-4-6": {"input": 3.00, "output": 15.00},
        "gpt-5.4": {"input": 10.00, "output": 30.00},
        "gpt-5.4-mini": {"input": 0.15, "output": 0.60},
        "gpt-5.3-codex": {"input": 3.00, "output": 15.00},
    }

    def __init__(self) -> None:
        self.calls: list[ModelCall] = []

    def record(self, call: ModelCall) -> None:
        self.calls.append(call)

    def record_tokens(
        self,
        agent_name: str,
        model_name: str,
        input_tokens: int = 0,
        output_tokens: int = 0,
        cache_read_tokens: int = 0,
        provider_spec: str = "",
        duration_seconds: float = 0.0,
    ) -> None:
        _ = cache_read_tokens, provider_spec, duration_seconds
        vuln_class = agent_name.split("/", 2)[1] if "/" in agent_name else "general"
        self.record(
            ModelCall(
                model=model_id_from_spec(model_name),
                swarm_id=agent_name,
                vuln_class=vuln_class,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
            )
        )

    def record_usage(
        self,
        agent_name: str,
        usage: RunUsage,
        model_name: str,
        provider_spec: str = "",
        duration_seconds: float = 0.0,
    ) -> None:
        _ = provider_spec, duration_seconds
        self.record_tokens(
            agent_name=agent_name,
            model_name=model_name,
            input_tokens=usage.input_tokens,
            output_tokens=usage.output_tokens,
            cache_read_tokens=usage.cache_read_tokens,
        )

    def cost_for_call(self, call: ModelCall) -> float:
        prices = self.PRICE_PER_MILLION.get(call.model, {"input": 0.0, "output": 0.0})
        return (
            (call.input_tokens / 1_000_000) * prices["input"]
            + (call.output_tokens / 1_000_000) * prices["output"]
        )

    def total_cost(self) -> float:
        return sum(self.cost_for_call(call) for call in self.calls)

    def cost_by_swarm(self) -> dict[str, float]:
        result: dict[str, float] = {}
        for call in self.calls:
            result[call.swarm_id] = result.get(call.swarm_id, 0.0) + self.cost_for_call(call)
        return result

    def cost_by_model(self) -> dict[str, float]:
        result: dict[str, float] = {}
        for call in self.calls:
            result[call.model] = result.get(call.model, 0.0) + self.cost_for_call(call)
        return result

    def total_tokens(self) -> dict[str, int]:
        input_tokens = sum(call.input_tokens for call in self.calls)
        output_tokens = sum(call.output_tokens for call in self.calls)
        return {"input": input_tokens, "output": output_tokens, "total": input_tokens + output_tokens}


async def generate_report(
    findings: list[Finding],
    target: VulnTarget,
    tracker: CostTracker,
) -> dict[str, Any]:
    findings = deduplicate(findings)
    confirmed = [finding for finding in findings if finding.confirmed]
    severity_counts = {
        severity: sum(1 for finding in confirmed if finding.severity == severity)
        for severity in ("critical", "high", "medium", "low", "info")
    }
    total_confirmed = len(confirmed)
    tokens = tracker.total_tokens()
    total_cost = tracker.total_cost()
    cost_per_finding = total_cost / total_confirmed if total_confirmed else 0.0

    lines = [
        "# Vulnerability Research Report",
        f"**Target:** {target.name}",
        f"**Date:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
        f"**Confirmed Findings:** {total_confirmed}",
        "",
        "---",
        "",
        "## Findings",
        "",
    ]

    if not findings:
        lines.extend(["No findings were confirmed.", ""])

    for finding in findings:
        lines.extend(
            [
                f"### [{finding.severity.upper()}] {finding.vuln_class} - {finding.affected_component}",
                f"**Confirmed:** {'Yes' if finding.confirmed else 'No'}",
                "**Proof of Concept:**",
                "",
                "```",
                finding.proof_of_concept or "None provided.",
                "```",
                "",
                "**Evidence:**",
                "",
                "```",
                finding.evidence or "None provided.",
                "```",
                "",
            ]
        )

    lines.extend(
        [
            "## Cost Summary",
            "",
            f"**Total Cost:** ${total_cost:.4f}",
            f"**Cost per Confirmed Finding:** ${cost_per_finding:.4f}",
            f"**Total Tokens:** {tokens['total']}",
            f"**Input Tokens:** {tokens['input']}",
            f"**Output Tokens:** {tokens['output']}",
            "",
            "## Cost Breakdown",
            "",
            "### By Model",
        ]
    )
    for model, cost in sorted(tracker.cost_by_model().items()):
        lines.append(f"- {model}: ${cost:.4f}")
    lines.append("")
    lines.append("### By Scanner Swarm")
    for swarm_id, cost in sorted(tracker.cost_by_swarm().items()):
        lines.append(f"- {swarm_id}: ${cost:.4f}")

    json_report = {
        "target": {
            "name": target.name,
            "type": target.type,
            "url": target.url,
            "repo_url": target.repo_url,
            "binary_path": target.binary_path,
            "scope_allowlist": target.scope_allowlist,
        },
        "summary": {
            **severity_counts,
            "total_confirmed": total_confirmed,
        },
        "findings": [
            {
                "id": finding.id,
                "vuln_class": finding.vuln_class,
                "affected_component": finding.affected_component,
                "severity": finding.severity,
                "proof_of_concept": finding.proof_of_concept,
                "evidence": finding.evidence,
                "confirmed": finding.confirmed,
                "solver_model": finding.solver_model,
                "timestamp": finding.timestamp.isoformat(),
                "description": finding.description,
            }
            for finding in findings
        ],
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

    return {
        "markdown": "\n".join(lines),
        "json": json_report,
        "summary": {**severity_counts, "total_confirmed": total_confirmed},
        "cost_summary": json_report["cost_summary"],
    }


async def generate_summary_report(target_reports: list[dict[str, Any]], tracker: CostTracker) -> dict[str, Any]:
    severity_counts = {
        severity: sum(item["report"]["summary"][severity] for item in target_reports)
        for severity in ("critical", "high", "medium", "low", "info")
    }
    total_confirmed = sum(item["report"]["summary"]["total_confirmed"] for item in target_reports)
    tokens = tracker.total_tokens()
    total_cost = tracker.total_cost()
    cost_per_finding = total_cost / total_confirmed if total_confirmed else 0.0

    lines = [
        "# Vulnerability Research Summary",
        f"**Date:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
        f"**Targets:** {len(target_reports)}",
        f"**Confirmed Findings:** {total_confirmed}",
        "",
        "---",
        "",
        "## Targets",
        "",
    ]

    for item in target_reports:
        target = item["target"]
        report = item["report"]
        summary = report["summary"]
        lines.extend(
            [
                f"### {target.name}",
                f"- Type: {target.type}",
                f"- URL: {target.url or 'none'}",
                f"- Confirmed: {summary['total_confirmed']}",
                f"- Critical: {summary['critical']}",
                f"- High: {summary['high']}",
                f"- Report: {item['markdown_path']}",
                f"- JSON: {item['json_path']}",
                "",
            ]
        )

    lines.extend(
        [
            "## Cost Summary",
            "",
            f"**Total Cost:** ${total_cost:.4f}",
            f"**Cost per Confirmed Finding:** ${cost_per_finding:.4f}",
            f"**Total Tokens:** {tokens['total']}",
            f"**Input Tokens:** {tokens['input']}",
            f"**Output Tokens:** {tokens['output']}",
            "",
            "## Cost Breakdown",
            "",
            "### By Model",
        ]
    )
    for model, cost in sorted(tracker.cost_by_model().items()):
        lines.append(f"- {model}: ${cost:.4f}")
    lines.append("")
    lines.append("### By Scanner Swarm")
    for swarm_id, cost in sorted(tracker.cost_by_swarm().items()):
        lines.append(f"- {swarm_id}: ${cost:.4f}")

    json_report = {
        "summary": {**severity_counts, "total_confirmed": total_confirmed},
        "targets": [
            {
                "name": item["target"].name,
                "type": item["target"].type,
                "url": item["target"].url,
                "repo_url": item["target"].repo_url,
                "report": item["markdown_path"],
                "json": item["json_path"],
                "summary": item["report"]["summary"],
                "findings": item["report"]["json"]["findings"],
            }
            for item in target_reports
        ],
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

    return {
        "markdown": "\n".join(lines),
        "json": json_report,
        "summary": {**severity_counts, "total_confirmed": total_confirmed},
        "cost_summary": json_report["cost_summary"],
    }
