"""Per-model scanner agent."""

from __future__ import annotations

import asyncio
import json
import logging
import shlex
import tempfile
import time
from dataclasses import dataclass, field
from typing import Any

from pydantic_ai import Agent, RunContext
from pydantic_ai.toolsets import FunctionToolset
from pydantic_ai.toolsets.abstract import ToolsetTool
from pydantic_ai.toolsets.wrapper import WrapperToolset

from backend.deps import ScannerDeps
from backend.finding import Finding
from backend.loop_detect import LOOP_WARNING_MESSAGE, LoopDetector
from backend.models import (
    SWARM_CONFIGS,
    model_id_from_spec,
    provider_from_spec,
    resolve_model,
    resolve_model_settings,
    supports_vision,
)
from backend.output_types import FindingOutput
from backend.reporter import CostTracker
from backend.sandbox import DockerSandbox
from backend.solver_base import CANCELLED, ERROR, FINDING_CONFIRMED, NO_FINDING, ScannerResult
from backend.target_loader import VulnTarget
from backend.tools.sandbox import (
    bash,
    check_notes,
    list_files,
    notify_coordinator,
    read_file,
    web_fetch,
    write_file,
)
from backend.tools.vision import view_image
from backend.tracing import ScannerTracer

logger = logging.getLogger(__name__)

MAX_AGENT_REQUESTS = 25

SEMGREP_RULE_MAP = {
    "xss": "p/xss",
    "sqli": "p/sql-injection",
    "auth": "p/jwt",
    "source": "p/owasp-top-ten",
    "bof": "p/c.lang.security",
}


async def run_semgrep_in_sandbox(sandbox: DockerSandbox, local_path: str, rules: str) -> str:
    _ = local_path
    command = f"semgrep --config {shlex.quote(rules)} --json /target/source 2>/dev/null | head -c 20000"
    result = await sandbox.exec(command, timeout_s=180)
    return result.stdout or result.stderr or "No semgrep output."


async def build_solver_context(target: VulnTarget, vuln_class: str, sandbox: DockerSandbox) -> str:
    context = ""
    if target.repo_url:
        result = await sandbox.exec(
            f"rm -rf /target/source && git clone --depth=1 {shlex.quote(target.repo_url)} /target/source",
            timeout_s=180,
        )
        target.local_path = "/target/source"
        if result.exit_code != 0:
            return f"Repository clone failed:\n{result.stderr}\n"
        rules = SEMGREP_RULE_MAP.get(vuln_class, "auto")
        results = await run_semgrep_in_sandbox(sandbox, target.local_path, rules)
        context = f"Semgrep pre-scan results for {vuln_class}:\n{results}\n"
        context += "Start by verifying these candidates, then expand search.\n"
    return context


def validate_finding(finding: Finding) -> bool:
    return (
        finding.confirmed
        and bool(finding.proof_of_concept.strip())
        and bool(finding.affected_component.strip())
        and finding.affected_component.strip().lower() != "unknown"
        and finding.severity is not None
    )


def build_scanner_prompt(target: VulnTarget, vuln_class: str, source_context: str = "") -> str:
    extra = SWARM_CONFIGS.get(vuln_class, {}).get("system_prompt_extra", "")
    return f"""You are an authorized vulnerability research scanner.

Target:
- Name: {target.name}
- Type: {target.type}
- URL: {target.url or "none"}
- Repository: {target.repo_url or "none"}
- Binary: {target.binary_path or "none"}
- Scope allowlist: {", ".join(target.scope_allowlist) or "none"}
- Description: {target.description or "none"}

Vulnerability class: {vuln_class}
{extra}

Scope rules:
- Only interact with hosts and paths in scope_allowlist.
- Keep testing read-only unless the target definition explicitly says otherwise.
- Do not send target data to external hosts.
- A reportable issue must include a confirmed, reproducible proof of concept.

{source_context}

Return structured JSON only. If you confirm a vulnerability, set type to "finding".
If you cannot confirm one this turn, set type to "no_finding" and explain what was tried in evidence.
"""


@dataclass
class TracingToolset(WrapperToolset[ScannerDeps]):
    tracer: ScannerTracer = field(repr=False)
    loop_detector: LoopDetector = field(repr=False)
    step_counter: list[int] = field(repr=False)

    async def call_tool(
        self,
        name: str,
        tool_args: dict[str, Any],
        ctx: RunContext[ScannerDeps],
        tool: ToolsetTool[ScannerDeps],
    ) -> Any:
        self.step_counter[0] += 1
        step = self.step_counter[0]
        self.tracer.tool_call(name, tool_args, step)
        loop_status = self.loop_detector.check(name, tool_args)
        if loop_status == "break":
            self.tracer.event("loop_break", tool=name, step=step)
            return LOOP_WARNING_MESSAGE
        result = await self.wrapped.call_tool(name, tool_args, ctx, tool)
        result_text = str(result) if result is not None else ""
        self.tracer.tool_result(name, result_text, step)
        if loop_status == "warn" and isinstance(result, str):
            return f"{result}\n\n{LOOP_WARNING_MESSAGE}"
        return result


def _build_toolset(deps: ScannerDeps) -> FunctionToolset[ScannerDeps]:
    tools = [bash, read_file, write_file, list_files, web_fetch, check_notes, notify_coordinator]
    if deps.use_vision:
        tools.append(view_image)
    return FunctionToolset(tools=tools, max_retries=4)


class Scanner:
    def __init__(
        self,
        model_spec: str,
        target: VulnTarget,
        vuln_class: str,
        cost_tracker: CostTracker,
        settings: object,
        cancel_event: asyncio.Event | None = None,
        message_bus=None,
        notify_coordinator=None,
    ) -> None:
        self.model_spec = model_spec
        self.model_id = model_id_from_spec(model_spec)
        self.target = target
        self.vuln_class = vuln_class
        self.cost_tracker = cost_tracker
        self.settings = settings
        self.cancel_event = cancel_event or asyncio.Event()
        self.message_bus = message_bus
        self.notify_coordinator = notify_coordinator
        self.sandbox = DockerSandbox(
            image=getattr(settings, "sandbox_image", "vuln-research-sandbox"),
            target_dir=target.binary_path or "",
            memory_limit=getattr(settings, "container_memory_limit", "16g"),
        )
        self.use_vision = supports_vision(model_spec)
        self.tracer = ScannerTracer(f"{target.name}-{vuln_class}", self.model_id)
        self.loop_detector = LoopDetector()
        self.agent_name = f"{target.name}/{vuln_class}/{self.model_id}"
        self._agent: Agent[ScannerDeps, FindingOutput] | None = None
        self._messages: list = []
        self._step_count = [0]
        self._iteration_count = 0
        self._notes = ""

    async def start(self) -> None:
        await self.sandbox.start()
        context = await build_solver_context(self.target, self.vuln_class, self.sandbox)
        deps = ScannerDeps(
            sandbox=self.sandbox,
            target=self.target,
            vuln_class=self.vuln_class,
            workspace_dir=self.sandbox.workspace_dir,
            use_vision=self.use_vision,
            cost_tracker=self.cost_tracker,
            message_bus=self.message_bus,
            model_spec=self.model_spec,
            notify_coordinator=self.notify_coordinator,
        )
        toolset = TracingToolset(
            wrapped=_build_toolset(deps),
            tracer=self.tracer,
            loop_detector=self.loop_detector,
            step_counter=self._step_count,
        )
        self._agent = Agent(
            resolve_model(self.model_spec, self.settings),
            deps_type=ScannerDeps,
            system_prompt=build_scanner_prompt(self.target, self.vuln_class, context),
            model_settings=resolve_model_settings(self.model_spec),
            toolsets=[toolset],
            output_type=FindingOutput,
        )
        self._deps = deps
        self.tracer.event("start", target=self.target.name, vuln_class=self.vuln_class, model=self.model_id)

    async def run_once(self) -> ScannerResult:
        if not self._agent:
            await self.start()
        assert self._agent is not None
        prompt = (
            f"Scan for {self.vuln_class}. Confirm a proof of concept before returning a finding."
            if self._iteration_count == 0
            else "Continue from the prior work. Avoid repeating failed attempts."
        )
        if self._notes:
            prompt += f"\n\nCoordinator or sibling notes:\n{self._notes}"
            self._notes = ""

        started = time.monotonic()
        try:
            from pydantic_ai.usage import UsageLimits

            result = await self._agent.run(
                prompt,
                deps=self._deps,
                usage_limits=UsageLimits(request_limit=MAX_AGENT_REQUESTS),
            )
            self._iteration_count += 1
            usage = result.usage()
            self.cost_tracker.record_usage(
                self.agent_name,
                usage,
                self.model_id,
                provider_spec=provider_from_spec(self.model_spec),
                duration_seconds=time.monotonic() - started,
            )
            self.tracer.usage(usage.input_tokens, usage.output_tokens, usage.cache_read_tokens, 0.0)
            # Do not retain full tool-call history between passes. Large repos can
            # otherwise grow the next request past the model context limit.
            self._messages = []

            output = result.output
            if output.type == "finding":
                finding = Finding(
                    vuln_class=output.vuln_class,
                    affected_component=output.affected_component,
                    severity=output.severity,  # type: ignore[arg-type]
                    proof_of_concept=output.proof_of_concept,
                    evidence=output.evidence,
                    confirmed=output.confirmed,
                    solver_model=self.model_id,
                    description=output.description,
                )
                if validate_finding(finding):
                    return ScannerResult(finding, FINDING_CONFIRMED, output.description, self._step_count[0], 0.0, self.tracer.path)
                return ScannerResult(finding, NO_FINDING, "Finding did not pass validation.", self._step_count[0], 0.0, self.tracer.path)
            self._notes = output.evidence[:2000]
            return ScannerResult(None, NO_FINDING, output.evidence, self._step_count[0], 0.0, self.tracer.path)
        except asyncio.CancelledError:
            return ScannerResult(None, CANCELLED, "", self._step_count[0], 0.0, self.tracer.path)
        except Exception as exc:
            logger.error("[%s] scanner error: %s", self.agent_name, exc, exc_info=True)
            return ScannerResult(None, ERROR, str(exc), self._step_count[0], 0.0, self.tracer.path)

    def bump(self, insights: str) -> None:
        self._notes = insights
        self.loop_detector.reset()

    async def stop(self) -> None:
        self.tracer.close()
        await self.sandbox.stop()


async def clone_repo_to_temp(repo_url: str) -> str:
    path = tempfile.mkdtemp(prefix="vuln-source-")
    process = await asyncio.create_subprocess_exec(
        "git",
        "clone",
        "--depth=1",
        repo_url,
        path,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await process.communicate()
    if process.returncode != 0:
        raise RuntimeError((stderr or stdout).decode("utf-8", errors="replace"))
    return path


def parse_finding_json(text: str, model_id: str) -> Finding | None:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return None
    if data.get("type") != "finding":
        return None
    return Finding(
        vuln_class=data.get("vuln_class", ""),
        affected_component=data.get("affected_component", ""),
        severity=data.get("severity", "medium"),
        proof_of_concept=data.get("proof_of_concept", ""),
        evidence=data.get("evidence", ""),
        confirmed=bool(data.get("confirmed")),
        solver_model=model_id,
        description=data.get("description", ""),
    )


Solver = Scanner
