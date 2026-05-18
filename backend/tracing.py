"""Per-tool-call JSONL event tracing."""

from __future__ import annotations

import atexit
import json
import time
from pathlib import Path


def _sanitize(value: str) -> str:
    return value.replace("/", "_").replace("\\", "_").replace(" ", "_")


class ScannerTracer:
    def __init__(self, target_name: str, model_id: str, log_dir: str = "logs") -> None:
        Path(log_dir).mkdir(parents=True, exist_ok=True)
        ts = time.strftime("%Y%m%d-%H%M%S")
        self.path = str(Path(log_dir) / f"trace-{_sanitize(target_name)}-{_sanitize(model_id)}-{ts}.jsonl")
        self._fh = open(self.path, "a", encoding="utf-8")
        atexit.register(self.close)

    def close(self) -> None:
        if not self._fh.closed:
            self._fh.close()

    def _write(self, event: dict) -> None:
        try:
            self._fh.write(json.dumps({"ts": time.time(), **event}) + "\n")
            self._fh.flush()
        except Exception:
            pass

    def tool_call(self, tool_name: str, args: dict | str, step: int) -> None:
        args_text = args if isinstance(args, str) else json.dumps(args)
        self._write({"type": "tool_call", "tool": tool_name, "args": args_text[:2000], "step": step})

    def tool_result(self, tool_name: str, result: str, step: int) -> None:
        self._write({"type": "tool_result", "tool": tool_name, "result": result[:2000], "step": step})

    def model_response(self, text: str, step: int, input_tokens: int = 0, output_tokens: int = 0) -> None:
        self._write(
            {
                "type": "model_response",
                "text": text[:1000],
                "step": step,
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
            }
        )

    def usage(self, input_tokens: int, output_tokens: int, cache_read: int, cost_usd: float) -> None:
        self._write(
            {
                "type": "usage",
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "cache_read_tokens": cache_read,
                "cost_usd": round(cost_usd, 6),
            }
        )

    def event(self, kind: str, **kwargs) -> None:
        self._write({"type": kind, **kwargs})


SolverTracer = ScannerTracer
