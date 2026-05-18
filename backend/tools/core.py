"""SDK-agnostic scanner tool implementations."""

from __future__ import annotations

import json
import shlex
from pathlib import Path
from urllib.parse import urlparse

import httpx

MAX_OUTPUT = 8_000


def _truncate(text: str, limit: int = MAX_OUTPUT) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n... [truncated, {len(text)} chars total]"


async def do_bash(sandbox, command: str, timeout_seconds: int = 60) -> str:
    result = await sandbox.exec(command, timeout_s=timeout_seconds)
    parts: list[str] = []
    if result.stdout:
        parts.append(result.stdout)
    if result.stderr:
        parts.append(f"[stderr]\n{result.stderr}")
    if result.exit_code != 0:
        parts.append(f"[exit {result.exit_code}]")
    return _truncate("\n".join(parts).strip() or "(no output)")


async def do_read_file(sandbox, path: str) -> str:
    try:
        data = await sandbox.read_file(path)
    except Exception as exc:
        return f"Error reading file: {exc}"
    if isinstance(data, bytes):
        return _truncate(data[:8192].decode("utf-8", errors="replace"))
    return _truncate(data)


async def do_write_file(sandbox, path: str, content: str) -> str:
    try:
        await sandbox.write_file(path, content)
        return f"Written {len(content)} bytes to {path}"
    except Exception as exc:
        return f"Error writing file: {exc}"


async def do_list_files(sandbox, path: str = "/target") -> str:
    result = await sandbox.exec(f"ls -la {shlex.quote(path)}")
    if result.exit_code != 0:
        return result.stderr.strip() or f"Error listing {path}"
    return result.stdout.strip() or f"{path} is empty."


def _allowed(url: str, scope_allowlist: list[str]) -> bool:
    if not scope_allowlist:
        return False
    parsed = urlparse(url)
    host = parsed.netloc or parsed.path.split("/", 1)[0]
    return any(host == item or url.startswith(item) for item in scope_allowlist)


async def do_web_fetch(
    url: str,
    scope_allowlist: list[str],
    method: str = "GET",
    body: str = "",
) -> str:
    if not _allowed(url, scope_allowlist):
        return f"Fetch blocked: {url} is outside scope_allowlist."
    try:
        async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
            response = await client.request(method, url, content=body or None)
            text = response.text
            if len(text) > 10_000:
                text = text[:10_000] + f"\n... [truncated, total {len(response.text)} bytes]"
            return f"HTTP {response.status_code} {response.reason_phrase}\n{'-' * 40}\n{text}"
    except Exception as exc:
        return f"Fetch error: {exc}"


async def do_check_notes(message_bus, model_spec: str) -> str:
    if not message_bus:
        return "No shared notes available."
    notes = await message_bus.check(model_spec)
    return message_bus.format_unread(notes) if notes else "No new notes from sibling scanners."


async def do_view_image(sandbox, filename: str, use_vision: bool) -> tuple[bytes, str] | str:
    if not use_vision:
        return "Vision is not available for this model."
    ext_to_mime = {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".webp": "image/webp"}
    basename = Path(filename).name
    mime_type = ext_to_mime.get(Path(basename).suffix.lower())
    if not mime_type:
        return f"Unsupported image type: {filename}"
    for path in (filename, f"/target/input/{basename}", f"/target/workspace/{basename}"):
        try:
            return await sandbox.read_file_bytes(path), mime_type
        except Exception:
            continue
    return f"File not found: {filename}"


def finding_json_template(vuln_class: str) -> str:
    return json.dumps(
        {
            "type": "finding",
            "vuln_class": vuln_class,
            "affected_component": "specific file, endpoint, or binary offset",
            "severity": "medium",
            "proof_of_concept": "reproducible payload or exploit steps",
            "evidence": "observed response, crash, or trace",
            "confirmed": True,
            "description": "why the issue is exploitable",
        },
        indent=2,
    )
