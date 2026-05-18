"""Pydantic AI tool wrappers for the scanner sandbox."""

from pydantic_ai import RunContext

from backend.deps import ScannerDeps
from backend.tools.core import (
    do_bash,
    do_check_notes,
    do_list_files,
    do_read_file,
    do_web_fetch,
    do_write_file,
)


async def bash(ctx: RunContext[ScannerDeps], command: str, timeout_seconds: int = 60) -> str:
    """Execute a bash command inside the sandboxed Docker container."""
    return await do_bash(ctx.deps.sandbox, command, timeout_seconds)


async def read_file(ctx: RunContext[ScannerDeps], path: str) -> str:
    """Read a file from the sandbox."""
    return await do_read_file(ctx.deps.sandbox, path)


async def write_file(ctx: RunContext[ScannerDeps], path: str, content: str) -> str:
    """Write a file into the sandbox workspace."""
    return await do_write_file(ctx.deps.sandbox, path, content)


async def list_files(ctx: RunContext[ScannerDeps], path: str = "/target") -> str:
    """List files in the sandbox."""
    return await do_list_files(ctx.deps.sandbox, path)


async def web_fetch(ctx: RunContext[ScannerDeps], url: str, method: str = "GET", body: str = "") -> str:
    """Fetch an in-scope URL."""
    return await do_web_fetch(url, ctx.deps.target.scope_allowlist, method, body)


async def check_notes(ctx: RunContext[ScannerDeps]) -> str:
    """Check notes from sibling scanners."""
    return await do_check_notes(ctx.deps.message_bus, ctx.deps.model_spec)


async def notify_coordinator(ctx: RunContext[ScannerDeps], message: str) -> str:
    """Send a short note to the coordinator."""
    if ctx.deps.notify_coordinator:
        await ctx.deps.notify_coordinator(message)
        return "Message sent."
    return "No coordinator connected."
