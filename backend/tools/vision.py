"""Vision tool wrapper."""

from pydantic_ai import RunContext

from backend.deps import ScannerDeps
from backend.tools.core import do_view_image


async def view_image(ctx: RunContext[ScannerDeps], filename: str) -> tuple[bytes, str] | str:
    """Inspect an image from the sandbox when the model supports vision."""
    return await do_view_image(ctx.deps.sandbox, filename, ctx.deps.use_vision)
