"""Small shared message bus for scanner swarms."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field


@dataclass
class SharedNote:
    model: str
    content: str
    timestamp: float = field(default_factory=time.time)


@dataclass
class ScannerMessageBus:
    notes: list[SharedNote] = field(default_factory=list)
    cursors: dict[str, int] = field(default_factory=dict)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def post(self, model: str, content: str) -> None:
        async with self._lock:
            self.notes.append(SharedNote(model=model, content=content))
            self.notes = self.notes[-200:]

    async def check(self, model: str) -> list[SharedNote]:
        async with self._lock:
            cursor = self.cursors.get(model, 0)
            unread = [note for note in self.notes[cursor:] if note.model != model]
            self.cursors[model] = len(self.notes)
            return unread

    def format_unread(self, notes: list[SharedNote]) -> str:
        if not notes:
            return ""
        return "Notes from sibling scanners:\n\n" + "\n\n".join(
            f"[{note.model}] {note.content}" for note in notes
        )
