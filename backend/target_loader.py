"""Target loader for authorized vulnerability research."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

import yaml


@dataclass
class VulnTarget:
    name: str
    type: Literal["web", "binary", "source"]
    url: str | None = None
    repo_url: str | None = None
    binary_path: str | None = None
    vuln_classes: list[str] = field(default_factory=list)
    description: str = ""
    scope_allowlist: list[str] = field(default_factory=list)
    local_path: str | None = None

    def __post_init__(self) -> None:
        self.vuln_classes = [item.lower() for item in self.vuln_classes]
        if self.type == "web" and not self.url:
            raise ValueError(f"Web target {self.name!r} requires url")
        if self.type == "binary" and not self.binary_path:
            raise ValueError(f"Binary target {self.name!r} requires binary_path")
        if self.type == "source" and not self.repo_url:
            raise ValueError(f"Source target {self.name!r} requires repo_url")
        if self.url and not self.scope_allowlist:
            parsed = urlparse(self.url)
            if parsed.netloc:
                self.scope_allowlist.append(parsed.netloc)


def load_targets(path: str | Path) -> list[VulnTarget]:
    target_path = Path(path)
    if not target_path.exists():
        raise FileNotFoundError(f"Target file not found: {target_path}")

    data = yaml.safe_load(target_path.read_text()) or {}
    loaded: list[VulnTarget] = []
    for item in data.get("targets", []):
        loaded.append(
            VulnTarget(
                name=item.get("name", ""),
                type=item.get("type", "web"),
                url=item.get("url"),
                repo_url=item.get("repo_url") or item.get("repoUrl"),
                binary_path=item.get("binary_path") or item.get("binaryPath"),
                vuln_classes=item.get("vuln_classes") or item.get("vulnClasses") or [],
                description=item.get("description", ""),
                scope_allowlist=item.get("scope_allowlist") or item.get("scopeAllowlist") or [],
                local_path=item.get("local_path") or item.get("localPath"),
            )
        )

    if not loaded:
        raise ValueError(f"No targets found in {target_path}")
    return loaded
