"""Target loader for vulnerability research — reads web/binary/source targets from YAML."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import yaml


@dataclass
class VulnTarget:
    """A target for vulnerability research."""

    name: str
    type: Literal["web", "binary", "source"]
    url: str | None = None  # live web app base URL
    repo_url: str | None = None  # GitHub/GitLab source repo
    binary_path: str | None = None  # local ELF/PE path for binary analysis
    vuln_classes: list[str] = None  # e.g. ["xss", "sqli", "bof", "uaf", "auth"]
    description: str = ""
    scope_allowlist: list[str] = None  # domains/paths agents are allowed to test

    def __post_init__(self) -> None:
        """Validate and normalize."""
        if self.vuln_classes is None:
            self.vuln_classes = []
        if self.scope_allowlist is None:
            self.scope_allowlist = []

        # Normalize vuln_classes to lowercase
        self.vuln_classes = [v.lower() for v in self.vuln_classes]

        # Type-specific validation
        if self.type == "web" and not self.url:
            raise ValueError(f"Web target '{self.name}' requires 'url'")
        if self.type == "binary" and not self.binary_path:
            raise ValueError(f"Binary target '{self.name}' requires 'binary_path'")
        if self.type == "source" and not self.repo_url:
            raise ValueError(f"Source target '{self.name}' requires 'repo_url'")

        # Ensure scope_allowlist is populated for web targets
        if self.type == "web" and self.url and not self.scope_allowlist:
            from urllib.parse import urlparse
            parsed = urlparse(self.url)
            self.scope_allowlist = [parsed.netloc]


def load_targets(path: str | Path) -> list[VulnTarget]:
    """Load targets from a YAML file."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Target file not found: {path}")

    with open(path) as f:
        data = yaml.safe_load(f) or {}

    targets = []
    for target_data in data.get("targets", []):
        # Handle both camelCase and snake_case in YAML
        target = VulnTarget(
            name=target_data.get("name", ""),
            type=target_data.get("type", "web"),
            url=target_data.get("url"),
            repo_url=target_data.get("repo_url") or target_data.get("repoUrl"),
            binary_path=target_data.get("binary_path") or target_data.get("binaryPath"),
            vuln_classes=target_data.get("vuln_classes", target_data.get("vulnClasses", [])),
            description=target_data.get("description", ""),
            scope_allowlist=(
                target_data.get("scope_allowlist") or target_data.get("scopeAllowlist", [])
            ),
        )
        targets.append(target)

    if not targets:
        raise ValueError(f"No targets found in {path}")

    return targets
