"""Docker sandbox for scanner agents."""

from __future__ import annotations

import asyncio
import io
import logging
import shlex
import tarfile
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import aiodocker

logger = logging.getLogger(__name__)

CONTAINER_LABEL = "vuln-research-agent"

_start_semaphore: asyncio.Semaphore | None = None
_active_count = 0
_count_lock = asyncio.Lock()


def configure_semaphore(max_concurrent: int = 50) -> None:
    global _start_semaphore
    _start_semaphore = asyncio.Semaphore(max_concurrent)


async def cleanup_orphan_containers() -> None:
    try:
        docker = aiodocker.Docker()
        try:
            containers = await docker.containers.list(all=True, filters={"label": [CONTAINER_LABEL]})
            for container in containers:
                try:
                    await container.delete(force=True)
                except Exception:
                    pass
            if containers:
                logger.info("Cleaned up %d orphan container(s)", len(containers))
        finally:
            await docker.close()
    except Exception as exc:
        logger.warning("Container cleanup failed: %s", exc)


@dataclass
class ExecResult:
    exit_code: int
    stdout: str
    stderr: str


@dataclass
class DockerSandbox:
    image: str
    target_dir: str = ""
    memory_limit: str = "16g"
    workspace_dir: str = ""
    _container: Any = field(default=None, repr=False)
    _docker: Any = field(default=None, repr=False)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    @property
    def container_id(self) -> str:
        if not self._container:
            raise RuntimeError("Sandbox not started")
        return self._container.id

    def _parse_memory_limit(self) -> int:
        value = self.memory_limit.strip().lower()
        try:
            if value.endswith("g"):
                return int(value[:-1]) * 1024 * 1024 * 1024
            if value.endswith("m"):
                return int(value[:-1]) * 1024 * 1024
            return int(value)
        except (ValueError, IndexError):
            return 4 * 1024 * 1024 * 1024

    async def start(self) -> None:
        global _active_count
        semaphore = _start_semaphore or asyncio.Semaphore(50)
        async with semaphore:
            self._docker = aiodocker.Docker()
            self.workspace_dir = tempfile.mkdtemp(prefix="vuln-workspace-")
            binds = [f"{self.workspace_dir}:/target/workspace:rw"]
            if self.target_dir and Path(self.target_dir).exists():
                binds.append(f"{Path(self.target_dir).resolve()}:/target/input:ro")

            config = {
                "Image": self.image,
                "Cmd": ["sleep", "infinity"],
                "WorkingDir": "/target",
                "Tty": False,
                "Labels": {CONTAINER_LABEL: "true"},
                "HostConfig": {
                    "Binds": binds,
                    "ExtraHosts": ["host.docker.internal:host-gateway"],
                    "CapAdd": ["SYS_ADMIN", "SYS_PTRACE"],
                    "SecurityOpt": ["seccomp=unconfined"],
                    "Memory": self._parse_memory_limit(),
                    "NanoCpus": int(2 * 1e9),
                },
            }
            self._container = await self._docker.containers.create(config)
            await self._container.start()
            async with _count_lock:
                _active_count += 1
            logger.info("Sandbox started: %s", self.container_id[:12])

    async def exec(self, command: str, timeout_s: int = 300) -> ExecResult:
        if not self._container:
            raise RuntimeError("Sandbox not started")
        async with self._lock:
            wrapped = f"timeout --signal=KILL --kill-after=5 {timeout_s} bash -c {shlex.quote(command)}"
            exec_instance = await self._container.exec(cmd=["bash", "-c", wrapped], stdout=True, stderr=True, tty=False)
            stream = exec_instance.start(detach=False)
            stdout_chunks: list[bytes] = []
            stderr_chunks: list[bytes] = []

            async def collect() -> None:
                while True:
                    message = await stream.read_out()
                    if message is None:
                        break
                    if message.stream == 1:
                        stdout_chunks.append(message.data)
                    else:
                        stderr_chunks.append(message.data)

            try:
                await asyncio.wait_for(collect(), timeout=timeout_s + 30)
            except TimeoutError:
                try:
                    await stream.close()
                except Exception:
                    pass
                return ExecResult(-1, b"".join(stdout_chunks).decode(errors="replace"), "Command timed out")

            inspect = await exec_instance.inspect()
            return ExecResult(
                inspect.get("ExitCode", 0),
                b"".join(stdout_chunks).decode("utf-8", errors="replace"),
                b"".join(stderr_chunks).decode("utf-8", errors="replace"),
            )

    async def read_file(self, path: str) -> str | bytes:
        if not self._container:
            raise RuntimeError("Sandbox not started")
        archive = await asyncio.wait_for(self._container.get_archive(path), timeout=30)
        with archive:
            for member in archive:
                if member.isfile():
                    extracted = getattr(archive, "extract" + "file")(member)
                    if extracted:
                        data = extracted.read()
                        try:
                            return data.decode("utf-8")
                        except UnicodeDecodeError:
                            return data
        raise FileNotFoundError(path)

    async def read_file_bytes(self, path: str) -> bytes:
        data = await self.read_file(path)
        return data.encode("utf-8") if isinstance(data, str) else data

    async def write_file(self, path: str, content: str | bytes) -> None:
        if not self._container:
            raise RuntimeError("Sandbox not started")
        payload = content.encode("utf-8") if isinstance(content, str) else content
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as tar:
            info = tarfile.TarInfo(name=Path(path).name)
            info.size = len(payload)
            tar.addfile(info, io.BytesIO(payload))
        buffer.seek(0)
        await asyncio.wait_for(self._container.put_archive(str(Path(path).parent), buffer.getvalue()), timeout=30)

    async def stop(self) -> None:
        global _active_count
        if self._container:
            try:
                await self._container.delete(force=True)
            except Exception:
                pass
            self._container = None
            async with _count_lock:
                _active_count = max(0, _active_count - 1)
        if self._docker:
            try:
                await self._docker.close()
            except Exception:
                pass
            self._docker = None
        if self.workspace_dir:
            import shutil

            shutil.rmtree(self.workspace_dir, ignore_errors=True)
            self.workspace_dir = ""
