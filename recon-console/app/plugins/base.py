"""Plugin contract.

Every tool is a Plugin with four responsibilities:
  - declare the binary it needs (drives Tool Management availability),
  - decide whether it should run given what's been found so far (conditional
    dispatch -- the web plugins only fire on hosts with web ports),
  - run its subprocess,
  - parse output into the common schema (AssetData / ServiceData / FindingData).

Normalising every tool into this one schema is the real work of an
orchestrator. Add a tool by writing one subclass; the pipeline and UI need no
changes.
"""
from __future__ import annotations
import asyncio
import shutil
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Callable


@dataclass
class ServiceData:
    port: int
    protocol: str = "tcp"
    name: str = ""
    product: str = ""
    version: str = ""
    state: str = "open"


@dataclass
class AssetData:
    ip: str
    hostname: str = ""
    os_guess: str = ""
    status: str = "up"
    services: list[ServiceData] = field(default_factory=list)


@dataclass
class FindingData:
    title: str
    detail: str = ""
    severity: str = "info"
    source_tool: str = ""
    asset_ip: str = ""


@dataclass
class PluginResult:
    assets: list[AssetData] = field(default_factory=list)
    findings: list[FindingData] = field(default_factory=list)


@dataclass
class PluginContext:
    target: str
    profile: str
    workdir: str
    # Assets discovered by earlier plugins in the pipeline, so later plugins
    # (web, tls, smb...) can dispatch on open services.
    assets: list[AssetData] = field(default_factory=list)
    log: Callable[[str], None] = lambda msg: None


class Plugin(ABC):
    name: str = "plugin"
    binary: str = ""          # executable that must be on PATH
    description: str = ""
    # Some tool names collide with unrelated binaries on PATH (`httpx` is also
    # the Python HTTP client). When a marker is set, availability additionally
    # requires the version banner to contain it.
    version_args: tuple[str, ...] = ("-version",)
    version_marker: str = ""

    def is_available(self) -> bool:
        if not self.binary or shutil.which(self.binary) is None:
            return False
        if not self.version_marker:
            return True
        try:
            proc = subprocess.run(
                [self.binary, *self.version_args],
                capture_output=True, text=True, timeout=5,
            )
        except (OSError, subprocess.SubprocessError):
            return False
        banner = f"{proc.stdout or ''}{proc.stderr or ''}".lower()
        return self.version_marker.lower() in banner

    def should_run(self, ctx: PluginContext) -> bool:
        """Override to gate on prior findings. Default: always run."""
        return True

    @abstractmethod
    async def run(self, ctx: PluginContext) -> PluginResult:
        ...

    async def _exec(self, *cmd: str, timeout: int = 1800) -> tuple[int, str, str]:
        """Run a subprocess without blocking the event loop."""
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.DEVNULL,   # a tool must never block on stdin
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()                   # reap it; a bare kill leaves a zombie
            return 124, "", f"timed out after {timeout}s"
        return proc.returncode, out.decode(errors="replace"), err.decode(errors="replace")
