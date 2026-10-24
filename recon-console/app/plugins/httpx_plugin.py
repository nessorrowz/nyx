"""httpx (ProjectDiscovery): probe discovered web services.

Demonstrates conditional dispatch: it only runs against hosts where nmap found
a web port, and it builds its target list from prior results rather than
re-scanning. If the binary isn't installed it reports nothing and the pipeline
moves on.
"""
from __future__ import annotations
import json
import os

from .base import Plugin, PluginContext, PluginResult, FindingData

WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9090}
WEB_NAMES = {"http", "https", "http-alt", "http-proxy"}


class HttpxPlugin(Plugin):
    name = "httpx"
    binary = "httpx"
    description = "HTTP/HTTPS endpoint discovery"
    # Bare `httpx` also resolves to the unrelated Python HTTP client; require
    # the ProjectDiscovery banner so Tool Management doesn't false-positive.
    version_marker = "projectdiscovery"

    def _web_endpoints(self, ctx: PluginContext) -> list[str]:
        urls = []
        for asset in ctx.assets:
            for s in asset.services:
                if s.port in WEB_PORTS or s.name in WEB_NAMES:
                    scheme = "https" if s.port in (443, 8443) or "https" in s.name else "http"
                    urls.append(f"{scheme}://{asset.ip}:{s.port}")
        return urls

    def should_run(self, ctx: PluginContext) -> bool:
        return bool(self._web_endpoints(ctx))

    async def run(self, ctx: PluginContext) -> PluginResult:
        endpoints = self._web_endpoints(ctx)
        ctx.log(f"httpx: probing {len(endpoints)} web endpoint(s)")
        result = PluginResult()

        # A /16 can yield tens of thousands of endpoints, which would blow the
        # OS argv limit; a list file keeps the command line constant-size.
        list_path = os.path.join(ctx.workdir, "httpx_targets.txt")
        with open(list_path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(endpoints) + "\n")

        rc, out, err = await self._exec(
            "httpx", "-json", "-silent", "-title", "-status-code", "-tech-detect",
            "-l", list_path, timeout=600,
        )
        if rc not in (0,) and not out:
            ctx.log(f"httpx: no output (rc={rc})")
            return result

        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            url = data.get("url", "")
            title = data.get("title", "")
            status = data.get("status_code") or data.get("status-code") or ""
            tech = ", ".join(data.get("tech", []) or [])
            result.findings.append(FindingData(
                title=f"Live web service: {url}",
                detail=f"status={status} title={title!r} tech=[{tech}]",
                severity="info",
                source_tool="httpx",
                asset_ip=data.get("host", ""),
            ))
        ctx.log(f"httpx: {len(result.findings)} live endpoint(s)")
        return result
