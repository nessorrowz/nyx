"""testssl.sh: TLS/certificate assessment.

Runs only against services that look like TLS, and maps testssl's severity
findings into the common schema. Kept narrow (--severity LOW) so output is
actionable rather than a wall of cipher lines.
"""
from __future__ import annotations
import json
import os

from .base import Plugin, PluginContext, PluginResult, FindingData

TLS_PORTS = {443, 8443, 993, 995, 465, 990, 636, 989}
TLS_NAMES = {"https", "ssl", "tls", "imaps", "pop3s", "smtps", "ldaps"}

# testssl severity string -> our scale
SEV_MAP = {
    "CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium",
    "LOW": "low", "WARN": "low", "INFO": "info", "OK": "info",
}


class TestsslPlugin(Plugin):
    name = "testssl.sh"
    binary = "testssl.sh"
    description = "TLS and certificate assessment"

    def _tls_targets(self, ctx: PluginContext) -> list[tuple[str, int]]:
        targets = []
        for asset in ctx.assets:
            for s in asset.services:
                if s.port in TLS_PORTS or s.name in TLS_NAMES:
                    targets.append((asset.ip, s.port))
        return targets

    def should_run(self, ctx: PluginContext) -> bool:
        return bool(self._tls_targets(ctx))

    async def run(self, ctx: PluginContext) -> PluginResult:
        result = PluginResult()
        for ip, port in self._tls_targets(ctx):
            # Brackets keep IPv6 unambiguous for testssl; the finding still
            # records the bare address.
            host = f"[{ip}]" if ":" in ip else ip
            tgt = f"{host}:{port}"
            ctx.log(f"testssl.sh: scanning {tgt}")
            jf = os.path.join(ctx.workdir, f"testssl_{ip.replace(':', '_')}_{port}.json")
            rc, out, err = await self._exec(
                "testssl.sh", "--quiet", "--color", "0", "--severity", "LOW",
                "--jsonfile", jf, tgt, timeout=900,
            )
            if not os.path.exists(jf):
                ctx.log(f"testssl.sh: no result for {tgt} (rc={rc})")
                continue
            try:
                with open(jf, encoding="utf-8", errors="replace") as fh:
                    entries = json.load(fh)
            except (json.JSONDecodeError, OSError):
                continue
            if not isinstance(entries, list):
                continue
            for e in entries:
                sev = SEV_MAP.get(str(e.get("severity", "INFO")).upper(), "info")
                if sev == "info":
                    continue
                result.findings.append(FindingData(
                    title=f"TLS: {e.get('id', 'finding')} on {tgt}",
                    detail=str(e.get("finding", ""))[:500],
                    severity=sev,
                    source_tool="testssl.sh",
                    asset_ip=ip,
                ))
        ctx.log(f"testssl.sh: {len(result.findings)} finding(s)")
        return result
