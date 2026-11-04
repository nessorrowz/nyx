"""wafw00f: Web Application Firewall detection.

Conditional dispatch, like the other web plugins: it only runs against hosts
where nmap found a web port, builds its target list from prior results, and
writes findings for any host fronted by a WAF/CDN. Knowing a WAF sits in front
of a service shapes the rest of the engagement (rate limits, payload shaping),
so it is recon, not a vulnerability -- findings are informational.
"""
from __future__ import annotations
import json
import os

from .base import Plugin, PluginContext, PluginResult, FindingData
from .web import web_endpoints


class Wafw00fPlugin(Plugin):
    name = "wafw00f"
    binary = "wafw00f"
    description = "Web application firewall (WAF) detection"

    def should_run(self, ctx: PluginContext) -> bool:
        return bool(web_endpoints(ctx))

    async def run(self, ctx: PluginContext) -> PluginResult:
        endpoints = web_endpoints(ctx)
        ctx.log(f"wafw00f: probing {len(endpoints)} web endpoint(s)")
        result = PluginResult()

        # Feed targets via a file (-i): a /16 can yield tens of thousands of
        # endpoints and blow the OS argv limit otherwise.
        list_path = os.path.join(ctx.workdir, "wafw00f_targets.txt")
        with open(list_path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(endpoints) + "\n")
        out_path = os.path.join(ctx.workdir, "wafw00f.json")

        rc, out, err = await self._exec(
            "wafw00f", "-i", list_path, "-f", "json", "-o", out_path,
            timeout=600,
        )
        if not os.path.exists(out_path):
            ctx.log(f"wafw00f: no output (rc={rc})")
            return result
        try:
            with open(out_path, encoding="utf-8", errors="replace") as fh:
                entries = json.load(fh)
        except (json.JSONDecodeError, OSError):
            ctx.log("wafw00f: could not parse output")
            return result
        if not isinstance(entries, list):
            return result

        for e in entries:
            if not isinstance(e, dict) or not e.get("detected"):
                continue
            firewall = str(e.get("firewall") or "unknown").strip()
            if firewall.lower() in ("none", "generic", ""):
                continue
            url = str(e.get("url") or "")
            vendor = str(e.get("manufacturer") or "").strip()
            result.findings.append(FindingData(
                title=f"WAF detected: {firewall}" + (f" ({vendor})" if vendor else ""),
                detail=f"url={url} firewall={firewall} manufacturer={vendor}",
                severity="info",
                source_tool="wafw00f",
                asset_ip=_host_of(url),
            ))
        ctx.log(f"wafw00f: {len(result.findings)} WAF(s) detected")
        return result


def _host_of(url: str) -> str:
    """Pull the bare host out of scheme://host:port so the finding keys to an
    Asset.ip (which is how the per-host view groups it)."""
    rest = url.split("://", 1)[-1]
    host = rest.split("/", 1)[0]
    if host.startswith("[") and "]" in host:        # [ipv6]:port
        return host[1:host.index("]")]
    return host.rsplit(":", 1)[0] if ":" in host else host
