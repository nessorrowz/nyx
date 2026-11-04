"""Nmap: discovery + service/version detection.

Flags scale with the chosen profile so a /24 in 'discovery' mode doesn't turn
into a full -sV sweep. The wide-then-deep idea (fast sweep, then depth only on
open ports) lives inside nmap here; at larger scale you'd front this with
masscan/naabu and feed the open ports back in.
"""
from __future__ import annotations
import os
import xml.etree.ElementTree as ET

from .base import Plugin, PluginContext, PluginResult, AssetData, ServiceData

PROFILE_FLAGS = {
    "discovery": ["-F", "-T4"],                         # top 100 ports, no version
    "standard":  ["--top-ports", "1000", "-sV", "-T4"],
    # -O/--osscan-guess populate Asset.os_guess. OS detection needs raw-socket
    # privilege; when nmap lacks it, bare -O makes nmap *quit* with no XML (it
    # does not silently fall back like -sS does). run() handles that by retrying
    # without -O, so discovery still works for an unprivileged extended scan.
    "extended":  ["--top-ports", "1000", "-sV", "-sC", "-O", "--osscan-guess", "-T4"],
}


class NmapPlugin(Plugin):
    name = "nmap"
    binary = "nmap"
    description = "Port discovery and service enumeration"

    async def run(self, ctx: PluginContext) -> PluginResult:
        flags = PROFILE_FLAGS.get(ctx.profile, PROFILE_FLAGS["standard"])
        xml_path = os.path.join(ctx.workdir, "nmap.xml")
        cmd = ["nmap", *flags, "-oX", xml_path, ctx.target]
        ctx.log(f"nmap: {' '.join(cmd)}")

        rc, out, err = await self._exec(*cmd, timeout=3600)
        # -O without privilege aborts the whole scan before any XML is written.
        # Detect that and retry without OS detection so discovery is never lost.
        if (rc != 0 and not os.path.exists(xml_path)
                and ("-O" in flags or "--osscan-guess" in flags)):
            ctx.log("nmap: OS detection needs root privilege; retrying without -O")
            flags = [f for f in flags if f not in ("-O", "--osscan-guess")]
            cmd = ["nmap", *flags, "-oX", xml_path, ctx.target]
            rc, out, err = await self._exec(*cmd, timeout=3600)
        if rc != 0 and not os.path.exists(xml_path):
            ctx.log(f"nmap failed (rc={rc}): {err.strip()[:300]}")
            return PluginResult()

        assets = self._parse(xml_path, ctx)
        ctx.log(f"nmap: {len(assets)} host(s) up, "
                f"{sum(len(a.services) for a in assets)} open service(s)")
        return PluginResult(assets=assets)

    @staticmethod
    def _parse(xml_path: str, ctx: PluginContext) -> list[AssetData]:
        assets: list[AssetData] = []
        try:
            root = ET.parse(xml_path).getroot()
        except (ET.ParseError, FileNotFoundError):
            return assets

        for host in root.findall("host"):
            if (host.find("status") is not None
                    and host.find("status").get("state") != "up"):
                continue

            ip = ""
            for addr in host.findall("address"):
                if addr.get("addrtype") in ("ipv4", "ipv6"):
                    ip = addr.get("addr", "")
            if not ip:
                continue

            hostname = ""
            hn = host.find("hostnames/hostname")
            if hn is not None:
                hostname = hn.get("name", "")

            os_guess = ""
            osmatch = host.find("os/osmatch")
            if osmatch is not None:
                os_guess = osmatch.get("name", "")

            asset = AssetData(ip=ip, hostname=hostname, os_guess=os_guess)
            for port in host.findall("ports/port"):
                state_el = port.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue
                try:
                    portid = int(port.get("portid", 0))
                except (TypeError, ValueError):
                    continue
                svc = port.find("service")
                asset.services.append(ServiceData(
                    port=portid,
                    protocol=port.get("protocol", "tcp"),
                    name=(svc.get("name", "") if svc is not None else ""),
                    product=(svc.get("product", "") if svc is not None else ""),
                    version=(svc.get("version", "") if svc is not None else ""),
                ))
            assets.append(asset)
        return assets
