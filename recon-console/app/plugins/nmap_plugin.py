"""Nmap: discovery + service/version detection.

Flags scale with the chosen profile so a /24 in 'discovery' mode doesn't turn
into a full -sV sweep. The wide-then-deep idea (fast sweep, then depth only on
open ports) lives inside nmap here; at larger scale you'd front this with
masscan/naabu and feed the open ports back in.

Depth is pulled out of the XML, not left on the floor:
  - os_guess falls back to the service CPE / extrainfo when -O is unavailable
    (it needs raw-socket privilege, which most runs don't have), so a host is
    still labelled "Linux" from `cpe:/o:linux:...` or `extrainfo="Ubuntu Linux"`.
  - NSE script output (-sC, extended profile) becomes findings: `ftp-anon` is
    high-signal, the rest are informational banners worth recording.
"""
from __future__ import annotations
import os
import xml.etree.ElementTree as ET

from .base import Plugin, PluginContext, PluginResult, AssetData, ServiceData, FindingData

# -Pn: treat hosts as up without ICMP. Internal ranges routinely block ping, so
# a host-discovery probe would skip live boxes; authorized internal testing
# wants every in-scope address scanned.
PROFILE_FLAGS = {
    "discovery": ["-Pn", "-F", "-T4"],                         # top 100 ports, no version
    "standard":  ["-Pn", "--top-ports", "1000", "-sV", "-T4"],
    # -O/--osscan-guess populate Asset.os_guess when privileged. OS detection
    # needs raw-socket privilege; when nmap lacks it, bare -O makes nmap *quit*
    # with no XML (it does not silently fall back like -sS does). run() handles
    # that by retrying without -O; os_guess then comes from CPE/extrainfo.
    "extended":  ["-Pn", "--top-ports", "1000", "-sV", "-sC",
                  "-O", "--osscan-guess", "-T4"],
}

# NSE scripts worth surfacing, and how loud. Unlisted scripts are informational
# banners (http-title, http-server-header, ssh-hostkey, ...).
NSE_SEVERITY = {
    "ftp-anon": "high",            # anonymous FTP login allowed
}
# Keywords used to recognise an OS string in service extrainfo/ostype.
_OS_KEYWORDS = ("windows", "linux", "ubuntu", "debian", "centos", "red hat",
                "freebsd", "openbsd", "darwin", "macos", "android")


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

        # Parse the XML once; both the asset walk and the script walk read the
        # same tree (the file can be large on a wide scan).
        try:
            root = ET.parse(xml_path).getroot()
        except (ET.ParseError, FileNotFoundError):
            return PluginResult()
        assets = self._hosts(root)
        findings = self._scripts(root)
        ctx.log(f"nmap: {len(assets)} host(s) up, "
                f"{sum(len(a.services) for a in assets)} open service(s), "
                f"{len(findings)} script finding(s)")
        return PluginResult(assets=assets, findings=findings)

    @staticmethod
    def _parse(xml_path: str, ctx: PluginContext) -> list[AssetData]:
        """File wrapper around _hosts (used by tests / ad-hoc parsing)."""
        try:
            root = ET.parse(xml_path).getroot()
        except (ET.ParseError, FileNotFoundError):
            return []
        return NmapPlugin._hosts(root)

    @staticmethod
    def _hosts(root: ET.Element) -> list[AssetData]:
        assets: list[AssetData] = []
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

            asset = AssetData(ip=ip, hostname=hostname)
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
            # Prefer a real -O match; otherwise mine CPE/extrainfo so os_guess
            # isn't dead weight on the common unprivileged path.
            asset.os_guess = NmapPlugin._os_guess(host)
            assets.append(asset)
        return assets

    @staticmethod
    def _os_guess(host: ET.Element) -> str:
        osmatch = host.find("os/osmatch")
        if osmatch is not None and osmatch.get("name"):
            return osmatch.get("name", "")
        # Fall back to service evidence.
        for svc in host.findall("ports/port/service"):
            for cpe in svc.findall("cpe"):
                text = (cpe.text or "").strip().lower()
                if text.startswith("cpe:/o:"):
                    guess = _humanize_os_cpe(text)
                    if guess:
                        return guess
            for attr in (svc.get("ostype"), svc.get("extrainfo")):
                guess = _os_from_text(attr or "")
                if guess:
                    return guess
        return ""

    @staticmethod
    def _findings(xml_path: str) -> list[FindingData]:
        """File wrapper around _scripts (used by tests / ad-hoc parsing)."""
        try:
            root = ET.parse(xml_path).getroot()
        except (ET.ParseError, FileNotFoundError):
            return []
        return NmapPlugin._scripts(root)

    @staticmethod
    def _scripts(root: ET.Element) -> list[FindingData]:
        findings: list[FindingData] = []
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

            # Port-level NSE (-sC) output, and host-level scripts.
            for port in host.findall("ports/port"):
                portid = port.get("portid", "")
                for script in port.findall("script"):
                    f = _script_finding(script, ip, portid)
                    if f:
                        findings.append(f)
            for script in host.findall("hostscript/script"):
                f = _script_finding(script, ip, "")
                if f:
                    findings.append(f)
        return findings


def _script_finding(script: ET.Element, ip: str, portid: str) -> FindingData | None:
    sid = script.get("id", "")
    output = (script.get("output", "") or "").strip()
    if not sid or not output:
        return None
    where = f"{ip}:{portid}" if portid else ip
    return FindingData(
        title=f"{sid} on {where}",
        detail=output[:500],
        severity=NSE_SEVERITY.get(sid, "info"),
        source_tool="nmap",
        asset_ip=ip,
    )


def _humanize_os_cpe(cpe: str) -> str:
    # cpe:/o:linux:linux_kernel:5.4 -> "Linux"; cpe:/o:microsoft:windows_10 -> "Windows 10"
    parts = cpe.split(":")
    if len(parts) < 3:
        return ""
    vendor = parts[2]
    product = parts[3] if len(parts) > 3 else ""
    if vendor == "linux":
        return "Linux"
    base = (product or vendor).replace("_", " ").strip()
    return base.title() if base else ""


def _os_from_text(text: str) -> str:
    low = text.lower()
    for kw in _OS_KEYWORDS:
        if kw in low:
            # Return the leading clause ("Ubuntu Linux" from "Ubuntu Linux; protocol 2.0").
            return text.split(";")[0].strip()
    return ""
