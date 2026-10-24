"""Core pipeline tests: no tools, no web server, no network.

    cd recon-console && python -m unittest discover -s tests

These cover the parts that are easy to break and expensive to notice:
normalisation of a tool's output, the feed-forward/merge behaviour of the
result store, per-plugin failure isolation, and the subprocess timeout path.
"""
import asyncio
import os
import sys
import tempfile
import unittest

os.environ["RECON_DB"] = os.path.join(tempfile.mkdtemp(), "test.db")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlmodel import select  # noqa: E402

from app import jobs  # noqa: E402
from app.db import init_db, get_session  # noqa: E402
from app.models import Asset, Finding, Project, ScanJob, Service  # noqa: E402
from app.plugins import registry  # noqa: E402
from app.plugins.base import (  # noqa: E402
    AssetData, FindingData, Plugin, PluginContext, PluginResult, ServiceData,
)
from app.plugins.nmap_plugin import NmapPlugin  # noqa: E402
from app.validation import normalize_target  # noqa: E402

NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
<host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/>
<hostnames><hostname name="localhost"/></hostnames>
<ports>
<port protocol="tcp" portid="8080"><state state="open"/>
  <service name="http" product="SimpleHTTP" version="0.6"/></port>
<port protocol="tcp" portid="445"><state state="closed"/>
  <service name="microsoft-ds"/></port>
</ports>
<os><osmatch name="Linux 5.0"/></os></host>
<host><status state="down"/><address addr="127.0.0.2" addrtype="ipv4"/></host>
</nmaprun>"""


class BoomPlugin(Plugin):
    name = "boom"
    binary = "python"

    async def run(self, ctx: PluginContext) -> PluginResult:
        raise RuntimeError("kaboom")


class StubPlugin(Plugin):
    name = "stub"
    binary = "python"

    async def run(self, ctx: PluginContext) -> PluginResult:
        return PluginResult(
            assets=[AssetData(ip="10.1.1.1", services=[ServiceData(port=22, name="ssh")])],
            findings=[FindingData(title="stub finding", severity="high", source_tool="stub")],
        )


def _new_job() -> int:
    init_db()
    with get_session() as s:
        project = Project(name="tests")
        s.add(project)
        s.commit()
        s.refresh(project)
        job = ScanJob(project_id=project.id, target="127.0.0.1", scan_mode="custom",
                      profile="standard", modules="boom,stub", scope_confirmed=True,
                      status="queued")
        s.add(job)
        s.commit()
        s.refresh(job)
        return job.id


class TargetValidationTest(unittest.TestCase):
    def test_accepts_what_the_prd_promises(self):
        self.assertEqual(normalize_target("127.0.0.1"), "127.0.0.1")
        self.assertEqual(normalize_target("10.10.5.7/24"), "10.10.5.0/24")
        self.assertEqual(normalize_target("example.com"), "example.com")
        self.assertEqual(normalize_target("https://10.0.0.5:8443/app"), "10.0.0.5")
        self.assertEqual(normalize_target("::1"), "::1")

    def test_refuses_option_injection_and_junk(self):
        for bad in ("--script=/tmp/x", "-iL /etc/passwd", "1.2.3.4 5.6.7.8",
                    "", "   ", "9.9.9.9/999", "ftp://x.com", "bad_host!"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                normalize_target(bad)

    def test_refuses_oversized_ranges(self):
        with self.assertRaises(ValueError):
            normalize_target("10.0.0.0/8")


class NmapParseTest(unittest.TestCase):
    def test_parse_normalises_hosts_and_skips_closed_ports(self):
        workdir = tempfile.mkdtemp()
        path = os.path.join(workdir, "nmap.xml")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(NMAP_XML)

        assets = NmapPlugin._parse(
            path, PluginContext(target="127.0.0.1", profile="discovery", workdir=workdir)
        )

        self.assertEqual(len(assets), 1, "down hosts must be dropped")
        asset = assets[0]
        self.assertEqual((asset.ip, asset.hostname, asset.os_guess),
                         ("127.0.0.1", "localhost", "Linux 5.0"))
        self.assertEqual([s.port for s in asset.services], [8080])
        self.assertEqual(asset.services[0].product, "SimpleHTTP")


class PipelineTest(unittest.TestCase):
    def _run(self, plugins, job_id=None):
        job_id = job_id or _new_job()
        original = registry.select
        registry.select = lambda mode, profile, modules: plugins
        try:
            asyncio.run(jobs._run_job(job_id))
        finally:
            registry.select = original
        return job_id

    def test_a_failing_tool_does_not_fail_the_job(self):
        job_id = self._run([BoomPlugin(), StubPlugin()])
        with get_session() as s:
            job = s.get(ScanJob, job_id)
            self.assertEqual(job.status, "completed")
            self.assertIn("boom: step failed: kaboom", job.log)
            self.assertIn("--- running stub ---", job.log)

    def test_results_are_persisted_and_deduped(self):
        job_id = self._run([StubPlugin(), StubPlugin()])
        with get_session() as s:
            assets = s.exec(select(Asset).where(Asset.scan_job_id == job_id)).all()
            asset_ids = [a.id for a in assets]
            services = s.exec(select(Service).where(Service.asset_id.in_(asset_ids))).all()
            findings = s.exec(select(Finding).where(Finding.scan_job_id == job_id)).all()

        self.assertEqual([a.ip for a in assets], ["10.1.1.1"])
        self.assertEqual(len(services), 1, "same port+protocol must not duplicate")
        self.assertTrue(findings)

    def test_workdir_is_removed(self):
        job_id = _new_job()
        seen = {}

        class SpyPlugin(Plugin):
            name = "spy"
            binary = "python"

            async def run(self, ctx):
                seen["workdir"] = ctx.workdir
                return PluginResult()

        self._run([SpyPlugin()], job_id)
        self.assertTrue(seen["workdir"])
        self.assertFalse(os.path.exists(seen["workdir"]))

    def test_exec_timeout_is_reported(self):
        rc, _out, err = asyncio.run(
            StubPlugin()._exec(sys.executable, "-c", "import time; time.sleep(10)", timeout=1)
        )
        self.assertEqual(rc, 124)
        self.assertIn("timed out", err)


class RegistryTest(unittest.TestCase):
    def test_order_is_catalog_order_not_selection_order(self):
        chosen = registry.select("custom", "standard", ["testssl.sh", "nmap"])
        self.assertEqual([p.name for p in chosen], ["nmap", "testssl.sh"])

    def test_unknown_modules_are_ignored(self):
        self.assertEqual(registry.select("custom", "standard", ["nope"]), [])

    def test_full_profile_discovery_is_nmap_only(self):
        self.assertEqual([p.name for p in registry.select("full", "discovery", [])], ["nmap"])


class ScanGateTest(unittest.TestCase):
    """The gates live in create_scan, not only in the UI."""

    def _post(self, **payload):
        from fastapi import HTTPException

        from app.main import ScanIn, create_scan

        body = ScanIn(**{"scope_confirmed": True, **payload})
        try:
            return create_scan(body), None
        except HTTPException as exc:
            return None, exc

    def test_scope_confirmation_is_required(self):
        _created, err = self._post(target="127.0.0.1", scope_confirmed=False)
        self.assertEqual(err.status_code, 400)

    def test_bad_requests_are_rejected(self):
        for payload in (
            {"target": "--script=/tmp/x", "scan_mode": "custom", "modules": ["nmap"]},
            {"target": "127.0.0.1", "scan_mode": "bogus"},
            {"target": "127.0.0.1", "profile": "bogus"},
            {"target": "127.0.0.1", "scan_mode": "custom", "modules": []},
            {"target": "127.0.0.1", "scan_mode": "custom", "modules": ["evil"]},
        ):
            with self.subTest(payload=payload):
                _created, err = self._post(**payload)
                self.assertEqual(err.status_code, 400)

    def test_extended_profile_needs_active_checks_ack(self):
        _created, err = self._post(target="127.0.0.1", profile="extended")
        self.assertEqual(err.status_code, 400)

        created, err = self._post(target="127.0.0.1", profile="extended",
                                  aggressive_ack=True)
        self.assertIsNone(err)
        self.assertTrue(created["id"])

    def test_custom_scan_cannot_reach_active_checks(self):
        # The profile radios are hidden for custom scans, so a stale "extended"
        # value must not hand `nmap -sC` to a scan nobody acknowledged.
        created, err = self._post(target="127.0.0.1", scan_mode="custom",
                                  profile="extended", modules=["nmap"])
        self.assertIsNone(err)
        with get_session() as s:
            self.assertEqual(s.get(ScanJob, created["id"]).profile, "standard")
if __name__ == "__main__":
    unittest.main()
