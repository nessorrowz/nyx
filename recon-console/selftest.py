"""Runs the real scan pipeline end to end against loopback, no web server.

Exits 0 only if the pipeline actually produced results. A missing binary used
to end as a green "completed" job with no assets, which made this smoke test
decorative; it now fails loudly instead.

    python selftest.py
"""
import asyncio
import os
import shutil
import sys
import tempfile
from pathlib import Path

if shutil.which("nmap") is None:
    print("nmap is not on PATH - the pipeline has nothing to run. Install nmap first.")
    raise SystemExit(2)

# Keep the smoke test out of the real engagement database.
os.environ.setdefault("RECON_DB", str(Path(tempfile.mkdtemp()) / "selftest.db"))

from sqlmodel import select  # noqa: E402

from app.db import init_db, get_session  # noqa: E402
from app.models import Project, ScanJob, Asset, Service, Finding  # noqa: E402
from app import jobs  # noqa: E402


async def main() -> int:
    init_db()
    with get_session() as s:
        p = Project(name="Test")
        s.add(p)
        s.commit()
        s.refresh(p)
        job = ScanJob(project_id=p.id, target="127.0.0.1", scan_mode="full",
                      profile="discovery", scope_confirmed=True, status="queued")
        s.add(job)
        s.commit()
        s.refresh(job)
        jid = job.id

    await jobs._run_job(jid)

    with get_session() as s:
        job = s.get(ScanJob, jid)
        assets = s.exec(select(Asset).where(Asset.scan_job_id == jid)).all()
        finds = s.exec(select(Finding).where(Finding.scan_job_id == jid)).all()
        status = job.status
        print("STATUS:", status, "| error:", job.error or "none")
        print("--- LOG ---")
        print(job.log)
        print("--- ASSETS ---")
        service_count = 0
        for a in assets:
            svcs = s.exec(select(Service).where(Service.asset_id == a.id)).all()
            service_count += len(svcs)
            print(f"  {a.ip}  host={a.hostname or '-'}  "
                  f"services={[(v.port, v.name) for v in svcs]}")
        print("--- FINDINGS ---", [(f.severity, f.title) for f in finds] or "none")

    problems = []
    if status != "completed":
        problems.append(f"status is {status!r}, expected 'completed'")
    if not assets:
        problems.append("no assets were discovered for 127.0.0.1")
    if service_count == 0:
        problems.append("no services were parsed from the nmap XML")

    if problems:
        print("\nFAILED:")
        for p in problems:
            print(" -", p)
        return 1
    print("\nOK: pipeline discovered assets and parsed services.")
    return 0


raise SystemExit(asyncio.run(main()))
