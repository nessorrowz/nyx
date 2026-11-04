"""FastAPI application: REST API + static UI.

Endpoints map 1:1 to the console screens:
  GET  /api/tools                 Tool Management (availability)
  GET/POST /api/projects          Projects & Targets
  POST /api/scans                 Scan Center -> enqueue a job
  GET  /api/scans[/{id}]          Scan Jobs (status + live log)
  GET  /api/scans/{id}/assets     Assets & Services
  GET  /api/scans/{id}/findings   Findings
"""
from __future__ import annotations
import asyncio
import json
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlmodel import select
from sqlalchemy import func

from app.db import init_db, get_session
from app.models import Project, ScanJob, Asset, Service, Finding
from app.plugins import registry
from app import jobs
from app.validation import normalize_target, parse_allowlist, enforce_scope

STATIC = Path(__file__).resolve().parent.parent / "static"

# Hard scope allowlist (CIDRs and/or domains, comma-separated). Deny-by-default
# when set; empty means the checkbox gate alone applies. Read per-request so an
# operator can tighten scope without a restart.
def _allowlist() -> list[str]:
    return parse_allowlist(os.environ.get("RECON_SCOPE"))


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    worker = asyncio.create_task(jobs.start_worker())
    try:
        yield
    finally:
        worker.cancel()


app = FastAPI(title="Recon Console", lifespan=lifespan)


# ----- request bodies -----
class ProjectIn(BaseModel):
    name: str


class ScanIn(BaseModel):
    target: str
    scan_mode: str = "full"            # single | custom | full
    profile: str = "standard"          # discovery | standard | extended
    modules: list[str] = []
    project_name: str = "Default"
    scope_confirmed: bool = False
    aggressive_ack: bool = False      # required for the extended profile


# ----- tools -----
@app.get("/api/tools")
def list_tools():
    cat = registry.catalog()
    online = sum(1 for t in cat if t["available"])
    return {"tools": cat, "online": online, "total": len(cat)}


# ----- projects -----
@app.get("/api/projects")
def list_projects():
    with get_session() as s:
        return s.exec(select(Project).order_by(Project.id.desc())).all()


@app.post("/api/projects")
def create_project(body: ProjectIn):
    with get_session() as s:
        p = Project(name=body.name)
        s.add(p); s.commit(); s.refresh(p)
        return p


def _get_or_make_project(name: str) -> int:
    with get_session() as s:
        p = s.exec(select(Project).where(Project.name == name)).first()
        if not p:
            p = Project(name=name)
            s.add(p); s.commit(); s.refresh(p)
        return p.id


# ----- scans -----
SCAN_MODES = {"single", "custom", "full"}
PROFILES = {"discovery", "standard", "extended"}

# Service-word -> ports, so an engagement search for "smb" matches nmap's
# "microsoft-ds" on 445/139. Extend as new tools/services are added.
SERVICE_ALIASES = {
    "smb": {139, 445}, "rdp": {3389}, "winrm": {5985, 5986},
    "ldap": {389, 636}, "mssql": {1433}, "mysql": {3306},
    "ssh": {22}, "ftp": {21}, "rpc": {135},
}


@app.post("/api/scans")
def create_scan(body: ScanIn):
    # Scope gate. The mockup's confirmation checkbox, enforced server-side so a
    # scan can't start without it. Extend with an allowlist: reject targets not
    # inside an approved CIDR/domain set before enqueueing.
    if not body.scope_confirmed:
        raise HTTPException(400, "Target must be confirmed in scope before scanning.")

    try:
        target = normalize_target(body.target)
        enforce_scope(target, _allowlist())
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc

    if body.scan_mode not in SCAN_MODES:
        raise HTTPException(400, f"scan_mode must be one of {sorted(SCAN_MODES)}.")
    if body.profile not in PROFILES:
        raise HTTPException(400, f"profile must be one of {sorted(PROFILES)}.")
    if body.scan_mode != "full":
        if not body.modules:
            raise HTTPException(400, "Select at least one module.")
        unknown = [m for m in body.modules if m not in registry.BY_NAME]
        if unknown:
            raise HTTPException(400, f"Unknown module(s): {', '.join(unknown)}.")
    # The profile only scales a full assessment, and NmapPlugin reads ctx.profile.
    # Without this downgrade a custom scan could reach `nmap -sC` by leaving the
    # hidden profile radio on "extended" - where the ack box isn't even shown.
    profile = body.profile if body.scan_mode == "full" else "standard"
    if profile == "extended" and not body.aggressive_ack:
        raise HTTPException(
            400,
            "The extended profile runs active checks; confirm aggressive_ack to proceed.",
        )

    project_id = _get_or_make_project(body.project_name or "Default")
    with get_session() as s:
        job = ScanJob(
            project_id=project_id,
            target=target,
            scan_mode=body.scan_mode,
            profile=profile,
            modules=",".join(body.modules),
            scope_confirmed=True,
            status="queued",
        )
        s.add(job); s.commit(); s.refresh(job)
        job_id = job.id

    jobs.enqueue(job_id)
    return {"id": job_id, "target": target, "status": "queued"}


@app.get("/api/scans")
def list_scans():
    with get_session() as s:
        rows = s.exec(select(ScanJob).order_by(ScanJob.id.desc())).all()
        # Counts let the UI default to (and flag) the scans that actually hold
        # results. One grouped query each, not a per-job pair (no N+1).
        asset_counts = dict(s.exec(
            select(Asset.scan_job_id, func.count(Asset.id))
            .group_by(Asset.scan_job_id)).all())
        finding_counts = dict(s.exec(
            select(Finding.scan_job_id, func.count(Finding.id))
            .group_by(Finding.scan_job_id)).all())
        out = []
        for r in rows:
            d = _job_summary(r)
            d["assets"] = asset_counts.get(r.id, 0)
            d["findings"] = finding_counts.get(r.id, 0)
            out.append(d)
        return out


@app.get("/api/assets")
def search_assets(service: str = "", port: int | None = None,
                  project_id: int | None = None):
    """Engagement-wide, host-centric query — the product's headline goal
    ("which hosts expose SMB across the whole engagement?"). Merges assets
    across every scan (optionally one project) and filters by service name /
    product substring and/or port.
    """
    needle = service.strip().lower()
    # nmap names SMB "microsoft-ds", RDP "ms-wbt-server", etc., so a plain
    # substring search for "smb"/"rdp" would miss them. Map common service words
    # to their ports so the PRD's "which hosts expose SMB?" query just works.
    alias_ports = SERVICE_ALIASES.get(needle, set())
    with get_session() as s:
        q = select(Asset)
        if project_id is not None:
            # select(ScanJob.id) yields scalar ids, not ScanJob rows.
            job_ids = s.exec(
                select(ScanJob.id).where(ScanJob.project_id == project_id)).all()
            q = q.where(Asset.scan_job_id.in_(job_ids or [-1]))
        assets = s.exec(q).all()

        merged: dict[str, dict] = {}
        for a in assets:
            svcs = s.exec(select(Service).where(Service.asset_id == a.id)).all()
            matched = [
                v for v in svcs
                if (not needle or needle in v.name.lower()
                    or needle in v.product.lower() or v.port in alias_ports)
                and (port is None or v.port == port)
            ]
            if (needle or port is not None) and not matched:
                continue
            shown = matched if (needle or port is not None) else svcs
            m = merged.setdefault(a.ip, {
                "ip": a.ip, "hostname": a.hostname, "os_guess": a.os_guess,
                "scan_ids": set(), "_ports": set(), "services": [],
            })
            m["scan_ids"].add(a.scan_job_id)
            m["hostname"] = m["hostname"] or a.hostname
            m["os_guess"] = m["os_guess"] or a.os_guess
            for v in shown:
                key = (v.port, v.protocol)
                if key in m["_ports"]:
                    continue
                m["_ports"].add(key)
                m["services"].append({
                    "port": v.port, "protocol": v.protocol, "name": v.name,
                    "product": v.product, "version": v.version})

        result = []
        for m in merged.values():
            m["scan_ids"] = sorted(m.pop("scan_ids"))
            m.pop("_ports")
            m["services"].sort(key=lambda x: x["port"])
            result.append(m)
        result.sort(key=lambda m: m["ip"])
        return result


@app.get("/api/scans/{job_id}")
def get_scan(job_id: int):
    with get_session() as s:
        job = s.get(ScanJob, job_id)
        if not job:
            raise HTTPException(404, "No such scan.")
        d = _job_summary(job)
        d["log"] = job.log
        d["error"] = job.error
        return d


@app.get("/api/scans/{job_id}/stream")
async def stream_scan(job_id: int):
    """Server-Sent Events: push log lines and status as the worker writes them,
    so the UI gets live updates without client-side polling. The worker and this
    generator share the one event loop and the DB, so each tick reads committed
    state. The stream closes itself once the job reaches a terminal state.
    """
    def sse(event: str, data) -> str:
        return f"event: {event}\ndata: {json.dumps(data)}\n\n"

    async def gen():
        sent = 0
        last_status = None
        # Confirm the job exists before opening a long-lived stream.
        with get_session() as s:
            if not s.get(ScanJob, job_id):
                yield sse("error", "No such scan.")
                return
        while True:
            with get_session() as s:
                job = s.get(ScanJob, job_id)
                if not job:
                    yield sse("error", "No such scan.")
                    return
                log, status, error = job.log or "", job.status, job.error
            if len(log) > sent:
                yield sse("log", log[sent:])
                sent = len(log)
            if status != last_status:
                yield sse("status", status)
                last_status = status
            if status in ("completed", "failed"):
                yield sse("done", error or "")
                return
            await asyncio.sleep(1)

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/api/scans/{job_id}/assets")
def scan_assets(job_id: int):
    with get_session() as s:
        assets = s.exec(select(Asset).where(Asset.scan_job_id == job_id)).all()
        out = []
        for a in assets:
            svcs = s.exec(select(Service).where(Service.asset_id == a.id)
                          .order_by(Service.port)).all()
            out.append({
                "ip": a.ip, "hostname": a.hostname, "os_guess": a.os_guess,
                "services": [
                    {"port": v.port, "protocol": v.protocol, "name": v.name,
                     "product": v.product, "version": v.version} for v in svcs
                ],
            })
        return out


@app.get("/api/scans/{job_id}/findings")
def scan_findings(job_id: int):
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    with get_session() as s:
        rows = s.exec(select(Finding).where(Finding.scan_job_id == job_id)).all()
        rows.sort(key=lambda f: order.get(f.severity, 9))
        return [
            {"severity": f.severity, "title": f.title, "detail": f.detail,
             "source_tool": f.source_tool, "asset_ip": f.asset_ip} for f in rows
        ]


def _job_summary(job: ScanJob) -> dict:
    return {
        "id": job.id, "target": job.target, "scan_mode": job.scan_mode,
        "profile": job.profile, "modules": job.modules, "status": job.status,
        "created_at": job.created_at.isoformat() if job.created_at else None,
    }


# ----- UI -----
app.mount("/static", StaticFiles(directory=STATIC), name="static")


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")
