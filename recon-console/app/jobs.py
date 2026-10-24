"""Async job queue + worker + pipeline.

The one architectural decision that matters most when you put a UI on scanners:
a scan can run for minutes or hours, so it can never happen inside an HTTP
request. Creating a scan just enqueues a job and returns immediately; a
background worker drains the queue and runs the pipeline, writing status and
results to the DB as it goes. The UI polls the DB-backed status.

This uses an in-process asyncio queue to stay dependency-free. For multiple
workers or crash-durable jobs, swap this module for Celery/RQ/ARQ + Redis --
the plugin and DB layers don't change.
"""
from __future__ import annotations
import asyncio
import tempfile
import shutil
from datetime import datetime, timezone

from sqlmodel import select as sqlselect

from app.db import get_session
from app.models import ScanJob, Asset, Service, Finding
from app.plugins import registry
from app.plugins.base import PluginContext

_queue: "asyncio.Queue[int]" = asyncio.Queue()
_loop: "asyncio.AbstractEventLoop | None" = None


def enqueue(job_id: int) -> None:
    """Hand a job id to the worker.

    POST /api/scans is a sync endpoint, so FastAPI runs it on a worker thread.
    asyncio.Queue is not thread-safe: waking the worker's pending get() has to be
    scheduled on the loop, or the job sits queued until an unrelated event wakes
    it.
    """
    loop = _loop
    if loop is not None and loop.is_running():
        loop.call_soon_threadsafe(_queue.put_nowait, job_id)
    else:  # worker not started yet (tests calling _run_job directly)
        _queue.put_nowait(job_id)


async def start_worker() -> None:
    """Launched once on app startup."""
    global _loop
    _loop = asyncio.get_running_loop()
    while True:
        job_id = await _queue.get()
        try:
            await _run_job(job_id)
        except Exception as exc:  # a crashing scan must not kill the worker
            try:
                _finish(job_id, "failed", error=str(exc))
            except Exception:   # a broken DB must not end the drain loop
                pass
        finally:
            _queue.task_done()


def _append_log(job_id: int, line: str) -> None:
    stamp = datetime.now(timezone.utc).strftime("%H:%M:%S")
    with get_session() as s:
        job = s.get(ScanJob, job_id)
        if job:
            job.log = (job.log or "") + f"[{stamp}] {line}\n"
            s.add(job)
            s.commit()


def _finish(job_id: int, status: str, error: str = "") -> None:
    with get_session() as s:
        job = s.get(ScanJob, job_id)
        if job:
            job.status = status
            job.error = error
            job.finished_at = datetime.now(timezone.utc)
            s.add(job)
            s.commit()


async def _run_job(job_id: int) -> None:
    with get_session() as s:
        job = s.get(ScanJob, job_id)
        if not job:
            return
        job.status = "running"
        job.started_at = datetime.now(timezone.utc)
        s.add(job)
        s.commit()
        mode, profile, target = job.scan_mode, job.profile, job.target
        modules = [m for m in (job.modules or "").split(",") if m]

    plugins = registry.select(mode, profile, modules)
    workdir = tempfile.mkdtemp(prefix=f"scan{job_id}_")
    try:
        if not plugins:
            _append_log(job_id, "No runnable modules selected.")
            _finish(job_id, "completed")
            return

        _append_log(job_id, f"Pipeline: {' -> '.join(p.name for p in plugins)}")
        ctx = PluginContext(
            target=target, profile=profile, workdir=workdir,
            log=lambda line: _append_log(job_id, line),
        )

        failed: list[str] = []
        for plugin in plugins:
            # the probe spawns a subprocess; keep it off the loop
            if not await asyncio.to_thread(plugin.is_available):
                _append_log(job_id, f"{plugin.name}: binary not installed, skipping.")
                continue
            if not plugin.should_run(ctx):
                _append_log(job_id, f"{plugin.name}: nothing to act on, skipping.")
                continue
            _append_log(job_id, f"--- running {plugin.name} ---")
            try:
                result = await plugin.run(ctx)
                ctx.assets.extend(result.assets)      # feed forward for dispatch
                _persist(job_id, result)
            except Exception as exc:  # a failing tool fails its step, not the job
                failed.append(plugin.name)
                _append_log(job_id, f"{plugin.name}: step failed: {exc}")
                continue

        if failed:
            _append_log(job_id, f"{len(failed)} step(s) failed: {', '.join(failed)}")
        _append_log(job_id, "Scan complete.")
        _finish(job_id, "completed")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def _persist(job_id: int, result) -> None:
    with get_session() as s:
        for a in result.assets:
            # merge: one Asset row per IP per job
            existing = s.exec(
                sqlselect(Asset).where(Asset.scan_job_id == job_id, Asset.ip == a.ip)
            ).first()
            if existing:
                asset = existing
                if a.hostname and not asset.hostname:
                    asset.hostname = a.hostname
                if a.os_guess and not asset.os_guess:
                    asset.os_guess = a.os_guess
                s.add(asset)
                s.commit()
                s.refresh(asset)
            else:
                asset = Asset(scan_job_id=job_id, ip=a.ip,
                              hostname=a.hostname, os_guess=a.os_guess, status=a.status)
                s.add(asset)
                s.commit()
                s.refresh(asset)
            for svc in a.services:
                dup = s.exec(
                    sqlselect(Service).where(
                        Service.asset_id == asset.id,
                        Service.port == svc.port,
                        Service.protocol == svc.protocol,
                    )
                ).first()
                if dup:
                    continue
                s.add(Service(
                    asset_id=asset.id, port=svc.port, protocol=svc.protocol,
                    name=svc.name, product=svc.product, version=svc.version,
                    state=svc.state,
                ))
            s.commit()

        for f in result.findings:
            s.add(Finding(
                scan_job_id=job_id, asset_ip=f.asset_ip, severity=f.severity,
                title=f.title, detail=f.detail, source_tool=f.source_tool,
            ))
        s.commit()
