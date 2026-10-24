# Recon Console — Project State

**Snapshot date:** 2026-10-24 · **Milestone:** M0 (Foundation) complete

> **What this is:** a point-in-time picture of what's actually built, what's
> verified, and what's next. The PRD says what we're building; this says where
> we are. The README says how to run it.

---

## In one line

A working foundation: the full orchestrator architecture is in place with nmap
fully wired, two enrichment plugins demonstrating the pattern, and the whole
flow verified end to end. It is a vertical slice, not a finished product.

## Status at a glance

| Area | State |
|------|-------|
| Architecture (async jobs, plugins, DB, UI) | **Built** |
| nmap module (scan → parse → persist) | **Built + verified** |
| httpx / testssl.sh modules | **Built** (conditional dispatch verified; need binaries installed to run) |
| Web UI (wizard, jobs, assets, findings, tools) | **Built** (served + rendering verified) |
| Scope confirmation gate | **Built + verified** |
| Internal/AD modules (NetExec, enum4linux, LDAP) | **Not started** |
| Credentialed re-run workflow | **Not started** |
| Report export | **Not started** |
| Scope allowlist, exclude list, rate limits | **Not started** |
| Production job backend / auth / Postgres | **Not started** |

## What works today (verified)

Verified by running the real pipeline, not by inspection:

- **nmap pipeline** — ran against a live local listener; nmap fingerprinted it as
  `http / SimpleHTTPServer`, the service was parsed from nmap XML and persisted,
  and the asset/service rows came back correctly.
- **Conditional dispatch** — the pipeline chained `nmap → httpx`; httpx's
  `should_run` correctly recognized the open web port and only skipped because
  its binary isn't installed in the test environment (graceful skip, not error).
- **API** — `GET /api/tools` 200; `POST /api/scans` without scope confirmation
  returns 400; with confirmation returns 200 and a queued job; `GET /api/scans`
  lists it; `GET /` serves the UI.
- **Tool availability detection** — correctly reports nmap available, httpx and
  testssl.sh not installed.

## Repository map

```
recon-console/
  README.md                 run instructions + architecture + how to extend
  requirements.txt          fastapi, uvicorn, sqlmodel
  run.sh                    launch script (checks nmap, installs deps, runs)
  selftest.py               headless smoke test of the real pipeline
  docs/
    PRD.md                  product requirements
    PROJECT_STATE.md        this file
  app/
    main.py                 FastAPI: REST API + serves UI
    db.py                   SQLite via SQLModel
    models.py               Project / ScanJob / Asset / Service / Finding
    jobs.py                 async queue + background worker + pipeline
    plugins/
      base.py               Plugin contract + common data schema
      registry.py           tool catalog, availability, pipeline selection
      nmap_plugin.py        discovery + service/version detection
      httpx_plugin.py       web probe (conditional on web ports)
      testssl_plugin.py     TLS checks (conditional on TLS services)
  static/index.html         the console UI (one file, no build step)
```

## Key decisions already made

- **Python / FastAPI** — matches the tool ecosystem (most of it is Python) and
  gives clean async subprocess handling.
- **In-process asyncio job queue** for now — zero extra dependencies; designed to
  be swapped for Celery/RQ + Redis without touching plugins or the DB.
- **SQLite, host-centric schema** — queryable engagement-wide store; Postgres is
  a later swap behind the same models.
- **Single-file UI, no build step** — Tailwind via CDN + vanilla JS, so it runs
  with just the Python deps. A full React build is deferred until the UI grows.
- **Scope gate enforced server-side**, not just in the UI.
- **Scanning/enumeration only** — exploitation is deliberately out of scope.

## Known limitations / not yet built

- Only nmap runs usefully out of the box; httpx and testssl.sh need their
  binaries installed, and no internal/AD tools exist yet.
- Live updates are by polling (2s), not streaming.
- No job cancel, timeout override from UI, or resume.
- Scope control is the confirmation checkbox only — no allowlist or exclude list.
- No authentication on the console; loopback-only by default.
- No report export, projects UI, or scheduling yet.
- Jobs are not durable across a process restart (in-memory queue).

## Next up (suggested order)

1. **Internal/AD plugins** — NetExec (`nxc`), enum4linux-ng, ldapdomaindump.
   Highest value for the internal-pentest use case.
2. **Credentialed re-run** — add creds to the plugin context; re-run enrichment
   only, against already-discovered hosts.
3. **Scope allowlist + exclude list** — the cheapest high-value safety upgrade.
4. **Findings/Assets filtering + report export.**
5. **Production hardening** — Celery/Redis, SSE/WebSocket, auth, Postgres.

## How to run / test

```bash
cd recon-console
pip install -r requirements.txt     # nmap must also be on PATH
./run.sh                            # -> http://127.0.0.1:8777
python selftest.py                  # headless pipeline smoke test
```
