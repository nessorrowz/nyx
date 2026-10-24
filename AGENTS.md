# nyx - Recon Console

Web-based orchestrator for network recon and vulnerability *identification* during
**authorized internal penetration tests**. Runs a pipeline of established tools
(nmap, httpx, testssl.sh, ...), normalizes their output into one host-centric
schema, and serves it in a single console UI.

The value is the orchestration and the unified result set - not the scanners.

- `PRD.md` - what to build, in what order, what is out of bounds
- `PROJECT_STATE.md` - what is actually built and verified
- `recon-console/README.md` - how to run it and how to extend it

(`docs/PRD.md` and `docs/PROJECT_STATE.md` inside `recon-console/` are duplicates of
the root copies - keep them in sync if you edit either.)

## Non-negotiables

- **No exploitation.** Recon, enumeration, and vulnerability identification only.
  No payload delivery, no post-exploitation. That line is a product decision, not
  a backlog item.
- **The scope gate stays server-side.** `scope_confirmed` is enforced in
  `POST /api/scans`, never only in the UI. Any new entry point that can send
  packets must inherit the same gate.
- **Loopback by default.** The console binds `127.0.0.1`. It is itself a
  high-value target; do not widen the bind without auth in front.
- **Never scan anything that is not explicitly authorized.** Test only against
  loopback or a lab range you own.

## Layout

```
nyx/
  PRD.md, PROJECT_STATE.md     product + status (read before planning work)
  recon-console/
    app/main.py                FastAPI: REST API + serves the UI
    app/db.py                  SQLite via SQLModel (recon.db, gitignored-by-absence)
    app/models.py              Project / ScanJob / Asset / Service / Finding
    app/jobs.py                asyncio queue + worker + pipeline
    app/plugins/base.py        Plugin contract + AssetData/ServiceData/FindingData
    app/plugins/registry.py    tool catalog, availability, pipeline selection
    app/plugins/*_plugin.py    one file per tool
    static/index.html          the whole UI (one file, no build step)
    selftest.py                headless end-to-end pipeline test
    run.sh                     launch script
```

## Commands

```bash
cd recon-console
pip install -r requirements.txt        # nmap must be on PATH
./run.sh                               # -> http://127.0.0.1:8777 (--reload)
python selftest.py                     # real pipeline against 127.0.0.1, no server
python -m unittest discover -s tests   # 11 core tests, no tools or network needed
```

There is no lint config and no CI. `selftest.py` is the end-to-end smoke test (it
needs nmap and now fails loudly without it); `tests/` covers parsing, persistence,
dispatch and validation in isolation. Run both after touching `jobs.py`, `db.py`,
`models.py`, `validation.py`, or any plugin.

## Architecture contract (read before adding a tool)

`jobs._run_job` walks a plugin list from `registry.select(mode, profile, modules)`:

1. `is_available()` false -> log skip, continue (a missing binary is never an error).
2. `should_run(ctx)` false -> log skip, continue (conditional dispatch).
3. `await run(ctx)` -> `PluginResult`; assets are extended into `ctx.assets`
   so **later** plugins can dispatch on open services, then persisted.

Adding a tool = one `*_plugin.py` subclass + one import/entry in
`registry.PLUGINS` + (if it belongs in a full-assessment profile) a name in
`PROFILE_PIPELINE`. `main.py`, `jobs.py`, `models.py`, and the UI must not need
changes for a new tool - if they do, the contract is being violated and should be
fixed instead of special-cased.

Hard rules that fall out of the above:

- **nmap (or any discovery tool) leads** the pipeline order - everything
  downstream dispatches on its services.
- **Order is catalog order**, not user selection order (`registry.select`
  re-sorts). Do not rely on tick order.
- **A failing tool fails its step, not the job.** Catch per-plugin; `_finish(...,
  "failed")` is reserved for a crashed worker path.
- **Results are written as they are produced** (`_persist` merges one `Asset` row
  per IP per job, dedupes `Service` on port+protocol). Preserve that merging -
  engagement-wide queries depend on it.
- **Never block the event loop.** Subprocesses go through `Plugin._exec` (async,
  with timeout). No `subprocess.run`.
- Scan output goes to a per-job temp dir (`tempfile.mkdtemp`), not the repo.
- **Validate before enqueueing.** `app/validation.py` is the only place that
  decides a target is legal (IP / CIDR <= /16 / hostname / http(s) URL). Everything
  downstream assumes it already ran, and a target ends up in an argv list - never
  accept one that starts with `-` or contains whitespace.
- **Gates live server-side.** `scope_confirmed` and the extended profile's
  `aggressive_ack` are checked in `create_scan`, not just in the UI.

## Conventions

- Python 3.11+ style already in use: `from __future__ import annotations`,
  dataclasses for the plugin schema, SQLModel for tables, type hints everywhere.
- Comments explain *why* (see the module docstrings) - match that density; do not
  narrate obvious code.
- `static/index.html` is one file, Tailwind via CDN, vanilla JS, polling every 2s.
  Keep it build-step-free; no framework until the PRD says otherwise.
- Cite `file:line` when reporting on the code. Run `python selftest.py` after edits.
- Never commit unless explicitly asked.

## Status and next work

M0 (foundation) is done and verified: async jobs, plugin system, DB, UI, nmap
wired, httpx/testssl.sh proving conditional dispatch, scope gate, `GET /api/tools`,
`POST /api/scans` 400-without-confirmation.

Suggested order for M1 (from `PROJECT_STATE.md`):

1. Internal/AD plugins - NetExec (`nxc`), enum4linux-ng, ldapdomaindump
2. Credentialed re-run (creds in `PluginContext`, enrichment-only against known hosts)
3. Scope allowlist + exclude list
4. Findings/Assets filtering + report export
5. Production hardening - Celery/Redis, SSE/WebSocket, auth, Postgres

## Gotchas

- **`httpx` on PATH may not be ProjectDiscovery's httpx.** This machine has
  `~/scoop/apps/miniconda3/.../scripts/httpx` (the Python HTTP client). That is why
  `Plugin.version_marker` exists: a plugin whose name collides with another binary
  must set one (`HttpxPlugin` uses `"projectdiscovery"`), or Tool Management will
  report a false positive and the plugin will just log "no output".
- **nmap is not on PATH in this environment** - install it before anything
  end-to-end works.
- `recon.db` is created next to `recon-console/` on first run and is not committed;
  delete it to reset state.
- Jobs are **not durable across a restart** (in-memory asyncio queue) - a queued
  or running job disappears with the process.
- `jobs.enqueue` must stay thread-safe: `POST /api/scans` is a sync endpoint, so
  FastAPI runs it off-loop. It goes through `loop.call_soon_threadsafe`; a direct
  `_queue.put_nowait` from that thread can leave a job queued indefinitely.
- The UI's live log is polling, not streaming - do not assume push semantics.
- `testssl.sh` availability depends on a shell script plus openssl, so its
  `which` check is weaker than for compiled tools.
