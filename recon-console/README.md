# Recon Console

A web console that orchestrates recon/scanning tools into one run: point it at a
target, pick a profile, and it runs a pipeline of tools, normalizes their output
into one schema, and shows assets, services, and findings in a single UI.

**For authorized penetration testing only.** Every scan requires an explicit
in-scope confirmation, enforced server-side.

This is a working **foundation / vertical slice**, not a finished product: the
full architecture is in place (async job queue, plugin system, host-centric DB,
web UI) with nmap fully wired and three enrichment plugins (httpx, wafw00f,
testssl.sh) demonstrating conditional dispatch. Extending it is a matter of
adding plugins.

## Run it

```bash
cd recon-console
pip install -r requirements.txt    # fastapi, uvicorn, sqlmodel
# nmap must be on PATH:  apt install nmap   (or:  brew install nmap)
./run.sh                            # or: uvicorn app.main:app --port 8777
```

Open http://127.0.0.1:8777. It binds to loopback by default — keep it there, or
put it behind a VPN/SSH tunnel and real auth before exposing it.

To light up the other modules, put their binaries on PATH:
`httpx` (ProjectDiscovery), `wafw00f`, and `testssl.sh`. The Tool Management
screen shows what's detected; missing tools are skipped gracefully, not errored.
A tool whose name collides with an unrelated binary (plain `httpx` is also a Python
HTTP client) is verified by its version banner, so it is reported as not installed
rather than silently doing nothing. Set `version_marker` on such a plugin.

Smoke test without the UI: `python selftest.py` runs the real pipeline against
`127.0.0.1` and prints the result (it needs nmap on PATH and exits non-zero if the
pipeline produced nothing).

Unit tests need no tools and no network: `python -m unittest discover -s tests`.

Every scan is validated server-side before it can be queued: the target must be an
IP, a CIDR of /16 or narrower, a hostname, or an http(s) URL (a URL is reduced to
its host), and the extended profile additionally requires `aggressive_ack` because
it runs active nmap scripts (which also attempt OS detection — best-effort, since
that needs raw-socket privilege; nmap retries without it when unprivileged).

**Hard scope allowlist.** Set `RECON_SCOPE` to a comma/newline-separated list of
CIDRs and/or domains and the API rejects any target outside it, deny-by-default,
before a job is ever queued — the strongest guardrail against a fat-fingered
out-of-scope scan. An entry is a CIDR (an IP/CIDR target must sit inside it) or a
domain (a hostname target must equal it or be a subdomain); IP and domain targets
only match entries of their own kind. Unset means the in-scope checkbox alone
applies.

```bash
export RECON_SCOPE="10.0.0.0/8,192.168.0.0/16,corp.example.com"
```

## How it's built

```
app/
  main.py              FastAPI: REST API + serves the UI
  db.py                SQLite via SQLModel
  models.py            Project / ScanJob / Asset / Service / Finding
  jobs.py              async queue + background worker + pipeline
  plugins/
    base.py            Plugin contract + common data schema
    registry.py        tool catalog, availability, pipeline selection
    nmap_plugin.py     discovery + service/version detection (XML parse)
    httpx_plugin.py    web probe  (runs only on hosts with web ports)
    wafw00f_plugin.py  WAF detection (runs only on hosts with web ports)
    testssl_plugin.py  TLS checks (runs only on TLS services)
static/index.html      the console UI (one file, no build step)
```

Each UI screen maps to a table and an endpoint:

| Screen            | Table            | Endpoint                      |
|-------------------|------------------|-------------------------------|
| Scan Center       | ScanJob          | `POST /api/scans`             |
| Scan Jobs         | ScanJob          | `GET /api/scans[/{id}]`       |
| Assets & Services | Asset + Service  | `GET /api/scans/{id}/assets`  |
| Findings          | Finding          | `GET /api/scans/{id}/findings`|
| Tool Management   | (plugin registry)| `GET /api/tools`              |

### Three design decisions that matter

1. **Scans never run inside an HTTP request.** `POST /api/scans` validates,
   inserts a `queued` job, enqueues its id, and returns immediately. A background
   worker (`jobs.start_worker`) drains the queue and runs the pipeline, writing
   status/log/results to the DB as it goes. The UI polls job status. This is the
   whole reason a scanner-with-a-UI is harder than it looks.

2. **One normalized schema.** Every tool, however it formats output, is parsed
   into `AssetData` / `ServiceData` / `FindingData`. That normalization is the
   real work of an orchestrator and the thing that makes "one run, combined
   results" possible.

3. **Conditional dispatch.** nmap runs first; its results feed forward so web/TLS
   plugins only fire on hosts that actually expose those services. The pipeline
   is a small DAG, not a fixed list.

## Add a tool (the extension seam)

Write one class in `app/plugins/`, add it to `registry.PLUGINS`:

```python
class MyToolPlugin(Plugin):
    name = "mytool"
    binary = "mytool"
    description = "what it does"

    def should_run(self, ctx):          # optional: gate on prior findings
        return any(s.port == 445 for a in ctx.assets for s in a.services)

    async def run(self, ctx):
        rc, out, err = await self._exec("mytool", ctx.target)
        # parse out -> return PluginResult(assets=[...], findings=[...])
        return PluginResult(findings=[...])
```

No changes needed to the pipeline, DB, API, or UI.

## For internal network pentest (your use case)

The two enrichment plugins here are web/TLS-leaning. For AD/internal, add
plugins wrapping the tools that matter inside a perimeter — each is a drop-in:

- **NetExec (`nxc`)** — SMB/LDAP/MSSQL/WinRM/RDP enumeration across many hosts
- **enum4linux-ng** — SMB/share/user enumeration
- **ldapdomaindump** / **windapsearch** — AD/LDAP dumps
- **Greenbone / OpenVAS** — full network vulnerability scanning
- **gowitness / eyewitness** — screenshot internal web UIs at scale

Make credentials a first-class input: the plugin context already carries prior
results; add an optional creds field so you can re-run just the enrichment stage
once you've obtained a foothold.

## Before production

- **Job backend:** swap the in-process `asyncio.Queue` in `jobs.py` for
  Celery/RQ/ARQ + Redis (multiple workers, crash-durable jobs). Plugins and DB
  don't change.
- **Live updates:** the UI now streams the job log over Server-Sent Events
  (`GET /api/scans/{id}/stream`), falling back to 2s polling if the stream
  drops. For multi-worker durability move the stream to a Redis pub/sub or
  WebSockets once the job backend below is swapped.
- **Scope allowlist:** implemented via `RECON_SCOPE` (see above). For production,
  store the approved set per-project in the DB rather than one process-wide env
  var, so each engagement carries its own scope.
- **Fragile-device handling:** internal ranges hide printers/appliances/OT gear.
  Add an exclude list and gate aggressive scripts behind a flag.
- **AuthN/AuthZ**, DB → Postgres, and per-project scope storage.
```
