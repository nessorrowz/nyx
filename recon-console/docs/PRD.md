# Recon Console — Product Requirements Document

**Status:** Draft v0.1 · **Last updated:** 2026-10-24 · **Owner:** project lead

> **What this document is for:** define what Recon Console must do, for whom, and
> in what order to build it, so implementation stays aligned with the goal and
> scope doesn't drift. Read it to decide what to build next and what's out of bounds.

---

## 1. Summary

Recon Console is a web-based orchestrator for network reconnaissance and
vulnerability scanning during **authorized internal penetration tests**. The
operator enters a target, picks a profile, and the console runs a pipeline of
established tools (nmap, httpx, testssl.sh, and more), normalizes their output
into one schema, and presents assets, services, and findings in a single UI —
instead of running each tool by hand and stitching the results together.

The product's value is the orchestration and the unified result set, not the
scanners themselves, which already exist and are best-in-class.

## 2. Problem

Internal network assessment means running the same sequence of tools against
many hosts, each with its own invocation, output format, and quirks. Operators
lose time on three things: re-running a fixed tool sequence per host,
reconciling incompatible outputs into one picture, and tracking which hosts had
what done to them across a long engagement. Existing GUIs (Legion, SPARTA) model
single-host workflows and don't scale cleanly to subnet sweeps with a queryable,
engagement-wide result set.

## 3. Goals and non-goals

**Goals**
- One run produces combined, normalized results across many tools and hosts.
- A host-centric result store that can be queried across a whole engagement
  (e.g. "which hosts expose SMB?").
- An extensible plugin model so adding a tool is a contained, low-risk change.
- Scope and safety controls built into the workflow, not bolted on.
- A UI an operator can drive without reading tool man pages.

**Non-goals (for now)**
- Exploitation, payload delivery, or post-exploitation. The console does recon,
  enumeration, and vulnerability *identification* only.
- Replacing the underlying tools or reimplementing their logic.
- Being a multi-tenant SaaS. Single-team, self-hosted is the target.
- External/continuous attack-surface monitoring (a possible later product, not
  this one).

## 4. Users

- **Primary — internal pentester / red-teamer.** Runs authorized engagements
  against client or employer internal ranges. Comfortable on the CLI; wants the
  console to remove repetition and give a consolidated, queryable picture.
- **Secondary — engagement lead / reviewer.** Reviews findings and asset
  coverage across the engagement; cares about the Findings and Reports views and
  knowing scope was respected.

## 5. Use cases

1. Sweep a subnet, identify live hosts and their services, and get a single
   ranked list of findings — in one action.
2. Re-run enrichment against already-discovered hosts after obtaining
   credentials, without redoing discovery.
3. Run a single tool against one target for a quick check.
4. Review, mid-engagement, every host and service found so far and filter by
   service or severity.
5. Confirm a target is in scope before any packet is sent, and have the system
   refuse out-of-scope targets.

## 6. Functional requirements

Priority: **P0** must-have for a usable product · **P1** important · **P2** later.

### 6.1 Scan configuration (Scan Center)
- **P0** Accept a target as IP, CIDR, hostname, or URL.
- **P0** Three scan modes: single tool, custom (choose tools), full assessment.
- **P0** Full-assessment profiles that scale tool depth: discovery, standard,
  extended. Extended (active/intrusive checks) is explicitly gated.
- **P0** Require explicit in-scope confirmation before a scan can start.
- **P1** Per-project scope definition (approved CIDRs/domains) used to validate
  targets automatically.
- **P2** Saved scan presets.

### 6.2 Job execution (Scan Jobs)
- **P0** Scans run asynchronously; the UI never blocks on a scan.
- **P0** Each job exposes live status (queued/running/completed/failed) and a log.
- **P0** A failing tool fails its step, not the whole worker or job.
- **P1** Cancel a running job; set per-tool timeouts.
- **P1** Resume/checkpoint so an interrupted engagement doesn't restart from zero.
- **P2** Concurrency controls and rate limiting per target.

### 6.3 Results (Assets & Services, Findings)
- **P0** Normalize all tool output into one schema: Asset → Service → Finding.
- **P0** One asset row per host per job; merge repeated discoveries.
- **P0** Findings carry severity, source tool, and host, and sort by severity.
- **P1** Query/filter assets by service and findings by severity across a job.
- **P2** Deduplicate and correlate findings across tools.

### 6.4 Tool management
- **P0** Detect which tool binaries are installed and show availability.
- **P0** Skip unavailable tools gracefully rather than erroring.
- **P2** Per-tool configuration (wordlists, flags, nuclei templates) from the UI.

### 6.5 Projects, reporting, scheduling
- **P1** Group scans under projects/targets.
- **P1** Export a report (Markdown/HTML/PDF) of assets and findings.
- **P2** Scheduled/recurring scans.

### 6.6 Conditional dispatch
- **P0** Discovery results feed later stages so service-specific tools run only
  against hosts that expose the relevant service (web tools on web ports, TLS
  tools on TLS services, SMB tools on 445, etc.).

## 7. Tool / module catalog

**Implemented:** nmap (discovery + service/version detection), httpx (web probe,
conditional), testssl.sh (TLS, conditional).

**Planned — internal/AD focus (highest priority next):** NetExec (`nxc`) for
SMB/LDAP/MSSQL/WinRM/RDP enumeration, enum4linux-ng, ldapdomaindump /
windapsearch, Greenbone/OpenVAS for network vuln scanning, gowitness/eyewitness
for web-UI screenshots at scale.

**Planned — web/general:** nuclei, whatweb, wafw00f, nikto, ffuf/gobuster, OWASP
ZAP. (nuclei, Greenbone, ZAP appear in the original UI mockups.)

## 8. Non-functional requirements

- **Safety/authorization (P0).** No scan without in-scope confirmation; an
  allowlist (P1) to hard-block out-of-scope targets; an exclude list and a gate
  on aggressive checks to avoid knocking over fragile/legacy/OT devices.
- **Console security (P0).** Binds to loopback by default; must sit behind real
  auth and a trusted network before any wider exposure. A recon console is itself
  a high-value target.
- **Extensibility (P0).** Adding a tool = one plugin file + one registry entry,
  with no changes to the pipeline, DB, API, or UI.
- **Performance (P1).** Wide-then-deep scanning (fast sweep, depth only on open
  ports); handle subnet-scale targets without serial per-host full scans.
- **Durability (P1).** Jobs survive a process restart; results persist.

## 9. UX

Left-nav console (per the approved mockups): Scan Center, Scan Jobs, Assets &
Services, Findings, Tool Management (plus Projects, Reports, Schedules as those
land). Scan Center is a short wizard — target, mode, profile/modules, scope
confirmation, start — with a live summary of what will run. Jobs show a live log.
Results views are scannable and filterable. Copy is plain and operator-facing;
empty and error states say what to do next.

## 10. Data model

`Project → ScanJob → Asset → Service`, with `Finding` attached to a job (and a
host). ScanJob holds mode, profile, module list, status, scope confirmation, and
log. This host-centric shape is what makes engagement-wide queries possible.

## 11. Architecture (summary)

FastAPI backend; async job queue with a background worker running the pipeline;
plugin system with a common contract and result schema; SQLite now, Postgres
later; single-file web UI. The pipeline is a small DAG: discovery first, then
conditional enrichment. See `README.md` for the implemented detail.

## 12. Roadmap

- **M0 — Foundation (done).** Architecture, async jobs, plugin system, DB, UI;
  nmap wired; httpx/testssl.sh demonstrating dispatch; scope gate; verified
  end to end.
- **M1 — Internal/AD modules.** NetExec, enum4linux-ng, ldapdomaindump; Findings
  and Assets filtering; report export.
- **M2 — Credentialed workflow.** Creds as a first-class input; re-run enrichment
  only; Greenbone integration.
- **M3 — Scale & safety hardening.** Scope allowlist, exclude list, rate limits,
  job cancel/timeout/resume; masscan/naabu front-end for large ranges.
- **M4 — Production.** Celery/Redis job backend, SSE/WebSocket live updates,
  auth, Postgres, scheduling.

## 13. Risks

- **Authorization/legal.** Misuse against out-of-scope or unauthorized targets.
  *Mitigation:* mandatory scope confirmation (done), allowlist (M3), audit log.
- **Fragile devices.** Aggressive scans crashing printers/appliances/OT.
  *Mitigation:* exclude list and gated aggressive checks (M3).
- **Scope creep toward exploitation.** Keep the product on the recon/enumeration
  side of the line; exploitation stays a non-goal.
- **Scan-time blowups on large ranges.** *Mitigation:* wide-then-deep, and a
  masscan/naabu front-end (M3).

## 14. Open questions

- Single-operator or multi-user from the start? (Drives auth priority.)
- Is report export needed in M1, or is the queryable UI enough for now?
- Credential storage for the credentialed workflow — in-DB (encrypted) or
  supplied per-run and never persisted?

## 15. Success criteria

- A full internal sweep that previously took a manual tool-by-tool sequence runs
  as one action and yields a consolidated, severity-ranked result set.
- Adding a new tool takes a single plugin file and no other changes.
- No scan ever runs against an unconfirmed target.
