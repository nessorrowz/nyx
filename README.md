# nyx

Recon Console - a web console that orchestrates network reconnaissance and
vulnerability-identification tools into a single run, for **authorized** internal
penetration tests.

Point it at a target, pick a profile, and it runs a pipeline of established tools
(nmap, httpx, testssl.sh, ...), normalizes their output into one host-centric
schema, and shows assets, services, and findings in one UI.

| Document | What it covers |
|----------|----------------|
| [PRD.md](PRD.md) | what to build, in what order, what is out of bounds |
| [PROJECT_STATE.md](PROJECT_STATE.md) | what is built and verified, what is next |
| [recon-console/README.md](recon-console/README.md) | run instructions, architecture, how to add a tool |
| [AGENTS.md](AGENTS.md) | engineering conventions and invariants for this repo |

## Quick start

```bash
cd recon-console
pip install -r requirements.txt     # nmap must also be on PATH
./run.sh                            # -> http://127.0.0.1:8777
python selftest.py                  # headless pipeline smoke test
```

Binds to loopback by default. Put it behind auth and a trusted network before any
wider exposure - a recon console is itself a high-value target.

**Authorized testing only.** Every scan requires an explicit in-scope
confirmation, enforced server-side; only run against targets you are authorized
to assess.
