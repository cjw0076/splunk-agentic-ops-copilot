# Splunk Agentic Ops — Incident Copilot

> **▶ 60-second demo video:** [https://github.com/cjw0076/splunk-agentic-ops-copilot/releases/download/demo-v1/splunk_copilot_demo.mp4](https://github.com/cjw0076/splunk-agentic-ops-copilot/releases/download/demo-v1/splunk_copilot_demo.mp4)


- status: working synthetic MVP (demo-ready, fully offline)
- event: Devpost hackathon — observability / security / agentic ops with Splunk
- official_url: https://splunk.devpost.com/
- rules_url: https://splunk.devpost.com/rules
- deadline: 2026-06-15
- prize: $20,000
- domain: observability, security, developer experience with Splunk AI
- license: MIT (see `LICENSE`)

## What this is

An **agentic incident-investigation copilot** that, on an anomaly trigger,
drives a real investigation loop over Splunk data:

> anomaly → hypothesis → **run SPL searches** to confirm/refute → contradiction
> → evidence-justified **self-correction** → MITRE-mapped correlation findings →
> **root-cause** → **blast-radius** estimate → **remediation checklist**,

with **every step recorded to an append-only evidence ledger and a replayable
trace**, and every finding citing the exact event rows that justify it.

The key honesty property: **the SPL searches are REAL, not mocked.** The agent
runs genuine SPL strings through a small SPL engine (`src/splunk_copilot/spl.py`)
over synthetic Splunk-style events. The same SPL strings would run unchanged in a
real Splunk deployment — only the search *backend* swaps (see
[live-Splunk upgrade path](#live-splunk-upgrade-path)).

> **Synthetic data only.** No live Splunk, no real systems, no customer data, no
> secrets. All IPs are RFC 5737 documentation ranges or known benign scanner
> space; the API key id is a fake placeholder.

## Run the demo (one command, stdlib Python only)

```bash
./run_demo.sh
# or explicitly:
PYTHONPATH=src python3 -m splunk_copilot --case-dir data/synthetic/incident-01 --out out
```

Requires only Python 3.10+ (no pip installs, no network). Outputs:

- `out/ledger.json` — the evidence-linked finding ledger (schema below)
- `out/trace.json` — the replayable trace (every SPL search + reasoning step)

Replay the recorded reasoning + SPL:

```bash
PYTHONPATH=src python3 -m splunk_copilot --replay out/trace.json
```

Run an ad-hoc SPL query against the case (proves the engine is real):

```bash
PYTHONPATH=src python3 -m splunk_copilot \
  --spl 'index=web uri_path="/api/login" status=401 | stats count by clientip'
```

Run the tests:

```bash
PYTHONPATH=src python3 tests/test_copilot.py     # or: python3 -m pytest tests/ -q
```

## Results (from the test run)

On the synthetic `incident-01` case, against its ground truth:

| metric | value |
|--------|-------|
| MITRE techniques recall | **1.0** (4/4) |
| precision | **1.0** |
| decoy rejected (via self-correction) | **YES** |
| blast-radius hosts correct | **YES** (`web-prod-01`, `app-prod-02`) |
| blast-radius identities correct | **YES** (`svc_deploy`) |
| tests passing | **19/19** |

## The synthetic incident (`incident-01`)

One coherent story across four Splunk sourcetypes:

> A deploy service-account **API key was accidentally committed to a public repo**
> → an attacker (`192.0.2.50`) ran **credential stuffing** against `/api/login`
> → **succeeded as `svc_deploy`** → **escalated to admin** via an unguarded
> `/api/admin/grant_role` endpoint → **bulk-exported the customers table** three
> times, exfiltrating ~64 MB outbound (confirmed on the firewall).

MITRE chain: T1110.004 → T1078.004 → T1068 → T1567.002, plus an ops
`service_error_cascade` class.

**Planted decoy:** an internet SSH scanner (`45.155.205.99`) brute-forces the
bastion with 8 failed logins. It *looks* like the entry vector but never
authenticates and is rated benign in threat intel — the agent must form that
wrong hypothesis first, hit the contradiction, and self-correct.

Dataset + ground truth: `data/synthetic/incident-01/` (see its `README.md`).

## The SPL subset supported (real engine, not a mock)

`src/splunk_copilot/spl.py` is a hand-written SPL engine — a recursive-descent
parser for `where`/`eval` (no Python `eval()` of search input). Supported:

**Base search** (before the first `|`):
- `index=… sourcetype=…` and any `field=value` / `field!=value`
- bare terms (substring match over `_raw` / all fields)
- `earliest=<epoch> latest=<epoch>` time-window filters

**Pipeline commands** (after each `|`):
- `| stats count [as X] [sum|avg|min|max|dc|values(f) [as Y] …] [by f1,f2]`
- `| where <expr>` — `=,!=,<,<=,>,>=`, `AND/OR/NOT`, `like()`, `match()`,
  arithmetic, parentheses
- `| eval newfield = <expr>` — arithmetic / string concat / `if(...)`
- `| sort [-]field[, …] [limit]`, `| head N`, `| dedup f[, …]`
- `| table f1,f2,…` (= `| fields …`), `| rename old as new[, …]`

Provenance survives aggregation: every result row carries the source event
refs, so a `stats`-collapsed finding still cites the exact lines behind it.

## Architecture

```
data/synthetic/incident-01/*.{jsonl,csv}      synthetic Splunk events + lookups
        │  (read-only loader = the search-peer / HEC analog)
        ▼
src/splunk_copilot/events.py     EventStore: typed read-only events,
                                 stable provenance refs "<file>:<row>"
        ▼
src/splunk_copilot/spl.py        SplEngine: REAL SPL subset; the agent's
                                 "Splunk search calls" run through here
        ▼
src/splunk_copilot/detections.py correlation searches AS SPL, each mapped to
                                 a MITRE technique + ops failure class
        ▼
src/splunk_copilot/agent.py      InvestigationAgent loop:
   ingest → hypothesis(H1, wrong) → contradiction → self-correct(H2)
          → correlation findings → root cause → blast radius
          → remediation → verification
        ▼
src/splunk_copilot/ledger.py     append-only evidence ledger (schema-conformant)
src/splunk_copilot/trace.py      append-only replayable trace (SPL + reasoning)
        ▼
out/ledger.json   out/trace.json
```

## Ledger schema

Records conform to `docs/agent_evidence_ledger_schema.json` (a shared asset with
the sibling `find_evil` DFIR agent — same provenance-chain design). Each finding
adds `spl` (the re-runnable search), `evidence_refs` (full provenance chain),
`mitre_attack`, `ops_class`, `iocs`, and `recommendation`. Records are
append-only and never edited.

## How it maps to a real Splunk deployment

Everything the agent does is shaped like real Splunk usage:

- the **SPL strings are production-shaped** — `index=… sourcetype=… | stats … by
  …`, `| where …`, `| eval …` — and can be pasted into a real search bar or saved
  as **correlation searches** in Splunk Enterprise Security.
- the **sourcetypes are real** (`access_combined`, `linux_secure`, `pan:traffic`,
  an app log) — the same field names you would extract live.
- findings carry **MITRE ATT&CK** ids, matching ES's risk/threat framework.

### Live-Splunk upgrade path

The only thing synthetic is the *search backend*. To go live, swap
`SplEngine.search()` for a thin client and keep everything else:

```python
# Option A: Splunk REST / SDK
import splunklib.client as client          # pip install splunklib
svc = client.connect(token=os.environ["SPLUNK_TOKEN"], host=..., port=8089)
def search(spl: str) -> SearchResult:
    job = svc.jobs.create(f"search {spl}", exec_mode="blocking")
    rows = [dict(r) for r in results.JSONResultsReader(job.results(output_mode="json"))]
    return SearchResult(spl, rows)

# Option B: Splunk MCP server (agentic)
#   point an MCP client at a Splunk MCP server and call its `run_spl` tool;
#   the agent loop, detections, ledger, trace, and scoring are unchanged.
```

`SPLUNK_TOKEN` / the MCP endpoint is the *only* new input. No secrets live in
this repo; nothing else in the agent changes. The detectors, the
self-correction loop, the ledger, the trace, and the accuracy harness are
backend-agnostic.

## Status / blockers

- Working synthetic MVP: end-to-end run, 4/4 MITRE techniques recovered, decoy
  rejected, blast radius correct, recall=precision=1.0, 19/19 tests green.
- Why synthetic: a live Splunk trial signup is reCAPTCHA-gated and we have no
  live tenant. The architecture is built so a `SPLUNK_TOKEN` or an MCP endpoint
  is a one-function swap (above).
- Founder-only gates (NOT done by the build agent): register on Devpost,
  publish the public repo under MIT, record the demo video.

## Immediate tasks (remaining — founder)

1. Register on Devpost; publish this repo under MIT.
2. Record a ~3-min demo video (`docs/devpost_submission.md` has the script beats).
3. (optional) Attach a live Splunk token / MCP endpoint to run against real data.
