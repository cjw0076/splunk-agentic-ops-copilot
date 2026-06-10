# Splunk Agentic Ops — Incident Copilot

> **▶ 60-second demo video:** [https://github.com/cjw0076/splunk-agentic-ops-copilot/releases/download/demo-v1/splunk_copilot_demo.mp4](https://github.com/cjw0076/splunk-agentic-ops-copilot/releases/download/demo-v1/splunk_copilot_demo.mp4)


- status: prize-caliber build — 5 scenarios, web dashboard, eval harness, live-Splunk seam, fully offline by default
- event: Devpost hackathon — observability / security / agentic ops with Splunk
- official_url: https://splunk.devpost.com/
- rules_url: https://splunk.devpost.com/rules
- deadline: 2026-06-16
- prize: $20,000
- domain: observability, security, developer experience with Splunk AI
- license: MIT (see `LICENSE`)

## What this is

An **agentic incident-investigation copilot** that, on an anomaly trigger, drives
a real investigation loop over Splunk data:

> anomaly → hypothesis → **run SPL searches** to confirm/refute → contradiction
> → evidence-justified **self-correction** → MITRE-mapped correlation findings →
> **root-cause** → **blast-radius** estimate → **remediation checklist**,

with **every step recorded to an append-only evidence ledger and a replayable
trace**, and every finding citing the exact event rows that justify it.

The key honesty property: **the SPL searches are REAL, not mocked.** The agent
runs genuine SPL strings through a hand-written SPL engine
(`src/splunk_copilot/spl.py`) over synthetic Splunk-style events. The same SPL
strings run unchanged against a real Splunk deployment — only the *search
backend* swaps (see [live-Splunk path](#live-splunk-upgrade-path)).

> **Synthetic data only by default.** No live Splunk, no real systems, no
> customer data, no secrets. All IPs are RFC 5737 documentation ranges or known
> benign scanner space; API keys / secret names are fake placeholders.

## What's in the box

| piece | what it proves |
|-------|----------------|
| **5 diverse incidents** (`data/synthetic/`) | one agent, five distinct attack classes, each with a planted decoy |
| **Real SPL engine** (`spl.py`) | `stats`/`eventstats`/`streamstats`/`timechart`/`transaction`/`bin`/`rex`/`lookup`/`top`/`rare`/`eval`(coalesce/case/round/match/…) — all genuinely executed |
| **One scenario-agnostic agent** (`agent.py`) | manifest-driven; the loop, detectors, ledger, trace, scoring are identical across cases |
| **Detector library** (`detections.py`) | 12 correlation searches AS SPL, MITRE-mapped, each self-gating on real evidence |
| **Web dashboard** (`webapp/`) | live, visual investigation: SPL + result tables, self-correction, MITRE findings, blast radius, replay |
| **Eval harness** (`eval/`) | real benchmark: per-scenario recall/precision/decoy/MITRE-coverage/MTTR + aggregate |
| **Live-Splunk seam** (`backends.py`) | `SearchBackend` interface; `SplunkRestBackend` runs the SAME SPL over `/services/search/jobs` |
| **41 passing tests** (`tests/`) | SPL-command correctness, per-scenario accuracy, evidence integrity, mocked REST flow |

## Run it (stdlib Python only for the core)

```bash
# one-command CLI demo on any scenario
./run_demo.sh data/synthetic/incident-02-ransomware out

# the agent across ALL five scenarios with a real benchmark table
PYTHONPATH=src python3 eval/run_eval.py

# the web dashboard (needs fastapi + uvicorn; pip install -r webapp/requirements.txt)
./run_dashboard.sh        # http://127.0.0.1:8000

# tests
PYTHONPATH=src python3 -m pytest tests/ -q
```

The CLI + eval require only **Python 3.10+** (no pip installs, no network). The
dashboard adds `fastapi` + `uvicorn` (the only dependencies in the whole repo).

Ad-hoc SPL against a case (proves the engine is real):

```bash
PYTHONPATH=src python3 -m splunk_copilot --case-dir data/synthetic/incident-01 \
  --spl 'index=web uri_path="/api/login" status=401 | stats count by clientip'
```

## The five synthetic incidents

The **same agent** solves all five via SPL; each plants a tempting decoy the
agent must form, contradict, and self-correct away from.

| id | attack class | MITRE chain | planted decoy |
|----|--------------|-------------|----------------|
| `incident-01` | external intrusion → data breach | T1110.004 → T1078.004 → T1068 → T1567.002 | benign SSH mass-scanner on the bastion |
| `incident-02-ransomware` | ransomware | T1490 → T1486 | benign EICAR antivirus test file |
| `incident-03-insider` | insider data theft | T1530 | approved high-volume nightly ETL job |
| `incident-04-cloud-ato` | cloud/SaaS account takeover | T1078 → T1098.001 | sanctioned corporate VPN US/EU egress |
| `incident-05-supplychain` | supply-chain compromise | T1195.001 → T1071.001 | legit `webpack` bump that broke tests |

Each case dir has realistic Splunk sourcetypes (`access_combined`, `linux_secure`,
`pan:traffic`, `xmlwineventlog:sysmon`, `okta:authentication`, `okta:system`,
`db:audit`, `ci:build`, `app:payments`), a `threat_intel.csv` lookup, a
`ground_truth.json` (scoring), a `scenario.json` (agent manifest), and a `README.md`.

## Eval results (real run: `python3 eval/run_eval.py`)

```
scenario                  class                       recall  prec  decoy  mitre  mttr  blast
---------------------------------------------------------------------------------------------
incident-01               external_breach                1.0   1.0    yes    4/4     5     ok
incident-02-ransomware    ransomware                     1.0   1.0    yes    2/2     5     ok
incident-03-insider       insider_threat                 1.0   1.0    yes    1/1     5     ok
incident-04-cloud-ato     account_takeover               1.0   1.0    yes    2/2     5     ok
incident-05-supplychain   supply_chain                   1.0   1.0    yes    2/2     5     ok
---------------------------------------------------------------------------------------------
AGGREGATE (macro avg)                                    1.0   1.0   100%          5.0
```

- macro recall / precision: **1.0 / 1.0**, decoy rejection: **100%**
- blast-radius host & identity accuracy: **100%**
- **11 distinct MITRE techniques** covered across the five classes
- mean-time-to-root-cause (real SPL searches to the self-correction): **5.0**
- `tests`: **41/41** green

(`mttr_steps` counts the real SPL searches the agent runs up to and including the
self-correction — an honest proxy for time-to-root-cause. Full machine-readable
report: `eval/report.json`.)

## The web dashboard (`webapp/`)

FastAPI backend + a single-page vanilla-JS frontend (no heavy frameworks). It
runs a **real investigation live** and visualises, step by step:

1. the **anomaly trigger** + sourcetype histogram,
2. the agent's **hypotheses**, each **SPL query as it runs with its real result
   table**, and the **self-correction**,
3. the **MITRE-mapped findings** with **evidence-row citations** and IOCs,
4. **root cause** + a **blast-radius** view (hosts / identities / data assets),
5. the **remediation checklist**,
6. the **accuracy scorecard** (vs ground truth),
7. the full **replayable trace timeline**.

```bash
pip install -r webapp/requirements.txt
./run_dashboard.sh                 # -> http://127.0.0.1:8000
# endpoints: GET /api/scenarios, GET /api/investigate/{id}, POST /api/spl, GET /api/health
```

Runs locally against the synthetic data with **zero credentials**.

## The SPL subset (real engine, not a mock)

`src/splunk_copilot/spl.py` is a hand-written SPL engine — a recursive-descent
parser for `where`/`eval` (no Python `eval()` of search input). Supported:

**Base search:** `index=… sourcetype=… field=value field!=value`, bare terms
(substring over `_raw`/fields), `earliest=<epoch> latest=<epoch>`.

**Pipeline commands:**
`stats` · `eventstats` · `streamstats [window=N]` · `timechart [span=]` ·
`transaction f [maxspan=]` · `bin`/`bucket [span=]` · `rex "(?<name>…)"` ·
`lookup <table.csv> <key> [as f] [OUTPUT …]` · `top`/`rare [limit=N]` ·
`where` · `eval` (`coalesce`, `case`, `round`, `match`, `like`, `strftime`,
`if`, `min`/`max`, … with multi-assignment) · `sort` · `head` · `dedup` ·
`table`/`fields` · `rename`.

Provenance survives aggregation: every result row carries the source event refs,
so a `stats`-collapsed finding still cites the exact lines behind it.

## Architecture

```
data/synthetic/<incident>/*.{jsonl,csv,json}   synthetic events + lookups + manifests
        │  (read-only loader = the search-peer / HEC analog)
        ▼
events.py     EventStore: typed read-only events, stable refs "<file>:<row>"
        ▼
backends.py   SearchBackend: SyntheticBackend (offline) | SplunkRestBackend (live)
        ▼
spl.py        SplEngine: REAL SPL subset; the agent's "Splunk search calls"
        ▼
detections.py 12 correlation searches AS SPL, each MITRE + ops-class mapped,
              self-gating on real evidence (the WHOLE library runs per case)
        ▼
agent.py      InvestigationAgent loop, driven by per-case scenario.json:
   ingest → hypothesis(H1, the decoy) → contradiction → self-correct(H2)
          → correlation findings → root cause → blast radius
          → remediation → verification (vs ground_truth.json)
        ▼
ledger.py     append-only evidence ledger     trace.py  replayable trace
        ▼
out/ledger.json   out/trace.json        eval/report.json        webapp/ dashboard
```

## How it maps to a real Splunk deployment

- the **SPL strings are production-shaped** and can be pasted into a real search
  bar or saved as **correlation searches** in Splunk Enterprise Security;
- the **sourcetypes are real** (`access_combined`, `linux_secure`, `pan:traffic`,
  `xmlwineventlog:sysmon`, `okta:authentication`, `okta:system`, `db:audit`,
  `ci:build`) — the same field names you'd extract live;
- findings carry **MITRE ATT&CK** ids, matching ES's risk/threat framework.

### Live-Splunk upgrade path

`src/splunk_copilot/backends.py` defines a `SearchBackend` seam. The default is
the offline `SyntheticBackend`. The `SplunkRestBackend` runs the **identical SPL**
against a live Splunk over REST (`POST /services/search/jobs` → poll → fetch
results) and adapts the rows into the agent's shape. **The one-line switch:**

```python
from splunk_copilot.backends import make_backend
backend = make_backend(case_dir)          # REST if SPLUNK_URL+SPLUNK_TOKEN set, else synthetic
agent = InvestigationAgent(case_id, case_dir, backend=backend)
```

```bash
export SPLUNK_URL=https://splunk.example:8089
export SPLUNK_TOKEN=<bearer-token>        # the ONLY new input; no secrets in this repo
```

The agent, detectors, ledger, trace, and eval run **unchanged** across backends.
The REST code is real and is unit-tested against a mocked HTTP layer
(`test_splunk_rest_backend_parses_real_rest_flow`) so it's verified even without
a live tenant.

## Ledger schema

Records conform to `docs/agent_evidence_ledger_schema.json`. Each finding adds
`spl` (the re-runnable search), `evidence_refs` (provenance chain),
`mitre_attack`, `ops_class`, `iocs`, `recommendation`. Append-only, never edited.

## Status

- Prize-caliber build: 5 scenarios solved by one agent at recall=precision=1.0,
  100% decoy rejection, 11 MITRE techniques, web dashboard, eval harness, live
  REST seam, **41/41 tests green** — all from real runs.
- Why synthetic by default: a live Splunk trial signup is reCAPTCHA-gated and we
  have no live tenant. The REST seam means a `SPLUNK_TOKEN` is a one-line swap.
- Founder-only gates (not done by the build agent): register on Devpost, publish
  the public repo under MIT, record the demo video.
