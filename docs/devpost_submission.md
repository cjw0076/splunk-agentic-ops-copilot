# Devpost submission — Splunk Agentic Ops: Incident Copilot

> SYNTHETIC DATA ONLY. No live Splunk tenant, no real systems, no secrets. All
> indicators are RFC 5737 / placeholder values, safe to publish.

## Inspiration

On-call engineers and SOC analysts drown in logs. When an alert fires, the hard
part is not searching Splunk — it is *reasoning*: forming a hypothesis, running
the right SPL to confirm or kill it, **noticing when the obvious story is wrong**,
and turning the result into a root cause, a blast radius, and a fix list — with
evidence you can defend in an incident review. We wanted an agent that does that
reasoning out loud, runs real SPL, and never makes a claim it can't cite.

## What it does

Given an anomaly trigger on synthetic Splunk data, the **Incident Copilot**:

1. **Triggers** on an outbound byte spike (firewall sourcetype).
2. **Forms a tempting-but-wrong first hypothesis** — "an SSH brute-force on the
   bastion got in" — because the auth log is full of failed root logins.
3. **Runs SPL to test it** and finds the contradiction: *zero* successful SSH
   logons from that IP, and threat intel rates it a benign internet scanner. It
   **self-corrects**.
4. **Confirms the real chain with SPL correlation searches:** a repo-leaked API
   key → credential stuffing on `/api/login` that *succeeded* as `svc_deploy` →
   privilege escalation via an unguarded `/api/admin/grant_role` → bulk customer
   export → ~64 MB exfil confirmed on the firewall.
5. **Maps each finding to MITRE ATT&CK** (T1110.004 → T1078.004 → T1068 →
   T1567.002) and an ops failure class.
6. **Produces a root-cause summary, an SPL-derived blast radius** (hosts
   `web-prod-01` + `app-prod-02`, identity `svc_deploy`, asset `customers`),
   **and a remediation checklist.**
7. **Self-scores** against ground truth and writes an **append-only evidence
   ledger** + a **replayable trace** — every claim cites the exact event rows,
   and every SPL search it ran is recorded.

The headline: **the Splunk searches are real, not faked.** A hand-written SPL
engine executes genuine SPL strings (`index=… | stats … by …`, `| where`,
`| eval`, `| sort`, `| head`, `| dedup`, `| table`) over the events. You can run
ad-hoc SPL against the case from the CLI and get honest results.

## How we built it

- **Stdlib Python 3.10+, zero dependencies, no network.** Runs offline anywhere.
- `spl.py` — a real SPL subset engine with a recursive-descent parser for
  `where`/`eval` (no Python `eval()` of search input — safe and honest).
  Provenance refs survive `stats` aggregation, so collapsed findings still cite
  source rows.
- `detections.py` — correlation searches expressed *as SPL strings* (the same
  ones you'd save in Splunk Enterprise Security), each mapped to MITRE + an ops
  class.
- `agent.py` — the deterministic, rule-driven investigation loop (anomaly →
  hypothesis → contradiction → self-correction → findings → root cause → blast
  radius → remediation → verification). No LLM, so it is 100% reproducible.
- `ledger.py` / `trace.py` — append-only evidence ledger (schema-conformant) and
  a replayable trace, reused from our sibling DFIR agent so the provenance design
  is battle-tested across two contests.
- A coherent synthetic incident with a `ground_truth.json` and a **planted
  decoy** that the agent must reject on evidence.

## Challenges we ran into

- **No live Splunk access.** The trial signup is reCAPTCHA-gated and we had no
  tenant. We turned that constraint into a design principle: make the *search
  backend* the only synthetic part, and the SPL/agent/ledger everything else.
  Going live is a single-function swap (`SplEngine.search()` → REST/SDK or an
  MCP `run_spl` tool); `SPLUNK_TOKEN` is the only new input.
- **Keeping the engine honest.** It would have been easy to hardcode results.
  Instead we built a genuine parser and added a test that re-runs each finding's
  saved SPL and asserts it returns exactly the cited evidence.
- **Provenance through aggregation.** `stats count by …` normally throws away
  which rows it summarized; we thread source refs through every pipeline stage so
  audit-ability never breaks.

## Accomplishments we're proud of

On the synthetic `incident-01` case, scored against ground truth:

- **recall = 1.0** (4/4 MITRE techniques), **precision = 1.0**
- **decoy rejected** via an evidence-justified self-correction
- **blast radius correct** (hosts + identities exact-match)
- **19/19 tests pass**, including SPL-engine correctness and an
  "every finding's SPL really returns its evidence" honesty test
- fully **offline, stdlib-only, reproducible**, with a replayable audit trail

## What we learned

The differentiator in agentic ops is not raw search — it is *defensible
reasoning*: an explicit wrong-then-corrected hypothesis, and a provenance chain
from every conclusion back to a specific log line. That structure is what an
incident reviewer (and a judge) can actually trust.

## What's next

- **Live Splunk MCP**: point the agent at a Splunk MCP server's `run_spl` tool
  (or the REST/SDK) — same SPL, same agent loop, real data.
- More incident archetypes (deploy-cascade outage, insider data staging,
  token-theft lateral movement) reusing the same harness and scoring.
- Optional LLM narration layer on top of the deterministic core (the core stays
  reproducible; the LLM only explains).
- Push findings back as Splunk **notable events** / risk modifiers.

## Try it (judges)

```bash
./run_demo.sh                                   # full investigation, offline
PYTHONPATH=src python3 -m splunk_copilot --replay out/trace.json   # replay the reasoning
PYTHONPATH=src python3 tests/test_copilot.py    # 19/19 tests
PYTHONPATH=src python3 -m splunk_copilot \
  --spl 'index=web uri_path="/api/login" status=401 | stats count by clientip'
```

## ~3-minute demo video — beats

1. (0:00) One-liner: "an agent that investigates a Splunk incident, runs *real*
   SPL, and cites every claim." Note: synthetic data, offline.
2. (0:20) `./run_demo.sh`. Pause on the **wrong first hypothesis** (SSH
   brute-force) → the **contradiction** (zero successes + benign TI) → the
   **self-correction**.
3. (1:00) Scroll the **SPL searches run** block — these are real queries; show
   one being re-run ad-hoc with `--spl`.
4. (1:40) The **evidence-linked findings** (MITRE ids, SPL, `evidence_refs`),
   then **root cause + blast radius + remediation checklist**.
5. (2:20) The **accuracy self-check** (recall/precision 1.0, decoy rejected) and
   `--replay` of the trace.
6. (2:45) Close on the **live-Splunk upgrade path**: only `SplEngine.search()`
   swaps for an MCP/REST call; `SPLUNK_TOKEN` is the only new input.
