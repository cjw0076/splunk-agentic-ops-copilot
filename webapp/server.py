"""FastAPI backend for the Splunk Incident Copilot dashboard.

Runs a real investigation (the same ``InvestigationAgent`` over synthetic data,
zero credentials) and exposes its structured output so the single-page frontend
can visualise: the anomaly trigger, the agent's hypotheses, every SPL query as it
runs with its real result table, the self-correction, the MITRE-mapped findings
with evidence-row citations, the blast-radius view, the remediation checklist,
and the replayable trace timeline.

Endpoints (all read-only, synthetic):
    GET  /                       -> the dashboard SPA
    GET  /api/scenarios          -> list of available synthetic incidents
    GET  /api/investigate/{id}   -> full structured investigation result
    POST /api/spl                -> run an ad-hoc SPL query against a scenario
    GET  /api/health             -> liveness

Run:
    PYTHONPATH=src uvicorn webapp.server:app --reload --port 8000
"""

from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from fastapi import FastAPI, HTTPException  # noqa: E402
from fastapi.responses import HTMLResponse, JSONResponse  # noqa: E402
from pydantic import BaseModel  # noqa: E402

from splunk_copilot.agent import InvestigationAgent  # noqa: E402
from splunk_copilot.events import EventStore  # noqa: E402
from splunk_copilot.spl import REF_KEY, SplEngine, SplError  # noqa: E402

DATA_DIR = os.path.join(ROOT, "data", "synthetic")
WEB_DIR = os.path.dirname(os.path.abspath(__file__))

app = FastAPI(title="Splunk Incident Copilot", version="1.0.0")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _scenarios() -> list[dict]:
    out = []
    for name in sorted(os.listdir(DATA_DIR)):
        case_dir = os.path.join(DATA_DIR, name)
        manifest = os.path.join(case_dir, "scenario.json")
        if not (os.path.isdir(case_dir) and os.path.exists(manifest)):
            continue
        import json
        with open(manifest, encoding="utf-8") as fh:
            m = json.load(fh)
        out.append({"id": name, "title": m.get("title", name),
                    "attack_class": m.get("attack_class", "-")})
    return out


def _clean_rows(rows: list[dict], limit: int = 25) -> list[dict]:
    """Strip the internal refs key but keep an evidence-ref summary per row."""
    out = []
    for r in rows[:limit]:
        clean = {k: v for k, v in r.items() if k != REF_KEY}
        clean["_evidence"] = r.get(REF_KEY, [])
        out.append(clean)
    return out


def _investigate(case_id: str) -> dict:
    case_dir = os.path.join(DATA_DIR, case_id)
    if not os.path.isdir(case_dir):
        raise HTTPException(status_code=404, detail=f"unknown scenario {case_id}")
    agent = InvestigationAgent(case_id=case_id, case_dir=case_dir)
    summary = agent.run()

    # event-store overview (sourcetype histogram) for the ingest panel
    by_st: dict[str, int] = {}
    for ev in agent.store.events:
        by_st[ev.sourcetype] = by_st.get(ev.sourcetype, 0) + 1

    # build a re-runner so each SPL search in the trace gets a live result table
    eng = SplEngine(agent.store)

    timeline = []
    for step in agent.trace.steps:
        entry = {"step": step["step"], "kind": step["kind"], "ts": step["ts_wall_utc"]}
        if step["kind"] == "tool_call" and step.get("tool") == "splunk.search":
            spl = step["args"]["spl"]
            try:
                res = eng.search(spl)
                entry["spl"] = spl
                entry["result_count"] = res.count
                entry["columns"] = _columns(res.rows)
                entry["rows"] = _clean_rows(res.rows)
                entry["evidence_refs"] = step.get("result_refs", [])[:8]
            except SplError as exc:  # pragma: no cover - defensive
                entry["spl"] = spl
                entry["error"] = str(exc)
        elif step["kind"] == "hypothesis":
            entry.update(hypothesis_id=step["hypothesis_id"],
                         statement=step["statement"], confidence=step["confidence"])
        elif step["kind"] == "contradiction":
            entry.update(hypothesis_id=step["hypothesis_id"], reason=step["reason"],
                         evidence_refs=step["evidence_refs"])
        elif step["kind"] == "self_correction":
            entry.update(from_hypothesis=step["from_hypothesis"],
                         to_statement=step["to_statement"], rationale=step["rationale"])
        elif step["kind"] == "finding":
            entry.update(evidence_id=step["evidence_id"], label=step["label"],
                         evidence_refs=step["evidence_refs"])
        elif step["kind"] == "note":
            entry.update(text=step["text"])
        timeline.append(entry)

    findings = []
    for d in agent.detections_found:
        findings.append({
            "rule_id": d.rule_id, "mitre": d.mitre, "ops_class": d.ops_class,
            "label": d.label, "severity": d.severity, "summary": d.summary,
            "spl": d.spl, "evidence_refs": d.evidence_refs, "iocs": d.iocs,
            "recommendation": d.recommendation,
        })

    remediation = []
    for rec in agent.ledger.records:
        if rec["event_type"] == "containment" and rec.get("recommendation"):
            remediation = rec["recommendation"].split(" || ")

    anomaly = agent.manifest.get("anomaly", {})
    return {
        "case_id": case_id,
        "title": summary["title"],
        "attack_class": agent.manifest.get("attack_class", "-"),
        "anomaly": {"summary": anomaly.get("summary", ""),
                    "spl": anomaly.get("spl", ""),
                    "time_utc": anomaly.get("trigger_time_utc", "")},
        "sourcetypes": by_st,
        "event_count": len(agent.store.events),
        "timeline": timeline,
        "findings": findings,
        "root_cause": summary["root_cause"],
        "blast_radius": summary["blast_radius"],
        "remediation": remediation,
        "accuracy": summary["accuracy"],
        "iocs": agent.manifest.get("iocs", []),
        "ledger_records": summary["ledger_records"],
        "trace_steps": summary["trace_steps"],
    }


def _columns(rows: list[dict]) -> list[str]:
    cols: list[str] = []
    for r in rows:
        for k in r.keys():
            if k != REF_KEY and k not in cols:
                cols.append(k)
    return cols


# ---------------------------------------------------------------------------
# routes
# ---------------------------------------------------------------------------

@app.get("/api/health")
def health():
    return {"status": "ok", "scenarios": len(_scenarios()), "synthetic": True}


@app.get("/api/scenarios")
def scenarios():
    return {"scenarios": _scenarios()}


@app.get("/api/investigate/{case_id}")
def investigate(case_id: str):
    return JSONResponse(_investigate(case_id))


class SplRequest(BaseModel):
    case_id: str
    spl: str


@app.post("/api/spl")
def run_spl(req: SplRequest):
    case_dir = os.path.join(DATA_DIR, req.case_id)
    if not os.path.isdir(case_dir):
        raise HTTPException(status_code=404, detail=f"unknown scenario {req.case_id}")
    store = EventStore(case_dir)
    store.load()
    eng = SplEngine(store)
    try:
        res = eng.search(req.spl)
    except SplError as exc:
        raise HTTPException(status_code=400, detail=f"SPL error: {exc}")
    return {"spl": req.spl, "count": res.count, "columns": _columns(res.rows),
            "rows": _clean_rows(res.rows), "refs": res.refs[:20]}


@app.get("/", response_class=HTMLResponse)
def index():
    with open(os.path.join(WEB_DIR, "index.html"), encoding="utf-8") as fh:
        return fh.read()
