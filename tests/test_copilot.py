"""Smoke + correctness + accuracy tests for the Splunk Incident Copilot.

Run: PYTHONPATH=src python3 -m pytest tests/ -q
 or: PYTHONPATH=src python3 tests/test_copilot.py
"""

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from splunk_copilot.agent import InvestigationAgent  # noqa: E402
from splunk_copilot.events import EventStore  # noqa: E402
from splunk_copilot.spl import SplEngine, SplError  # noqa: E402

CASE_DIR = os.path.join(ROOT, "data", "synthetic", "incident-01")


def _engine():
    store = EventStore(CASE_DIR)
    store.load()
    return SplEngine(store)


def _run():
    agent = InvestigationAgent(case_id="incident-01", case_dir=CASE_DIR)
    summary = agent.run()
    return agent, summary


# ---- SPL engine correctness ------------------------------------------------

def test_spl_base_filters():
    eng = _engine()
    r = eng.search('index=web sourcetype=access_combined uri_path="/api/login"')
    assert r.count == 11
    assert all(row["uri_path"] == "/api/login" for row in r.rows)


def test_spl_field_not_equal():
    eng = _engine()
    total = eng.search('index=web uri_path="/api/login"').count
    not200 = eng.search('index=web uri_path="/api/login" status!=200').count
    assert not200 == total - 1  # exactly one 200 success


def test_spl_stats_count_by():
    eng = _engine()
    r = eng.search('index=web uri_path="/api/login" status=401 | stats count by clientip')
    assert r.count == 1
    assert r.rows[0]["clientip"] == "192.0.2.50"
    assert r.rows[0]["count"] == 10


def test_spl_stats_sum_as_and_where():
    eng = _engine()
    r = eng.search('index=web uri_path="/api/export/customers" | where bytes > 1000000 '
                   '| stats count as n sum(bytes) as total by clientip')
    assert r.count == 1
    assert r.rows[0]["n"] == 3
    assert r.rows[0]["total"] == 64450000.0


def test_spl_sort_head_table():
    eng = _engine()
    r = eng.search('index=network | where bytes_out > 1000000 | sort -bytes_out '
                   '| head 2 | table src_ip,dest_ip,bytes_out')
    assert r.count == 2
    assert r.rows[0]["bytes_out"] == 23900000  # largest first
    assert set(r.rows[0].keys()) - {"__refs__"} == {"src_ip", "dest_ip", "bytes_out"}


def test_spl_eval_if():
    eng = _engine()
    r = eng.search('index=web | eval is_login = if(uri_path="/api/login", 1, 0) '
                   '| where is_login=1 | stats count')
    assert r.rows[0]["count"] == 11


def test_spl_time_window():
    eng = _engine()
    # the credential-stuffing burst sits between these epochs
    r = eng.search('index=web uri_path="/api/login" earliest=1749517380 latest=1749517400')
    assert r.count == 11
    r2 = eng.search('index=web uri_path="/api/login" earliest=1749517395')
    assert r2.count < r.count


def test_spl_dedup_and_where_string():
    eng = _engine()
    r = eng.search('index=web clientip=192.0.2.50 status=200 | dedup user | table user')
    users = {row["user"] for row in r.rows}
    assert users == {"svc_deploy"}


def test_spl_rejects_unknown_command():
    eng = _engine()
    try:
        eng.search('index=web | frobnicate foo')
    except SplError:
        return
    raise AssertionError("expected SplError for unsupported command")


def test_spl_refs_survive_aggregation():
    eng = _engine()
    r = eng.search('index=web uri_path="/api/login" status=401 | stats count by clientip')
    # the aggregated row must still carry provenance refs to the source events
    assert len(r.refs) == 10
    assert all(ref.startswith("web_access.jsonl:") for ref in r.refs)


# ---- accuracy / behaviour --------------------------------------------------

def test_perfect_recall_precision_and_decoy_rejected():
    _, summary = _run()
    acc = summary["accuracy"]
    assert acc["scored"]
    assert acc["recall"] == 1.0, f"recall {acc['recall']}, missed {acc['missed']}"
    assert acc["precision"] == 1.0
    assert acc["decoy_rejected"] is True


def test_blast_radius_correct():
    _, summary = _run()
    br = summary["blast_radius"]
    assert set(br["hosts"]) == {"web-prod-01", "app-prod-02"}
    assert set(br["identities"]) == {"svc_deploy"}
    assert summary["accuracy"]["blast_radius_hosts_correct"] is True
    assert summary["accuracy"]["blast_radius_identities_correct"] is True


def test_root_cause_names_leaked_key_and_priv_esc():
    _, summary = _run()
    rc = summary["root_cause"].lower()
    assert "api key" in rc
    assert "privilege escalation" in rc or "grant_role" in rc


# ---- evidence / ledger integrity -------------------------------------------

def test_every_alert_has_evidence_refs():
    agent, _ = _run()
    alerts = [r for r in agent.ledger.records if r["event_type"] == "alert"]
    assert alerts
    for r in alerts:
        assert r["evidence_refs"], f"{r['evidence_id']} missing evidence_refs"
        assert r["evidence_pointer"]


def test_evidence_refs_resolve_to_real_rows():
    agent, _ = _run()
    valid = {ev.ref for ev in agent.store.events}
    # lookups (threat_intel.csv:N) are also valid provenance targets
    for r in agent.store.lookups.get("threat_intel.csv", []):
        valid.add(f"threat_intel.csv:{r['row']}")
    for r in agent.ledger.records:
        for ref in r["evidence_refs"]:
            assert ref in valid, f"{r['evidence_id']} cites non-existent {ref}"


def test_alert_spl_actually_returns_its_evidence():
    """Honesty check: each alert's saved SPL, re-run, must return its refs."""
    agent, _ = _run()
    eng = SplEngine(agent.store)
    for r in agent.ledger.records:
        if r["event_type"] != "alert" or "spl" not in r:
            continue
        got = set(eng.search(r["spl"]).refs)
        # the saved SPL's results must be a subset of the cited evidence
        assert got and got.issubset(set(r["evidence_refs"])), \
            f"{r['evidence_id']} SPL {r['spl']!r} -> {got} not in {r['evidence_refs']}"


def test_self_correction_present_in_trace():
    agent, _ = _run()
    kinds = [s["kind"] for s in agent.trace.steps]
    assert "hypothesis" in kinds
    assert "contradiction" in kinds
    assert "self_correction" in kinds


def test_searches_were_actually_run():
    agent, _ = _run()
    searches = [s for s in agent.trace.steps
                if s["kind"] == "tool_call" and s["tool"] == "splunk.search"]
    assert len(searches) >= 10, "agent should run many real SPL searches"


def test_ledger_schema_required_fields_and_validity():
    agent, _ = _run()
    schema_path = os.path.join(ROOT, "docs", "agent_evidence_ledger_schema.json")
    with open(schema_path, encoding="utf-8") as fh:
        schema = json.load(fh)
    required = set(schema["records"]["required"])
    sev_enum = set(schema["records"]["properties"]["severity"]["enum"])
    status_enum = set(schema["records"]["properties"]["status"]["enum"])
    for r in agent.ledger.records:
        assert required.issubset(r.keys()), r["evidence_id"]
        assert r["severity"] in sev_enum
        assert r["status"] in status_enum


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"PASS {fn.__name__}")
    print(f"\nAll {len(fns)} tests passed.")
