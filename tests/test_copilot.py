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


# ---- broadened SPL commands -----------------------------------------------

def test_spl_eventstats_appends_without_collapsing():
    eng = _engine()
    r = eng.search('index=web uri_path="/api/login" status=401 '
                   '| eventstats count as fails by clientip')
    assert r.count == 10  # rows NOT collapsed
    assert all(row["fails"] == 10 for row in r.rows)


def test_spl_streamstats_running_count():
    eng = _engine()
    r = eng.search('index=web uri_path="/api/login" status=401 '
                   '| streamstats count as running by clientip '
                   '| table clientip,running')
    assert [row["running"] for row in r.rows] == list(range(1, 11))


def test_spl_streamstats_window():
    eng = _engine()
    r = eng.search('index=network | sort _time '
                   '| streamstats window=2 sum(bytes_out) as w by index '
                   '| table bytes_out,w')
    # windowed sum over the last 2 events
    assert r.rows[0]["w"] == r.rows[0]["bytes_out"]
    assert r.rows[1]["w"] == r.rows[0]["bytes_out"] + r.rows[1]["bytes_out"]


def test_spl_timechart_by_split():
    eng = _engine()
    r = eng.search('index=web uri_path="/api/login" | timechart span=1m count by status')
    assert r.count == 1
    row = r.rows[0]
    assert row["200"] == 1
    assert row["401"] == 10


def test_spl_bin_buckets_time():
    eng = _engine()
    r = eng.search('index=network | bin span=1m _time '
                   '| stats sum(bytes_out) as out by _time')
    # each bucket boundary is a multiple of 60
    assert all(int(row["_time"]) % 60 == 0 for row in r.rows)
    assert sum(row["out"] for row in r.rows) == \
        sum(ev.get("bytes_out") for ev in eng.store.events if ev.index == "network")


def test_spl_transaction_groups_by_field_with_maxspan():
    eng = _engine()
    r = eng.search('index=web clientip=192.0.2.50 '
                   '| transaction clientip maxspan=10m '
                   '| table clientip,eventcount,duration')
    assert r.count == 1
    assert r.rows[0]["clientip"] == "192.0.2.50"
    assert r.rows[0]["eventcount"] >= 13  # the whole attacker session
    assert r.rows[0]["duration"] > 0


def test_spl_transaction_splits_on_maxspan_gap():
    eng = _engine()
    # tiny maxspan forces each event into its own transaction
    r = eng.search('index=web clientip=192.0.2.50 | transaction clientip maxspan=1s')
    one = eng.search('index=web clientip=192.0.2.50').count
    assert r.count == one  # every event isolated


def test_spl_rex_extracts_named_groups():
    eng = _engine()
    r = eng.search('sourcetype=linux_secure action=failure '
                   r'| rex field=_raw "from (?<ip>\d+\.\d+\.\d+\.\d+) port (?<port>\d+)" '
                   '| dedup ip | table ip')
    assert {row["ip"] for row in r.rows} == {"45.155.205.99"}


def test_spl_lookup_enriches_from_threat_intel():
    eng = _engine()
    r = eng.search('index=web clientip=192.0.2.50 '
                   '| lookup threat_intel.csv indicator as clientip OUTPUT verdict '
                   '| dedup verdict | table clientip,verdict')
    assert r.count == 1
    assert r.rows[0]["verdict"] == "suspicious"


def test_spl_lookup_benign_decoy_ip():
    eng = _engine()
    r = eng.search('sourcetype=linux_secure src_ip=45.155.205.99 '
                   '| lookup threat_intel.csv indicator as src_ip OUTPUT verdict '
                   '| dedup verdict | table verdict')
    assert r.rows[0]["verdict"] == "benign"


def test_spl_top_and_rare():
    eng = _engine()
    top = eng.search('index=web | top limit=1 status')
    assert top.rows[0]["status"] == "401"
    assert top.rows[0]["count"] == 10
    assert 0 < top.rows[0]["percent"] <= 100
    rare = eng.search('index=web | rare limit=1 status')
    assert rare.rows[0]["count"] <= top.rows[0]["count"]


def test_spl_eval_coalesce_case_round():
    eng = _engine()
    r = eng.search('index=web uri_path="/api/login" status=200 '
                   '| eval who=coalesce(user,"anon"), '
                   'verdict=case(status=200,"ok",status=401,"deny"), '
                   'kb=round(bytes/1000.0,2) | table who,verdict,kb')
    row = r.rows[0]
    assert row["who"] == "svc_deploy"
    assert row["verdict"] == "ok"
    assert isinstance(row["kb"], float)


def test_spl_eval_chained_assignments():
    eng = _engine()
    r = eng.search('index=network | eval mb=round(bytes_out/1000000.0,1), '
                   'big=if(mb>5,"huge","ok") | where big="huge" | stats count')
    assert r.rows[0]["count"] == 3  # three >5MB outbound flows


def test_spl_eval_match_and_like():
    eng = _engine()
    r = eng.search('index=web | eval is_api=if(like(uri_path,"/api/%"),1,0) '
                   '| where is_api=1 | stats dc(uri_path) as paths')
    assert r.rows[0]["paths"] >= 3


def test_spl_rename_then_table():
    eng = _engine()
    r = eng.search('index=web uri_path="/api/login" status=401 '
                   '| stats count by clientip | rename clientip as attacker '
                   '| table attacker,count')
    assert r.rows[0]["attacker"] == "192.0.2.50"


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


# ---- all five scenarios: same agent, real numbers ---------------------------

SCENARIOS = [
    "incident-01",
    "incident-02-ransomware",
    "incident-03-insider",
    "incident-04-cloud-ato",
    "incident-05-supplychain",
]


def _run_case(case_id):
    case_dir = os.path.join(ROOT, "data", "synthetic", case_id)
    agent = InvestigationAgent(case_id=case_id, case_dir=case_dir)
    return agent, agent.run()


def test_all_scenarios_solved_perfectly():
    """The ONE agent solves all five incidents: full recall + precision, decoy
    rejected, blast radius correct. Real run, no per-case hardcoding."""
    for case_id in SCENARIOS:
        agent, summary = _run_case(case_id)
        acc = summary["accuracy"]
        assert acc["scored"], case_id
        assert acc["recall"] == 1.0, f"{case_id}: recall {acc['recall']} missed {acc['missed']}"
        assert acc["precision"] == 1.0, f"{case_id}: precision {acc['precision']}"
        assert acc["decoy_rejected"] is True, f"{case_id}: decoy not rejected"
        assert acc["blast_radius_hosts_correct"], case_id
        assert acc["blast_radius_identities_correct"], case_id


def test_all_scenarios_have_self_correction_and_evidence():
    for case_id in SCENARIOS:
        agent, _ = _run_case(case_id)
        kinds = [s["kind"] for s in agent.trace.steps]
        assert "self_correction" in kinds, case_id
        # every alert cites real, resolvable evidence rows
        valid = {ev.ref for ev in agent.store.events}
        for r in agent.store.lookups.get("threat_intel.csv", []):
            valid.add(f"threat_intel.csv:{r['row']}")
        for rec in agent.ledger.records:
            if rec["event_type"] != "alert":
                continue
            assert rec["evidence_refs"], case_id
            for ref in rec["evidence_refs"]:
                assert ref in valid, f"{case_id}: {rec['evidence_id']} cites {ref}"


def test_all_scenarios_alert_spl_returns_its_evidence():
    """Honesty check across all five: each alert's saved SPL, re-run, returns
    a subset of its cited evidence."""
    from splunk_copilot.spl import SplEngine
    for case_id in SCENARIOS:
        agent, _ = _run_case(case_id)
        eng = SplEngine(agent.store)
        for rec in agent.ledger.records:
            if rec["event_type"] != "alert" or "spl" not in rec:
                continue
            got = set(eng.search(rec["spl"]).refs)
            assert got and got.issubset(set(rec["evidence_refs"])), \
                f"{case_id}: {rec['evidence_id']} SPL {rec['spl']!r}"


def test_distinct_mitre_techniques_across_library():
    """The detector library covers a broad, distinct MITRE set across cases."""
    seen = set()
    for case_id in SCENARIOS:
        _, summary = _run_case(case_id)
        seen.update(summary["accuracy"]["detected_techniques"])
    # at least 8 distinct techniques across the five attack classes
    assert len(seen) >= 8, sorted(seen)


# ---- live-Splunk REST backend (mocked HTTP, no live server) -----------------

def test_splunk_rest_backend_parses_real_rest_flow():
    """The REST backend runs the SAME SPL against a mocked Splunk REST API and
    adapts job create -> poll -> results into the agent's row shape."""
    from splunk_copilot.backends import SplunkRestBackend
    from splunk_copilot.spl import REF_KEY

    class FakeHttp:
        def __init__(self):
            self.posted = []
        def post(self, path, data):
            self.posted.append((path, data))
            assert path == "/services/search/jobs"
            assert data["search"].startswith("search ")
            return json.dumps({"sid": "JOB-123"})
        def get(self, path):
            if path.endswith("/results?output_mode=json&count=0") or "/results" in path:
                return json.dumps({"results": [
                    {"clientip": "192.0.2.50", "count": "10", "_time": "1749517380"},
                    {"clientip": "203.0.113.66", "count": "3"},
                ]})
            # status poll
            return json.dumps({"entry": [{"content": {"isDone": True}}]})

    http = FakeHttp()
    be = SplunkRestBackend("https://splunk.example:8089", "tok", http=http)
    eng = be.engine()
    res = eng.search('index=web uri_path="/api/login" status=401 | stats count by clientip')
    assert res.count == 2
    assert res.rows[0]["clientip"] == "192.0.2.50"
    assert res.rows[0]["count"] == "10"
    # provenance refs point at the live job, not synthetic files
    assert all(ref.startswith("splunk:JOB-123:") for ref in res.refs)
    # it actually POSTed a create-job request
    assert http.posted and http.posted[0][0] == "/services/search/jobs"


def test_make_backend_defaults_to_synthetic_without_env(monkeypatch=None):
    from splunk_copilot.backends import make_backend, SyntheticBackend
    os.environ.pop("SPLUNK_URL", None)
    os.environ.pop("SPLUNK_TOKEN", None)
    be = make_backend(CASE_DIR)
    assert isinstance(be, SyntheticBackend)


def test_make_backend_selects_rest_with_env():
    from splunk_copilot.backends import make_backend, SplunkRestBackend
    os.environ["SPLUNK_URL"] = "https://splunk.example:8089"
    os.environ["SPLUNK_TOKEN"] = "tok"
    try:
        be = make_backend(CASE_DIR)
        assert isinstance(be, SplunkRestBackend)
    finally:
        os.environ.pop("SPLUNK_URL", None)
        os.environ.pop("SPLUNK_TOKEN", None)


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"PASS {fn.__name__}")
    print(f"\nAll {len(fns)} tests passed.")
