"""CLI: run the Splunk Incident Copilot on a synthetic case and emit artifacts.

Usage:
    python -m splunk_copilot --case-dir data/synthetic/incident-01 --out out
    python -m splunk_copilot --replay out/trace.json       # replay a recorded run
    python -m splunk_copilot --spl 'index=web ... | stats count by clientip'  # ad-hoc SPL
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from .agent import InvestigationAgent
from .backends import make_backend
from .events import EventStore
from .spl import REF_KEY, SplEngine

_C = {
    "h": "\033[1;36m", "ok": "\033[1;32m", "warn": "\033[1;33m",
    "bad": "\033[1;31m", "dim": "\033[2m", "x": "\033[0m",
}


def _color_enabled() -> bool:
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def c(key: str, text: str) -> str:
    if not _color_enabled():
        return text
    return f"{_C[key]}{text}{_C['x']}"


def _rule(title: str) -> None:
    print()
    print(c("h", f"== {title} " + "=" * max(0, 56 - len(title))))


def run_demo(case_dir: str, out_dir: str) -> int:
    case_id = os.path.basename(os.path.normpath(case_dir))
    os.makedirs(out_dir, exist_ok=True)

    print(c("h", "SPLUNK AGENTIC OPS — Incident Copilot"))
    print(c("dim", "SYNTHETIC DATA ONLY — no live Splunk, no real systems, no secrets."))
    print(c("dim", f"Case: {case_id}   Event dir: {case_dir}"))

    backend = make_backend(case_dir)
    bname = type(backend).__name__
    if bname != "SyntheticBackend":
        print(c("warn", f"Backend: {bname} (live Splunk via REST)"))
    agent = InvestigationAgent(case_id=case_id, case_dir=case_dir, backend=backend)
    summary = agent.run()

    _rule("REASONING (hypothesis -> contradiction -> self-correction)")
    for s in agent.trace.steps:
        if s["kind"] == "hypothesis":
            print(c("warn", f"  [HYPOTHESIS {s['hypothesis_id']}] (conf={s['confidence']})"))
            print(f"    {s['statement']}")
        elif s["kind"] == "contradiction":
            print(c("bad", f"  [CONTRADICTION on {s['hypothesis_id']}]"))
            print(f"    reason: {s['reason']}")
            print(c("dim", f"    evidence: {', '.join(s['evidence_refs'])}"))
        elif s["kind"] == "self_correction":
            print(c("ok", f"  [SELF-CORRECT {s['from_hypothesis']} -> new]"))
            print(f"    {s['to_statement']}")
            print(c("dim", f"    rationale: {s['rationale']}"))

    _rule("SPL SEARCHES RUN (real queries over synthetic events)")
    n = 0
    for s in agent.trace.steps:
        if s["kind"] == "tool_call" and s["tool"] == "splunk.search":
            n += 1
            print(c("dim", f"  [{n:>2}] ") + s["args"]["spl"])
            print(c("dim", f"       -> {s['result_count']} events  "
                           f"refs={', '.join(s['result_refs'][:5])}"
                           f"{' ...' if len(s['result_refs']) > 5 else ''}"))

    _rule("EVIDENCE-LINKED FINDINGS (every claim cites event rows)")
    for rec in agent.ledger.records:
        if rec["event_type"] != "alert":
            continue
        sev = rec["severity"].upper()
        sev_c = "bad" if sev in ("CRITICAL", "HIGH") else "warn"
        tag = rec.get("mitre_attack", "-") + "/" + rec.get("ops_class", "-")
        print(c(sev_c, f"  [{sev}] {tag}  {rec['evidence_id']}"))
        print(f"    {rec['summary'].split('] ',1)[-1]}")
        print(c("dim", f"    SPL: {rec.get('spl','')}"))
        print(c("dim", f"    evidence_refs: {rec['evidence_pointer']}"))
        if rec.get("iocs"):
            print(c("dim", f"    IOCs: {', '.join(str(i) for i in rec['iocs'])}"))

    _rule("ROOT CAUSE")
    print(f"  {summary['root_cause']}")

    _rule("BLAST RADIUS (SPL-derived)")
    br = summary["blast_radius"]
    print(f"  affected hosts     : {', '.join(br.get('hosts', [])) or '-'}")
    print(f"  affected identities: {', '.join(br.get('identities', [])) or '-'}")
    print(f"  data assets        : {', '.join(br.get('data_assets', [])) or '-'}")
    print(f"  exfiltrated        : ~{br.get('exfil_mb')} MB outbound")

    _rule("REMEDIATION CHECKLIST (recommendation-only)")
    for rec in agent.ledger.records:
        if rec["event_type"] == "containment":
            for line in rec["recommendation"].split(" || "):
                print(c("ok", f"  [ ] {line}"))

    _rule("ACCURACY SELF-CHECK (vs synthetic ground truth)")
    acc = summary["accuracy"]
    if acc.get("scored"):
        print(f"  techniques matched : {len(acc['matched'])}/{acc['expected_techniques']}")
        print(f"  recall             : {acc['recall']}")
        print(f"  precision          : {acc['precision']}")
        dr = acc["decoy_rejected"]
        print(f"  decoy rejected     : {c('ok','YES') if dr else c('bad','NO')}")
        bh = acc["blast_radius_hosts_correct"]
        bi = acc["blast_radius_identities_correct"]
        print(f"  blast radius hosts : {c('ok','CORRECT') if bh else c('bad','WRONG')}")
        print(f"  blast radius ids   : {c('ok','CORRECT') if bi else c('bad','WRONG')}")
        if acc["missed"]:
            print(c("warn", f"  missed             : {', '.join(acc['missed'])}"))

    ledger_path = os.path.join(out_dir, "ledger.json")
    trace_path = os.path.join(out_dir, "trace.json")
    agent.ledger.write(ledger_path)
    agent.trace.write(trace_path)

    _rule("ARTIFACTS WRITTEN")
    print(f"  ledger : {ledger_path}  ({len(agent.ledger.records)} records)")
    print(f"  trace  : {trace_path}  ({len(agent.trace.steps)} steps, replayable)")
    print()
    print(c("ok", f"DONE — {summary['detections']} findings, final hypothesis "
                  f"{summary['final_hypothesis']}, decoy rejected via self-correction."))
    return 0


def list_scenarios(data_dir: str = "data/synthetic") -> int:
    print(c("h", "Available synthetic scenarios:"))
    if not os.path.isdir(data_dir):
        print(c("bad", f"  no data dir at {data_dir}"))
        return 1
    for name in sorted(os.listdir(data_dir)):
        manifest = os.path.join(data_dir, name, "scenario.json")
        if not os.path.exists(manifest):
            continue
        with open(manifest, encoding="utf-8") as fh:
            m = json.load(fh)
        print(f"  {c('ok', name):<40} {m.get('title','')}")
        print(c("dim", f"    class={m.get('attack_class','-')}  "
                       f"--case-dir {os.path.join(data_dir, name)}"))
    return 0


def replay(trace_path: str) -> int:
    with open(trace_path, encoding="utf-8") as fh:
        tr = json.load(fh)
    print(c("h", f"REPLAY — case {tr['case_id']} — {tr['total_steps']} steps"))
    for s in tr["steps"]:
        tag = s["kind"].upper()
        line = f"  #{s['step']:>2} [{tag}]"
        if s["kind"] == "tool_call":
            line += f" {s['tool']}"
            if s["tool"] == "splunk.search":
                line += f" {s['args']['spl']}"
            line += f" -> {s['result_count']} rows"
            if s["result_refs"]:
                line += c("dim", f"  refs={', '.join(s['result_refs'][:6])}")
        elif s["kind"] == "hypothesis":
            line += f" {s['hypothesis_id']} (conf={s['confidence']}): {s['statement']}"
        elif s["kind"] == "contradiction":
            line += f" {s['hypothesis_id']}: {s['reason']}"
        elif s["kind"] == "self_correction":
            line += f" {s['from_hypothesis']} -> {s['to_statement']}"
        elif s["kind"] == "finding":
            line += f" {s['evidence_id']} {s['label']} refs={', '.join(s['evidence_refs'])}"
        elif s["kind"] == "note":
            line += f" {s['text']}"
        print(line)
    return 0


def ad_hoc_spl(case_dir: str, query: str) -> int:
    store = EventStore(case_dir)
    store.load()
    eng = SplEngine(store)
    res = eng.search(query)
    print(c("h", f"SPL> {query}"))
    print(c("dim", f"{res.count} result row(s); evidence refs: {', '.join(res.refs[:12])}"))
    for row in res.rows:
        clean = {k: v for k, v in row.items() if k != REF_KEY}
        print("  " + json.dumps(clean, ensure_ascii=False))
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="splunk_copilot",
        description="Agentic Splunk incident copilot (synthetic, SPL-driven).")
    p.add_argument("--case-dir", default="data/synthetic/incident-01",
                   help="directory of synthetic Splunk events")
    p.add_argument("--out", default="out", help="output directory for ledger/trace")
    p.add_argument("--replay", metavar="TRACE_JSON",
                   help="replay a previously recorded trace.json and exit")
    p.add_argument("--spl", metavar="QUERY",
                   help="run one ad-hoc SPL query against the case and exit")
    p.add_argument("--list", action="store_true",
                   help="list available synthetic scenarios and exit")
    args = p.parse_args(argv)
    if args.list:
        return list_scenarios()
    if args.replay:
        return replay(args.replay)
    if args.spl:
        return ad_hoc_spl(args.case_dir, args.spl)
    return run_demo(args.case_dir, args.out)


if __name__ == "__main__":
    raise SystemExit(main())
