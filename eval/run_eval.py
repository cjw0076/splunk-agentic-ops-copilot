"""Rigorous evaluation harness for the Splunk Incident Copilot.

Runs the SAME agent across every synthetic scenario and reports a real benchmark
table from real runs — no hardcoded numbers. For each scenario it measures:

* recall          — fraction of ground-truth MITRE techniques the agent detected
* precision       — fraction of the agent's MITRE detections that are real
                    (i.e. map to a ground-truth technique; ops-only rules excluded)
* decoy_rejected  — did the agent form the planted decoy hypothesis and then
                    self-correct away from it?
* mitre_coverage  — detected vs expected techniques (e.g. "2/2")
* mttr_steps      — mean-time-to-root-cause, measured as the number of real SPL
                    searches the agent ran up to and including the self-correction
                    (the step at which the true root-cause vector is established)
* blast_radius    — hosts + identities correct vs ground truth

Aggregates are macro-averaged across scenarios. Output: a console table plus a
machine-readable JSON report (``eval/report.json`` by default).

Usage:
    PYTHONPATH=src python3 eval/run_eval.py [--json eval/report.json]
"""

from __future__ import annotations

import argparse
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from splunk_copilot.agent import InvestigationAgent  # noqa: E402

SCENARIOS = [
    "incident-01",
    "incident-02-ransomware",
    "incident-03-insider",
    "incident-04-cloud-ato",
    "incident-05-supplychain",
]


def _mttr_steps(agent: InvestigationAgent) -> int:
    """SPL searches run up to and including the self-correction step.

    This is an honest proxy for mean-time-to-root-cause: the number of real
    searches the agent needed before it locked onto the true attack vector.
    """
    searches = 0
    for step in agent.trace.steps:
        if step["kind"] == "tool_call" and step.get("tool") == "splunk.search":
            searches += 1
        if step["kind"] == "self_correction":
            return searches
    return searches  # no self-correction (shouldn't happen) -> all searches


def eval_scenario(case_id: str) -> dict:
    case_dir = os.path.join(ROOT, "data", "synthetic", case_id)
    agent = InvestigationAgent(case_id=case_id, case_dir=case_dir)
    summary = agent.run()
    acc = summary["accuracy"]
    expected = acc["expected_techniques"]
    detected = len(acc["detected_techniques"])
    total_searches = sum(
        1 for s in agent.trace.steps
        if s["kind"] == "tool_call" and s.get("tool") == "splunk.search")
    return {
        "case_id": case_id,
        "title": summary["title"],
        "attack_class": agent.manifest.get("attack_class", "-"),
        "recall": acc["recall"],
        "precision": acc["precision"],
        "decoy_rejected": acc["decoy_rejected"],
        "expected_techniques": expected,
        "detected_techniques": acc["detected_techniques"],
        "mitre_coverage": f"{len([t for t in acc['matched']])}/{expected}",
        "mttr_steps": _mttr_steps(agent),
        "total_searches": total_searches,
        "blast_radius_hosts_correct": acc["blast_radius_hosts_correct"],
        "blast_radius_identities_correct": acc["blast_radius_identities_correct"],
        "detections": summary["detections"],
        "ledger_records": summary["ledger_records"],
        "trace_steps": summary["trace_steps"],
    }


def aggregate(results: list[dict]) -> dict:
    n = len(results)
    def avg(key):
        return round(sum(r[key] for r in results) / n, 3) if n else 0.0
    all_tech = sorted({t for r in results for t in r["detected_techniques"]})
    return {
        "scenarios": n,
        "macro_recall": avg("recall"),
        "macro_precision": avg("precision"),
        "decoy_rejection_rate": round(
            sum(1 for r in results if r["decoy_rejected"]) / n, 3) if n else 0.0,
        "blast_radius_hosts_accuracy": round(
            sum(1 for r in results if r["blast_radius_hosts_correct"]) / n, 3) if n else 0.0,
        "blast_radius_identities_accuracy": round(
            sum(1 for r in results if r["blast_radius_identities_correct"]) / n, 3) if n else 0.0,
        "mean_mttr_steps": avg("mttr_steps"),
        "distinct_mitre_techniques": all_tech,
        "distinct_mitre_count": len(all_tech),
    }


_C = {"h": "\033[1;36m", "ok": "\033[1;32m", "bad": "\033[1;31m",
      "dim": "\033[2m", "x": "\033[0m"}


def _color() -> bool:
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def c(key, text):
    return f"{_C[key]}{text}{_C['x']}" if _color() else text


def yn(b):
    return c("ok", "yes") if b else c("bad", "NO")


def print_table(results: list[dict], agg: dict) -> None:
    print(c("h", "\n== SPLUNK INCIDENT COPILOT — EVALUATION ACROSS ALL SCENARIOS ==\n"))
    hdr = (f"{'scenario':<26}{'class':<26}{'recall':>7}{'prec':>6}"
           f"{'decoy':>7}{'mitre':>7}{'mttr':>6}{'blast':>7}")
    print(c("dim", hdr))
    print(c("dim", "-" * len(hdr)))
    for r in results:
        blast = "ok" if (r["blast_radius_hosts_correct"]
                         and r["blast_radius_identities_correct"]) else "X"
        print(f"{r['case_id']:<26}{r['attack_class']:<26}"
              f"{r['recall']:>7}{r['precision']:>6}"
              f"{('yes' if r['decoy_rejected'] else 'NO'):>7}"
              f"{r['mitre_coverage']:>7}{r['mttr_steps']:>6}{blast:>7}")
    print(c("dim", "-" * len(hdr)))
    print(f"{'AGGREGATE (macro avg)':<46}"
          f"{agg['macro_recall']:>7}{agg['macro_precision']:>6}"
          f"{int(agg['decoy_rejection_rate']*100):>6}%"
          f"{'':>7}{agg['mean_mttr_steps']:>6}")
    print()
    print(f"  scenarios evaluated        : {agg['scenarios']}")
    print(f"  macro recall / precision   : {agg['macro_recall']} / {agg['macro_precision']}")
    print(f"  decoy rejection rate       : {int(agg['decoy_rejection_rate']*100)}%")
    print(f"  blast-radius host accuracy : {int(agg['blast_radius_hosts_accuracy']*100)}%")
    print(f"  blast-radius id accuracy   : {int(agg['blast_radius_identities_accuracy']*100)}%")
    print(f"  mean MTTR (SPL searches)   : {agg['mean_mttr_steps']}")
    print(f"  distinct MITRE techniques  : {agg['distinct_mitre_count']} "
          f"({', '.join(agg['distinct_mitre_techniques'])})")
    print()


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Evaluate the copilot across scenarios.")
    p.add_argument("--json", default=os.path.join(ROOT, "eval", "report.json"),
                   help="path to write the JSON benchmark report")
    args = p.parse_args(argv)

    results = [eval_scenario(cid) for cid in SCENARIOS]
    agg = aggregate(results)
    print_table(results, agg)

    report = {
        "schema": "splunk_copilot_eval/1.0",
        "synthetic": True,
        "aggregate": agg,
        "scenarios": results,
    }
    os.makedirs(os.path.dirname(args.json), exist_ok=True)
    with open(args.json, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    print(c("ok", f"JSON report written: {args.json}"))

    # non-zero exit if any scenario regresses below a perfect score, so the eval
    # doubles as a CI gate.
    ok = all(r["recall"] == 1.0 and r["precision"] == 1.0 and r["decoy_rejected"]
             for r in results)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
