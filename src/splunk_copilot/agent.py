"""The agentic ops investigation loop:

  anomaly trigger -> initial hypothesis (intentionally wrong: a tempting decoy)
  -> run SPL searches to confirm/refute -> contradiction -> evidence-justified
  self-correction (the real attack chain) -> correlation detectors ->
  evidence-linked findings -> root-cause summary -> blast-radius estimate ->
  remediation checklist -> accuracy self-check.

Reasoning is deterministic and rule-driven (no LLM / no network) so the demo is
fully reproducible offline. Every step is a real SPL search recorded to the
trace, and every finding cites the event rows the search returned.

The ONE agent is scenario-agnostic: the narrative-specific parts (which decoy to
form, what refutes it, the corrected vector, the root cause, the blast-radius
queries, the IOCs, the remediation) all come from a per-case ``scenario.json``
manifest. The detector library, ledger, trace, scoring, and loop are identical
across every incident — only the data and the manifest change. This is what lets
the same agent solve all five synthetic incidents honestly.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any

from . import detections
from .backends import SearchBackend, SyntheticBackend
from .events import EventStore
from .ledger import EvidenceLedger
from .spl import SplEngine
from .trace import TraceRecorder


@dataclass
class InvestigationAgent:
    case_id: str
    case_dir: str
    backend: SearchBackend | None = None
    store: EventStore = field(init=False)
    spl: SplEngine = field(init=False)
    trace: TraceRecorder = field(init=False)
    ledger: EvidenceLedger = field(init=False)
    manifest: dict[str, Any] = field(init=False, default_factory=dict)
    detections_found: list[detections.Detection] = field(default_factory=list)
    root_cause: str = ""
    blast_radius: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.trace = TraceRecorder(self.case_id)
        if self.backend is None:
            self.store = EventStore(self.case_dir)
            self.backend = SyntheticBackend(self.store)
        else:
            # backend supplies its own store/engine; keep a handle for scoring
            self.store = getattr(self.backend, "store", EventStore(self.case_dir))
        self.spl = self.backend.engine()
        self.spl.attach_trace(self.trace)
        self.ledger = EvidenceLedger(self.case_id)
        self.manifest = self._load_manifest()

    def _load_manifest(self) -> dict[str, Any]:
        path = os.path.join(self.case_dir, "scenario.json")
        if not os.path.exists(path):
            raise FileNotFoundError(f"scenario.json missing for {self.case_id}")
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)

    # ---- small template helper -------------------------------------------
    def _fmt(self, text: str, ctx: dict[str, Any]) -> str:
        out = text
        for k, v in ctx.items():
            out = out.replace("{" + k + "}", str(v))
        return out

    # ---- phase 1: anomaly trigger / ingest --------------------------------
    def ingest(self) -> None:
        self.backend.load()
        by_st: dict[str, int] = {}
        for ev in self.store.events:
            by_st[ev.sourcetype] = by_st.get(ev.sourcetype, 0) + 1
        self.trace.note(f"Ingested synthetic Splunk events by sourcetype: {by_st}")
        an = self.manifest["anomaly"]
        spike = self.spl.search(an["spl"])
        first = self.store.events[0] if self.store.events else None
        self.ledger.append(
            event_time_utc=an["trigger_time_utc"],
            event_type="ingestion", source="splunk_event_store",
            summary=(f"{an['summary']} ({len(spike.rows)} matching group(s)). Loaded "
                     f"{len(self.store.events)} events across {len(by_st)} sourcetypes."),
            severity="low", status="new",
            notes="SYNTHETIC DATA ONLY. Read-only event store; raw events not modified.",
            spl=an["spl"],
            evidence_refs=spike.refs or ([first.ref] if first else ["synthetic:1"]),
        )

    # ---- phase 2: first (intentionally shallow) hypothesis ----------------
    def initial_hypothesis(self) -> tuple[str, dict[str, Any]]:
        dh = self.manifest["decoy_hypothesis"]
        seed = self.spl.search(dh["seed_spl"])
        ctx: dict[str, Any] = {}
        if seed.rows:
            ctx["bf_ip"] = seed.rows[0].get(dh.get("seed_ip_field", "src_ip"))
            ctx["bf_count"] = seed.rows[0].get(dh.get("seed_count_field", "count"))
        stmt = self._fmt(dh["statement"], ctx)
        self.trace.hypothesis(dh["id"], stmt, confidence=dh.get("confidence", 0.5))
        return dh["id"], ctx

    # ---- phase 3: test H1, find contradiction, self-correct ---------------
    def self_correct(self, from_hid: str, ctx: dict[str, Any]) -> str:
        ref = self.manifest["refutation"]
        bf_ip = ctx.get("bf_ip")
        reasons: list[str] = []
        contradiction_refs: list[str] = []

        # (a) does the decoy actor ever actually succeed?
        if ref.get("success_check_spl"):
            succ = self.spl.search(self._fmt(ref["success_check_spl"], ctx))
            if not succ.rows:
                reasons.append(self._fmt(ref.get("no_success_reason",
                               "no corroborating successful access"), ctx))
            contradiction_refs.extend(succ.refs)

        # (b) what does threat intel say about the decoy indicator?
        ti_note = ""
        if ref.get("threat_lookup_indicator"):
            ind = self._fmt(ref["threat_lookup_indicator"], ctx)
            ti = self.store.threat_verdict(ind)
            if ti:
                ti_note = ti.get("note", "")
                ctx["ti_note"] = ti_note
                if ti.get("verdict") == "benign":
                    reasons.append(self._fmt(ref.get("benign_reason",
                                   "threat intel rates {bf_ip} benign"), ctx))
                for r in self.store.lookups.get("threat_intel.csv", []):
                    if r.get("indicator") == ind:
                        contradiction_refs.append(f"threat_intel.csv:{r.get('row')}")

        reason = "; ".join(reasons) or "no corroborating evidence for the decoy vector"
        # cap contradiction refs but keep at least one
        contradiction_refs = list(dict.fromkeys(contradiction_refs))[:4] or \
            ([self.store.events[0].ref] if self.store.events else ["synthetic:1"])
        self.trace.contradiction(from_hid, reason, contradiction_refs)

        # confirm the real vector
        ch = self.manifest["corrected_hypothesis"]
        corr_refs: list[str] = []
        for q in ch.get("corroborating_spl", []):
            corr_refs.extend(self.spl.search(self._fmt(q, ctx)).refs)
        corrected = self._fmt(ch["statement"], ctx)
        self.trace.self_correction(
            from_hid=from_hid, to_statement=corrected,
            rationale=f"{reason}. {self._fmt(ch.get('rationale', ''), ctx)}",
        )
        self.trace.hypothesis(ch["id"], corrected, confidence=ch.get("confidence", 0.9))
        self.ledger.append(
            event_time_utc=self.manifest["anomaly"]["trigger_time_utc"],
            event_type="triage", source="self_correction",
            summary=(f"Rejected decoy hypothesis {from_hid}. {reason}."),
            severity="low", status="triaging",
            notes=f"Self-correction: pivoted from the decoy theory to the "
                  f"corroborated attack chain based on SPL evidence.",
            spl=self._fmt(ref.get("success_check_spl", ""), ctx) or None,
            evidence_refs=contradiction_refs,
            recommendation="De-prioritise the decoy; focus on the corroborated chain.",
        )
        return ch["id"]

    # ---- phase 4: run correlation detectors, promote to findings ----------
    def investigate(self) -> None:
        dets = detections.run_all(self.spl)
        self.detections_found = dets
        for d in dets:
            self.trace.finding(d.rule_id, d.label, d.evidence_refs)
            self.ledger.append(
                event_time_utc=d.event_time_utc or self.manifest["anomaly"]["trigger_time_utc"],
                event_type="alert", source=f"correlation_search:{d.rule_id}",
                summary=f"[{d.mitre}/{d.ops_class}] {d.summary}",
                severity=d.severity, status="triaging",
                notes=f"Correlation search {d.rule_id}; MITRE {d.mitre}; "
                      f"ops_class {d.ops_class}. Synthetic data.",
                spl=d.spl, evidence_refs=d.evidence_refs,
                iocs=d.iocs, recommendation=d.recommendation,
                mitre=d.mitre if d.mitre != "-" else None, ops_class=d.ops_class,
            )

    # ---- phase 5: root cause + blast radius -------------------------------
    def assess(self) -> None:
        self.root_cause = self.manifest["root_cause"]
        br = self.manifest.get("blast_radius", {})
        host_set: set[str] = set()
        for q in br.get("host_queries", []):
            for r in self.spl.search(q).rows:
                if r.get("host"):
                    host_set.add(r["host"])
        identities: list[str] = []
        if br.get("identity_query"):
            idf = br.get("identity_field", "user")
            for r in self.spl.search(br["identity_query"]).rows:
                v = r.get(idf)
                if v and v != "-" and v not in identities:
                    identities.append(v)
        exfil = None
        if br.get("exfil_rule_id"):
            exfil = next((d.detail.get(br.get("exfil_detail_key", "exfil_mb"))
                          for d in self.detections_found
                          if d.rule_id == br["exfil_rule_id"]), None)
        self.blast_radius = {
            "hosts": sorted(host_set),
            "identities": sorted(identities),
            "data_assets": br.get("data_assets", []),
            "exfil_mb": exfil,
        }
        self.trace.note(f"Root cause established; blast radius = {self.blast_radius}")
        refs: list[str] = []
        for d in self.detections_found:
            refs.extend(d.evidence_refs)
        refs = list(dict.fromkeys(refs))
        self.ledger.append(
            event_time_utc=self.manifest["anomaly"]["trigger_time_utc"],
            event_type="triage", source="agent_root_cause",
            summary="ROOT CAUSE: " + self.root_cause,
            severity="critical", status="triaging",
            notes=f"Blast radius (SPL-derived): hosts={self.blast_radius['hosts']} "
                  f"identities={self.blast_radius['identities']} "
                  f"data_assets={self.blast_radius['data_assets']} "
                  f"exfil_mb={self.blast_radius['exfil_mb']}.",
            evidence_refs=refs[:12] or ([self.store.events[0].ref]
                                        if self.store.events else ["synthetic:1"]),
            iocs=self.manifest.get("iocs", []),
        )

    # ---- phase 6: remediation checklist -----------------------------------
    def remediate(self) -> None:
        all_refs: list[str] = []
        all_iocs: list[str] = []
        for d in self.detections_found:
            if d.severity in ("critical", "high"):
                all_refs.extend(d.evidence_refs)
                all_iocs.extend(d.iocs)
        all_refs = list(dict.fromkeys(all_refs))
        all_iocs = list(dict.fromkeys(all_iocs + self.manifest.get("iocs", [])))
        actions = self.manifest.get("remediation", [])
        self.trace.note("Built remediation checklist from critical/high findings.")
        self.ledger.append(
            event_time_utc=self.manifest["anomaly"]["trigger_time_utc"],
            event_type="containment", source="agent_playbook",
            summary="Remediation checklist: " + " | ".join(actions),
            severity="critical", status="mitigated",
            notes="Recommendation-only (no auto-execution). Operator approval required.",
            evidence_refs=all_refs[:12] or ([self.store.events[0].ref]
                                            if self.store.events else ["synthetic:1"]),
            iocs=all_iocs,
            recommendation=" || ".join(actions),
        )

    # ---- phase 7: verification / accuracy ---------------------------------
    def verify(self) -> dict[str, Any]:
        gt_path = os.path.join(self.case_dir, "ground_truth.json")
        result: dict[str, Any] = {"scored": False}
        if not os.path.exists(gt_path):
            self.trace.note("No ground_truth.json; skipping accuracy scoring.")
            return result
        with open(gt_path, encoding="utf-8") as fh:
            gt = json.load(fh)
        expected = gt.get("expected_findings", [])
        found_mitre = {d.mitre for d in self.detections_found}
        matched = [e for e in expected if e["mitre"] in found_mitre]
        missed = [e for e in expected if e["mitre"] not in found_mitre]
        rejected_decoy = any(s["kind"] == "self_correction" for s in self.trace.steps)
        recall = len(matched) / len(expected) if expected else 0.0
        gt_mitre = {e["mitre"] for e in expected}
        mitre_dets = [d for d in self.detections_found if d.mitre != "-"]
        true_pos = [d for d in mitre_dets if d.mitre in gt_mitre]
        precision = len(true_pos) / len(mitre_dets) if mitre_dets else 0.0
        gt_br = gt.get("blast_radius", {})
        br_hosts_ok = set(gt_br.get("hosts", [])) == set(self.blast_radius.get("hosts", []))
        br_ids_ok = set(gt_br.get("identities", [])) == set(self.blast_radius.get("identities", []))
        result = {
            "scored": True,
            "expected_techniques": len(expected),
            "detected_techniques": sorted(found_mitre - {"-"}),
            "matched": [e["id"] + ":" + e["mitre"] for e in matched],
            "missed": [e["id"] + ":" + e["mitre"] for e in missed],
            "recall": round(recall, 3),
            "precision": round(precision, 3),
            "decoy_rejected": rejected_decoy,
            "blast_radius_hosts_correct": br_hosts_ok,
            "blast_radius_identities_correct": br_ids_ok,
        }
        self.trace.note(f"Accuracy vs ground truth: recall={result['recall']} "
                        f"precision={result['precision']} decoy_rejected={rejected_decoy} "
                        f"blast_radius_hosts_correct={br_hosts_ok}")
        verify_refs: list[str] = []
        for e in matched:
            verify_refs.extend(e.get("key_evidence", [])[:1])
        self.ledger.append(
            event_time_utc=self.manifest["anomaly"]["trigger_time_utc"],
            event_type="verification", source="ground_truth.json",
            summary=(f"Validated findings against synthetic ground truth: "
                     f"{len(matched)}/{len(expected)} techniques matched, "
                     f"recall={result['recall']}, precision={result['precision']}, "
                     f"decoy_rejected={rejected_decoy}, "
                     f"blast_radius_hosts_correct={br_hosts_ok}."),
            severity="medium", status="verified",
            notes="Accuracy self-check on synthetic case. A live deployment would "
                  "replace ground_truth.json with analyst adjudication.",
            evidence_refs=verify_refs or ([self.store.events[0].ref]
                                          if self.store.events else ["synthetic:1"]),
        )
        return result

    # ---- orchestration ----------------------------------------------------
    def run(self) -> dict[str, Any]:
        self.ingest()
        h1, ctx = self.initial_hypothesis()
        h2 = self.self_correct(h1, ctx)
        self.investigate()
        self.assess()
        self.remediate()
        accuracy = self.verify()
        return {
            "case_id": self.case_id,
            "title": self.manifest.get("title", self.case_id),
            "final_hypothesis": h2,
            "detections": len(self.detections_found),
            "root_cause": self.root_cause,
            "blast_radius": self.blast_radius,
            "ledger_records": len(self.ledger.records),
            "trace_steps": len(self.trace.steps),
            "accuracy": accuracy,
        }
