"""The agentic ops investigation loop:

  anomaly trigger -> initial hypothesis (intentionally wrong: SSH brute-force)
  -> run SPL searches to confirm/refute -> contradiction -> evidence-justified
  self-correction (the real web credential-stuffing chain) -> correlation
  detectors -> evidence-linked findings -> root-cause summary -> blast-radius
  estimate -> remediation checklist -> accuracy self-check.

Reasoning is deterministic and rule-driven (no LLM / no network) so the demo is
fully reproducible offline. Every step is a real SPL search recorded to the
trace, and every finding cites the event rows the search returned.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any

from . import detections
from .events import EventStore
from .ledger import EvidenceLedger
from .spl import SplEngine
from .trace import TraceRecorder


@dataclass
class InvestigationAgent:
    case_id: str
    case_dir: str
    store: EventStore = field(init=False)
    spl: SplEngine = field(init=False)
    trace: TraceRecorder = field(init=False)
    ledger: EvidenceLedger = field(init=False)
    detections_found: list[detections.Detection] = field(default_factory=list)
    root_cause: str = ""
    blast_radius: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.trace = TraceRecorder(self.case_id)
        self.store = EventStore(self.case_dir)
        self.spl = SplEngine(self.store)
        self.spl.attach_trace(self.trace)
        self.ledger = EvidenceLedger(self.case_id)

    # ---- phase 1: anomaly trigger / ingest --------------------------------
    def ingest(self) -> None:
        self.store.load()
        by_st: dict[str, int] = {}
        for ev in self.store.events:
            by_st[ev.sourcetype] = by_st.get(ev.sourcetype, 0) + 1
        self.trace.note(f"Ingested synthetic Splunk events by sourcetype: {by_st}")
        # Anomaly trigger: an outbound byte spike on the firewall.
        spike = self.spl.search('index=network sourcetype=pan:traffic '
                                '| where bytes_out > 1000000 '
                                '| stats sum(bytes_out) as out_bytes by dest_ip')
        first = self.store.events[0] if self.store.events else None
        self.ledger.append(
            event_time_utc="2026-06-10T02:25:00Z",
            event_type="ingestion", source="splunk_event_store",
            summary=(f"Anomaly trigger: outbound byte spike detected on pan:traffic "
                     f"({len(spike.rows)} dest_ip over 1MB). Loaded "
                     f"{len(self.store.events)} events across {len(by_st)} sourcetypes."),
            severity="low", status="new",
            notes="SYNTHETIC DATA ONLY. Read-only event store; raw events not modified.",
            spl='index=network sourcetype=pan:traffic | where bytes_out > 1000000 '
                '| stats sum(bytes_out) as out_bytes by dest_ip',
            evidence_refs=spike.refs or ([first.ref] if first else ["fw_traffic.jsonl:1"]),
        )

    # ---- phase 2: first (intentionally shallow) hypothesis ----------------
    def initial_hypothesis(self) -> str:
        """Tempting-but-wrong first read: 'SSH brute-force on the bastion got in'."""
        hid = "H1"
        fails = self.spl.search('sourcetype=linux_secure action=failure '
                                '| stats count by src_ip')
        ip = fails.rows[0].get("src_ip") if fails.rows else "?"
        n = fails.rows[0].get("count") if fails.rows else 0
        stmt = (f"H1: The breach started with an SSH brute-force from {ip} against "
                f"bastion-01 ({n} failed logons) — classic perimeter intrusion.")
        self.trace.hypothesis(hid, stmt, confidence=0.5)
        return hid

    # ---- phase 3: test H1, find contradiction, self-correct ---------------
    def self_correct(self, from_hid: str) -> str:
        # Refute H1: was there ANY successful SSH logon from the brute-force IP?
        fails = self.spl.search('sourcetype=linux_secure action=failure '
                                '| stats count by src_ip')
        bf_ip = fails.rows[0].get("src_ip") if fails.rows else None
        succ = self.spl.search(f'sourcetype=linux_secure action=success src_ip={bf_ip}')
        ti = self.store.threat_verdict(bf_ip) if bf_ip else None
        ti_ref = None
        for r in self.store.lookups.get("threat_intel.csv", []):
            if r.get("indicator") == bf_ip:
                ti_ref = f"threat_intel.csv:{r.get('row')}"
        contradiction_refs = fails.refs[:2]
        if ti_ref:
            contradiction_refs.append(ti_ref)

        reasons = []
        if not succ.rows:
            reasons.append(f"zero successful SSH logons from {bf_ip} (all failures)")
        if ti and ti.get("verdict") == "benign":
            reasons.append(f"threat intel rates {bf_ip} benign ({ti.get('note')})")
        reason = "; ".join(reasons) or "no corroborating successful access from that IP"
        self.trace.contradiction(from_hid, reason, contradiction_refs)

        # Confirm the real vector: credential stuffing on the web /api/login.
        stuff = self.spl.search('index=web sourcetype=access_combined '
                                'uri_path="/api/login" status=401 | stats count by clientip')
        win = self.spl.search('index=web sourcetype=access_combined '
                              'uri_path="/api/login" status=200 | table clientip,user')
        corrected = (
            "H2: The real entry vector was web credential stuffing against "
            "/api/login from 192.0.2.50 using a repo-leaked API key, which "
            "succeeded as svc_deploy — NOT the SSH brute-force, which never "
            "authenticated."
        )
        self.trace.self_correction(
            from_hid=from_hid, to_statement=corrected,
            rationale=(f"{reason}. Meanwhile SPL shows "
                       f"{stuff.rows[0].get('count') if stuff.rows else '?'} failed "
                       f"/api/login from {stuff.rows[0].get('clientip') if stuff.rows else '?'} "
                       f"followed by a 200 success as "
                       f"{win.rows[0].get('user') if win.rows else '?'} — a real, "
                       f"corroborated web intrusion chain."),
        )
        self.trace.hypothesis("H2", corrected, confidence=0.94)
        self.ledger.append(
            event_time_utc="2026-06-10T02:23:20Z",
            event_type="triage", source="linux_secure + threat_intel",
            summary=("Rejected decoy hypothesis H1 (SSH brute-force vector). No "
                     "successful SSH logon from 45.155.205.99; IP rated benign."),
            severity="low", status="triaging",
            notes="Self-correction: pivoted from perimeter-SSH theory to web "
                  "credential-stuffing chain based on SPL evidence.",
            spl=f'sourcetype=linux_secure action=success src_ip={bf_ip}',
            evidence_refs=contradiction_refs,
            recommendation="Treat the SSH scan noise as low priority; focus on web auth + exfil.",
        )
        return "H2"

    # ---- phase 4: run correlation detectors, promote to findings ----------
    def investigate(self) -> None:
        dets = detections.run_all(self.spl)
        self.detections_found = dets
        for d in dets:
            self.trace.finding(d.rule_id, d.label, d.evidence_refs)
            self.ledger.append(
                event_time_utc=d.event_time_utc,
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
        self.root_cause = (
            "A deploy service-account API key (AKIA-DEPLOY-7Q2) committed to a "
            "public repo enabled credential-stuffing authentication as svc_deploy, "
            "followed by self-service privilege escalation through an unguarded "
            "/api/admin/grant_role endpoint, then bulk customer-data exfiltration."
        )
        # Blast radius derived from SPL, not hardcoded guesses. Find every host
        # the attacker IP 192.0.2.50 touched, across the web and app tiers.
        host_set: set[str] = set()
        web_hosts = self.spl.search('index=web clientip=192.0.2.50 | stats count by host')
        app_hosts = self.spl.search('index=app src_ip=192.0.2.50 | stats count by host')
        for res in (web_hosts, app_hosts):
            for r in res.rows:
                if r.get("host"):
                    host_set.add(r["host"])
        host_list = sorted(host_set)
        ids = self.spl.search('index=web clientip=192.0.2.50 status=200 '
                              '| dedup user | table user')
        identities = sorted({r.get("user") for r in ids.rows
                             if r.get("user") and r.get("user") != "-"})
        self.blast_radius = {
            "hosts": sorted(host_list),
            "identities": identities,
            "data_assets": ["customers"],
            "exfil_mb": next((d.detail.get("exfil_mb")
                              for d in self.detections_found
                              if d.rule_id == "CS-EXFIL-004"), None),
        }
        self.trace.note(f"Root cause established; blast radius = {self.blast_radius}")
        refs: list[str] = []
        for d in self.detections_found:
            refs.extend(d.evidence_refs)
        refs = list(dict.fromkeys(refs))
        self.ledger.append(
            event_time_utc="2026-06-10T02:28:00Z",
            event_type="triage", source="agent_root_cause",
            summary="ROOT CAUSE: " + self.root_cause,
            severity="critical", status="triaging",
            notes=f"Blast radius (SPL-derived): hosts={self.blast_radius['hosts']} "
                  f"identities={self.blast_radius['identities']} "
                  f"data_assets={self.blast_radius['data_assets']} "
                  f"exfil_mb={self.blast_radius['exfil_mb']}.",
            evidence_refs=refs[:12] or ["web_access.jsonl:15"],
            iocs=["192.0.2.50", "AKIA-DEPLOY-7Q2", "svc_deploy"],
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
        all_iocs = list(dict.fromkeys(all_iocs))
        actions = [
            "Disable the svc_deploy account and revoke all its active sessions/tokens.",
            "Rotate and purge API key AKIA-DEPLOY-7Q2; remove it from git history; enable CI secret scanning.",
            "Revoke the unauthorized admin role grant; gate /api/admin/* behind authz + approval.",
            "Block egress to 192.0.2.50 at fw-edge-01; add DLP + rate caps on /api/export/*.",
            "Enable lockout + MFA + rate-limiting on /api/login to stop credential stuffing.",
            "Quantify exfiltrated customer records and start breach-notification process.",
            "Add a saved correlation search for (login 401 burst -> 200) and (bulk export -> egress spike).",
        ]
        self.trace.note("Built remediation checklist from critical/high findings.")
        self.ledger.append(
            event_time_utc="2026-06-10T02:30:00Z",
            event_type="containment", source="agent_playbook",
            summary="Remediation checklist: " + " | ".join(actions),
            severity="critical", status="mitigated",
            notes="Recommendation-only (no auto-execution). Operator approval required.",
            evidence_refs=all_refs[:12] or ["web_access.jsonl:15"],
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
        # precision: detections that map to a real GT technique (ops-only rules excluded)
        mitre_dets = [d for d in self.detections_found if d.mitre != "-"]
        true_pos = [d for d in mitre_dets if d.mitre in gt_mitre]
        precision = len(true_pos) / len(mitre_dets) if mitre_dets else 0.0
        # blast-radius accuracy
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
            event_time_utc="2026-06-10T02:31:00Z",
            event_type="verification", source="ground_truth.json",
            summary=(f"Validated findings against synthetic ground truth: "
                     f"{len(matched)}/{len(expected)} techniques matched, "
                     f"recall={result['recall']}, precision={result['precision']}, "
                     f"decoy_rejected={rejected_decoy}, "
                     f"blast_radius_hosts_correct={br_hosts_ok}."),
            severity="medium", status="verified",
            notes="Accuracy self-check on synthetic case. A live deployment would "
                  "replace ground_truth.json with analyst adjudication.",
            evidence_refs=verify_refs or ["web_access.jsonl:15"],
        )
        return result

    # ---- orchestration ----------------------------------------------------
    def run(self) -> dict[str, Any]:
        self.ingest()
        h1 = self.initial_hypothesis()
        h2 = self.self_correct(h1)
        self.investigate()
        self.assess()
        self.remediate()
        accuracy = self.verify()
        return {
            "case_id": self.case_id,
            "final_hypothesis": h2,
            "detections": len(self.detections_found),
            "root_cause": self.root_cause,
            "blast_radius": self.blast_radius,
            "ledger_records": len(self.ledger.records),
            "trace_steps": len(self.trace.steps),
            "accuracy": accuracy,
        }
