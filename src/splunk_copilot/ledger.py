"""Append-only evidence ledger conforming to docs/agent_evidence_ledger_schema.json.

Each record is an immutable investigation finding with a provenance chain: every
record's ``evidence_pointer`` (and the structured ``evidence_refs`` carried
alongside) points at concrete synthetic event rows (``<file>:<row>``), each of
which was returned by a real SPL search. Records are never edited or deleted
once appended (append-only audit).
"""

from __future__ import annotations

import datetime as _dt
import json
from dataclasses import dataclass, field
from typing import Any

SEVERITY = {"low", "medium", "high", "critical"}
STATUS = {"new", "triaging", "mitigated", "verified", "closed"}
EVENT_TYPES = {"ingestion", "search", "alert", "triage", "containment", "verification"}


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class EvidenceLedger:
    case_id: str
    owner: str = "splunk_copilot"
    _records: list[dict[str, Any]] = field(default_factory=list)
    _counter: int = 0

    def append(
        self,
        *,
        event_time_utc: str,
        event_type: str,
        source: str,
        summary: str,
        severity: str,
        status: str,
        notes: str,
        evidence_refs: list[str],
        spl: str | None = None,
        iocs: list[str] | None = None,
        recommendation: str | None = None,
        mitre: str | None = None,
        ops_class: str | None = None,
    ) -> dict[str, Any]:
        assert severity in SEVERITY, f"bad severity {severity}"
        assert status in STATUS, f"bad status {status}"
        assert event_type in EVENT_TYPES, f"bad event_type {event_type}"
        assert evidence_refs, "every ledger record must cite >=1 evidence_ref"
        self._counter += 1
        datestamp = "".join(event_time_utc[:10].split("-"))
        evidence_id = f"SPLK-{self.case_id}-{datestamp}-{self._counter:03d}"
        rec: dict[str, Any] = {
            "evidence_id": evidence_id,
            "case_id": self.case_id,
            "event_time_utc": event_time_utc,
            "event_type": event_type,
            "source": source,
            "summary": summary,
            "severity": severity,
            "owner": self.owner,
            "status": status,
            "notes": notes,
            "iocs": iocs or [],
            "recommendation": recommendation or "",
            "evidence_pointer": "; ".join(evidence_refs),
            "evidence_refs": list(evidence_refs),
        }
        if spl:
            rec["spl"] = spl
        if mitre:
            rec["mitre_attack"] = mitre
        if ops_class:
            rec["ops_class"] = ops_class
        self._records.append(rec)
        return rec

    @property
    def records(self) -> list[dict[str, Any]]:
        return list(self._records)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "splunk_copilot_evidence_ledger/1.0",
            "case_id": self.case_id,
            "generated_utc": _now(),
            "synthetic": True,
            "record_count": len(self._records),
            "records": self._records,
        }

    def write(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh, indent=2, ensure_ascii=False)
