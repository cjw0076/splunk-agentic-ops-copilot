"""Append-only execution trace for replayable, auditable agent runs.

Records every SPL search, hypothesis, contradiction, self-correction, and
finding with a monotonic step index and timestamp. Writing it out gives a
"replay the agent's reasoning" artifact: which SPL it ran, what it found, where
it was wrong, and how it corrected.
"""

from __future__ import annotations

import datetime as _dt
import json
from dataclasses import dataclass, field
from typing import Any


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class TraceRecorder:
    case_id: str
    steps: list[dict[str, Any]] = field(default_factory=list)
    _seq: int = 0

    def _emit(self, kind: str, payload: dict[str, Any]) -> dict[str, Any]:
        self._seq += 1
        entry = {"step": self._seq, "ts_wall_utc": _now(), "kind": kind, **payload}
        self.steps.append(entry)
        return entry

    def tool_call(self, tool: str, args: dict[str, Any], result_refs: list[str]) -> None:
        self._emit(
            "tool_call",
            {"tool": tool, "args": args, "result_count": len(result_refs),
             "result_refs": result_refs},
        )

    def hypothesis(self, hid: str, statement: str, confidence: float) -> None:
        self._emit("hypothesis", {"hypothesis_id": hid, "statement": statement,
                                  "confidence": round(confidence, 3)})

    def contradiction(self, hid: str, reason: str, evidence_refs: list[str]) -> None:
        self._emit("contradiction", {"hypothesis_id": hid, "reason": reason,
                                     "evidence_refs": evidence_refs})

    def self_correction(self, from_hid: str, to_statement: str, rationale: str) -> None:
        self._emit("self_correction", {"from_hypothesis": from_hid,
                                       "to_statement": to_statement,
                                       "rationale": rationale})

    def finding(self, evidence_id: str, label: str, evidence_refs: list[str]) -> None:
        self._emit("finding", {"evidence_id": evidence_id, "label": label,
                               "evidence_refs": evidence_refs})

    def note(self, text: str) -> None:
        self._emit("note", {"text": text})

    def to_dict(self) -> dict[str, Any]:
        return {"case_id": self.case_id, "total_steps": len(self.steps),
                "steps": self.steps}

    def write(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh, indent=2, ensure_ascii=False)
