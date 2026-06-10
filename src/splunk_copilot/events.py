"""Read-only loader for synthetic Splunk-style events.

Every event gets a stable, immutable provenance ref of the form
``<source_file>:<row>`` (e.g. ``web_access.jsonl:15``). Findings cite these
refs so any claim traces back to a specific line of a specific synthetic
sourcetype — the provenance chain the judges care about. Each event also keeps
its Splunk ``index`` and ``sourcetype`` so real SPL ``index=`` / ``sourcetype=``
filters operate over it.

The loader is deliberately a "tool": typed, read-only, never mutates events.
"""

from __future__ import annotations

import csv
import json
import os
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Event:
    """One immutable Splunk-style event with a stable provenance ref."""

    ref: str  # "<source_file>:<row>"
    source_file: str  # filename within the case dir
    row: int
    index: str
    sourcetype: str
    data: dict[str, Any]

    def get(self, key: str, default: Any = None) -> Any:
        return self.data.get(key, default)


# Every ``*.jsonl`` in a case dir is a Splunk event stream; every ``*.csv`` is a
# lookup table (e.g. threat intel). The loader auto-discovers them so adding a
# new sourcetype to a scenario is just dropping in a new .jsonl — no code change.
# ``ground_truth.json`` / ``scenario.json`` are manifests, not events.
_NON_DATA_JSON = {"ground_truth.json", "scenario.json"}


@dataclass
class EventStore:
    """Loads + indexes all synthetic events and lookups for a case (read-only)."""

    case_dir: str
    events: list[Event] = field(default_factory=list)
    lookups: dict[str, list[dict[str, Any]]] = field(default_factory=dict)

    def load(self) -> None:
        names = sorted(os.listdir(self.case_dir)) if os.path.isdir(self.case_dir) else []
        for fname in names:
            if not fname.endswith(".jsonl"):
                continue
            path = os.path.join(self.case_dir, fname)
            with open(path, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    obj = json.loads(line)
                    row = int(obj["row"])
                    self.events.append(
                        Event(
                            ref=f"{fname}:{row}",
                            source_file=fname,
                            row=row,
                            index=str(obj.get("index", "")),
                            sourcetype=str(obj.get("sourcetype", "")),
                            data=obj,
                        )
                    )
        # stable global ordering by _time keeps streamstats/transaction sane
        self.events.sort(key=lambda e: (float(e.get("_time", 0) or 0), e.source_file, e.row))
        for fname in names:
            if not fname.endswith(".csv"):
                continue
            path = os.path.join(self.case_dir, fname)
            with open(path, encoding="utf-8", newline="") as fh:
                self.lookups[fname] = [dict(r) for r in csv.DictReader(fh)]
        self.lookups.setdefault("threat_intel.csv", [])

    # ---- typed read-only lookup "tool" ------------------------------------

    def threat_verdict(self, indicator: str) -> dict[str, Any] | None:
        """Look up an indicator in the offline threat-intel lookup."""
        for r in self.lookups.get("threat_intel.csv", []):
            if r.get("indicator") == indicator:
                return r
        return None

    def by_ref(self, ref: str) -> Event | None:
        for e in self.events:
            if e.ref == ref:
                return e
        return None
