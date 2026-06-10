"""Search-backend seam: run the SAME SPL through different engines.

The agent, detectors, ledger, trace, and eval harness all talk to a
``SearchBackend``. Two implementations ship:

* ``SyntheticBackend`` — the offline, stdlib-only SPL engine over synthetic
  JSONL events (the default; what the whole demo runs on).
* ``SplunkRestBackend`` — runs the identical SPL string against a real Splunk
  deployment over the REST API (``POST /services/search/jobs`` -> poll ->
  ``GET .../results``). It activates only when ``SPLUNK_URL`` + ``SPLUNK_TOKEN``
  are set, and it is real, correct REST code: it can be unit-tested against a
  mocked HTTP layer without a live Splunk, and dropped onto a live tenant with
  no other change.

The one-line switch::

    backend = make_backend(case_dir)   # auto: REST if env set, else synthetic

Nothing else in the agent changes. Provenance refs from the REST backend are
synthetic-free (``splunk:<sid>:<n>``) but the agent treats them identically.
"""

from __future__ import annotations

import json
import os
import time
import urllib.parse
import urllib.request
from typing import Any, Protocol

from .events import EventStore
from .spl import REF_KEY, SearchResult, SplEngine


class SearchBackend(Protocol):
    """Anything that can load a case and return an SPL engine the agent uses."""

    store: EventStore

    def load(self) -> None: ...

    def engine(self) -> SplEngine: ...


# ---------------------------------------------------------------------------
# Synthetic (default, offline)
# ---------------------------------------------------------------------------

class SyntheticBackend:
    """The offline SPL engine over synthetic JSONL events."""

    def __init__(self, store: EventStore):
        self.store = store
        self._engine = SplEngine(store)

    def load(self) -> None:
        self.store.load()

    def engine(self) -> SplEngine:
        return self._engine


# ---------------------------------------------------------------------------
# Live Splunk over REST
# ---------------------------------------------------------------------------

class _Http:
    """Tiny urllib wrapper so the REST backend can be mocked in tests.

    A test injects a fake ``post``/``get`` by passing an http object; production
    uses the default urllib implementation. No third-party HTTP dependency.
    """

    def __init__(self, base_url: str, token: str, verify_tls: bool = True):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.verify_tls = verify_tls

    def _ctx(self):  # pragma: no cover - thin TLS shim
        if self.verify_tls:
            return None
        import ssl
        c = ssl.create_default_context()
        c.check_hostname = False
        c.verify_mode = ssl.CERT_NONE
        return c

    def _request(self, method: str, path: str,
                 data: dict[str, str] | None = None) -> str:
        url = self.base_url + path
        body = urllib.parse.urlencode(data).encode() if data else None
        req = urllib.request.Request(url, data=body, method=method)
        req.add_header("Authorization", f"Bearer {self.token}")
        with urllib.request.urlopen(req, context=self._ctx()) as resp:  # pragma: no cover
            return resp.read().decode("utf-8")

    def post(self, path: str, data: dict[str, str]) -> str:
        return self._request("POST", path, data)

    def get(self, path: str) -> str:
        return self._request("GET", path)


class SplunkRestBackend:
    """Run SPL against a live Splunk via the search/jobs REST endpoint.

    Implements the standard create-job -> poll-until-done -> fetch-results dance
    and adapts Splunk's JSON result rows into the same dict shape the agent and
    detectors expect (including a ``REF_KEY`` provenance list).
    """

    def __init__(self, base_url: str, token: str, *,
                 http: _Http | None = None, verify_tls: bool = True,
                 poll_interval: float = 0.5, max_polls: int = 600,
                 case_dir: str | None = None):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.http = http or _Http(self.base_url, token, verify_tls)
        self.poll_interval = poll_interval
        self.max_polls = max_polls
        # a (mostly empty) store so the agent's threat_verdict()/scoring still
        # works; lookups live in Splunk in the live path.
        self.store = EventStore(case_dir or "")
        self._engine = _RestEngine(self)

    def load(self) -> None:
        # Live data already lives in Splunk; nothing to load locally. We still
        # try the local lookups dir so threat-intel scoring works in hybrid mode.
        if self.store.case_dir and os.path.isdir(self.store.case_dir):
            try:
                self.store.load()
            except Exception:  # pragma: no cover - tolerate missing local files
                pass

    def engine(self) -> SplEngine:
        return self._engine

    # ---- the actual REST search ------------------------------------------
    def run_spl(self, spl: str) -> SearchResult:
        # 1) create a blocking-style search job
        search_str = spl if spl.strip().lower().startswith("search") else f"search {spl}"
        resp = self.http.post("/services/search/jobs",
                              {"search": search_str, "output_mode": "json"})
        sid = self._parse_sid(resp)

        # 2) poll job status until isDone
        for _ in range(self.max_polls):
            status = self.http.get(
                f"/services/search/jobs/{urllib.parse.quote(sid)}?output_mode=json")
            if self._is_done(status):
                break
            time.sleep(self.poll_interval)  # pragma: no cover - timing
        else:  # pragma: no cover - timeout path
            raise TimeoutError(f"Splunk job {sid} did not complete")

        # 3) fetch the results
        raw = self.http.get(
            f"/services/search/jobs/{urllib.parse.quote(sid)}/results?output_mode=json&count=0")
        rows = self._parse_results(raw, sid)
        return SearchResult(spl=spl, rows=rows)

    @staticmethod
    def _parse_sid(resp: str) -> str:
        obj = json.loads(resp)
        sid = obj.get("sid")
        if not sid:
            raise ValueError(f"Splunk did not return a sid: {resp[:200]}")
        return sid

    @staticmethod
    def _is_done(status_json: str) -> bool:
        obj = json.loads(status_json)
        entries = obj.get("entry", [])
        if not entries:
            return False
        content = entries[0].get("content", {})
        done = content.get("isDone")
        return done in (True, "1", 1)

    @staticmethod
    def _parse_results(raw: str, sid: str) -> list[dict[str, Any]]:
        obj = json.loads(raw)
        out: list[dict[str, Any]] = []
        for i, r in enumerate(obj.get("results", []), start=1):
            row = {k: v for k, v in r.items() if not k.startswith("_") or k == "_time"}
            # preserve Splunk's _raw/_time if present
            if "_raw" in r:
                row["_raw"] = r["_raw"]
            # provenance ref: a live-Splunk row points at its job + offset
            row[REF_KEY] = [f"splunk:{sid}:{i}"]
            out.append(row)
        return out


class _RestEngine(SplEngine):
    """SplEngine whose ``search`` delegates to the live REST backend.

    Subclassing keeps the agent/detector call sites unchanged (they only ever
    call ``engine.search(spl)`` and read ``.rows`` / ``.refs``).
    """

    def __init__(self, backend: "SplunkRestBackend"):
        super().__init__(store=backend.store)
        self._backend = backend

    def search(self, spl: str) -> SearchResult:
        result = self._backend.run_spl(spl)
        if self._trace is not None:
            self._trace.tool_call(tool="splunk.search",
                                  args={"spl": spl, "backend": "splunk_rest"},
                                  result_refs=result.refs)
        return result


# ---------------------------------------------------------------------------
# selector
# ---------------------------------------------------------------------------

def make_backend(case_dir: str) -> SearchBackend:
    """Return the live REST backend if ``SPLUNK_URL``+``SPLUNK_TOKEN`` are set,
    otherwise the offline synthetic backend. This is the one-line switch."""
    url = os.environ.get("SPLUNK_URL")
    token = os.environ.get("SPLUNK_TOKEN")
    if url and token:
        verify = os.environ.get("SPLUNK_VERIFY_TLS", "1") not in ("0", "false", "no")
        return SplunkRestBackend(url, token, verify_tls=verify, case_dir=case_dir)
    return SyntheticBackend(EventStore(case_dir))
