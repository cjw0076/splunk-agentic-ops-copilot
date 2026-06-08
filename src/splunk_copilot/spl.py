"""A small but REAL SPL-like search engine over synthetic Splunk events.

This is not a mock. The agent's "Splunk searches" are genuine SPL strings that
get tokenized and executed against the loaded events. The supported subset is
the slice an incident copilot actually needs:

Base search (before the first ``|``):
    index=web sourcetype=access_combined status=200 uri_path="/api/login"
    field=value   field!=value   bareterm (substring over _raw/all fields)
    earliest=<epoch> latest=<epoch>   (time-window filter on _time)

Pipeline commands (after each ``|``):
    | where  <expr>                 boolean expr, =,!=,<,<=,>,>=, AND/OR/NOT,
                                     like(field,"pattern"), arithmetic, parens
    | eval   newfield = <expr>      arithmetic / string concat / if(...)
    | stats  count [as X] [sum(f) [as Y] ...] [by f1,f2]
    | sort   [-]field [, ...] [limit]
    | head   N
    | dedup  field [, ...]
    | table  f1, f2, ...
    | fields f1, f2, ...            (alias of table)
    | rename old as new [, ...]

Results are plain dicts. Each result keeps a hidden ``__refs__`` list carrying
the provenance refs of the source events that produced it, so every downstream
finding stays evidence-linked even through ``stats`` aggregation.

Expression evaluation is a hand-written recursive-descent parser — NO Python
``eval``/``exec`` of search input — so it is safe and the results are honest.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable

from .events import Event, EventStore

REF_KEY = "__refs__"


# ----------------------------------------------------------------------------
# tokenizer (shared by base-search term splitting and the where/eval parser)
# ----------------------------------------------------------------------------

_TOKEN_RE = re.compile(
    r"""
    \s*(?:
      (?P<str>"(?:[^"\\]|\\.)*")        # double-quoted string
    | (?P<op><=|>=|!=|=|<|>|\(|\)|,|\+|-|\*|/)
    | (?P<num>\d+\.\d+|\d+)
    | (?P<word>[A-Za-z_][A-Za-z0-9_.:]*)
    )
    """,
    re.VERBOSE,
)


def _tokenize(s: str) -> list[tuple[str, str]]:
    toks: list[tuple[str, str]] = []
    pos = 0
    while pos < len(s):
        m = _TOKEN_RE.match(s, pos)
        if not m or m.end() == pos:
            if s[pos].isspace():
                pos += 1
                continue
            raise SplError(f"cannot tokenize near: {s[pos:pos+20]!r}")
        pos = m.end()
        kind = m.lastgroup
        val = m.group()
        toks.append((kind, val.strip()))
    return toks


class SplError(ValueError):
    """Raised for an unsupported or malformed SPL query."""


# ----------------------------------------------------------------------------
# expression evaluator (for | where and | eval)
# ----------------------------------------------------------------------------

_FUNCS: dict[str, Callable[..., Any]] = {
    "like": lambda v, pat: _like(v, pat),
    "lower": lambda v: str(v).lower(),
    "upper": lambda v: str(v).upper(),
    "len": lambda v: len(str(v)),
    "if": lambda c, a, b: a if c else b,
    "match": lambda v, pat: bool(re.search(str(pat), str(v))),
}


def _like(value: Any, pattern: str) -> bool:
    # SPL-style like(): % = any run, _ = single char.
    rx = "^" + re.escape(str(pattern)).replace("\\%", ".*").replace("\\_", ".") + "$"
    return re.match(rx, str(value)) is not None


class _ExprParser:
    """Recursive-descent parser/evaluator for where/eval expressions.

    Grammar (lowest to highest precedence):
        or   := and (OR and)*
        and  := not (AND not)*
        not  := NOT not | cmp
        cmp  := add ((= | != | < | <= | > | >=) add)?
        add  := mul ((+|-) mul)*
        mul  := atom ((*|/) atom)*
        atom := number | string | func(args) | field | ( or )
    """

    def __init__(self, tokens: list[tuple[str, str]], row: dict[str, Any]):
        self.toks = tokens
        self.i = 0
        self.row = row

    def _peek(self) -> tuple[str, str] | None:
        return self.toks[self.i] if self.i < len(self.toks) else None

    def _next(self) -> tuple[str, str]:
        t = self.toks[self.i]
        self.i += 1
        return t

    def _accept_word(self, word: str) -> bool:
        t = self._peek()
        if t and t[0] == "word" and t[1].upper() == word:
            self.i += 1
            return True
        return False

    def _accept_op(self, op: str) -> bool:
        t = self._peek()
        if t and t[0] == "op" and t[1] == op:
            self.i += 1
            return True
        return False

    def parse(self) -> Any:
        val = self._or()
        if self.i != len(self.toks):
            raise SplError(f"trailing tokens in expression: {self.toks[self.i:]}")
        return val

    def _or(self) -> Any:
        val = self._and()
        while self._accept_word("OR"):
            rhs = self._and()
            val = bool(val) or bool(rhs)
        return val

    def _and(self) -> Any:
        val = self._not()
        while self._accept_word("AND"):
            rhs = self._not()
            val = bool(val) and bool(rhs)
        return val

    def _not(self) -> Any:
        if self._accept_word("NOT"):
            return not bool(self._not())
        return self._cmp()

    def _cmp(self) -> Any:
        left = self._add()
        for op in ("<=", ">=", "!=", "=", "<", ">"):
            if self._accept_op(op):
                right = self._add()
                return _compare(op, left, right)
        return left

    def _add(self) -> Any:
        val = self._mul()
        while True:
            if self._accept_op("+"):
                val = _arith_or_concat(val, self._mul(), "+")
            elif self._accept_op("-"):
                val = _to_num(val) - _to_num(self._mul())
            else:
                return val

    def _mul(self) -> Any:
        val = self._atom()
        while True:
            if self._accept_op("*"):
                val = _to_num(val) * _to_num(self._atom())
            elif self._accept_op("/"):
                val = _to_num(val) / _to_num(self._atom())
            else:
                return val

    def _atom(self) -> Any:
        t = self._peek()
        if t is None:
            raise SplError("unexpected end of expression")
        kind, val = t
        if kind == "op" and val == "(":
            self._next()
            inner = self._or()
            if not self._accept_op(")"):
                raise SplError("missing )")
            return inner
        if kind == "num":
            self._next()
            return float(val) if "." in val else int(val)
        if kind == "str":
            self._next()
            return _unquote(val)
        if kind == "word":
            self._next()
            nxt = self._peek()
            if nxt and nxt[0] == "op" and nxt[1] == "(":  # function call
                self._next()
                args = self._args()
                fn = _FUNCS.get(val.lower())
                if fn is None:
                    raise SplError(f"unknown function {val}()")
                return fn(*args)
            # bare word: field reference (missing -> None), or boolean literal
            low = val.lower()
            if low in ("true", "false"):
                return low == "true"
            return self.row.get(val)
        raise SplError(f"unexpected token {t}")

    def _args(self) -> list[Any]:
        args: list[Any] = []
        if self._accept_op(")"):
            return args
        args.append(self._or())
        while self._accept_op(","):
            args.append(self._or())
        if not self._accept_op(")"):
            raise SplError("missing ) in function call")
        return args


def _unquote(s: str) -> str:
    return s[1:-1].replace('\\"', '"').replace("\\\\", "\\")


def _to_num(v: Any) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


def _looks_numeric(v: Any) -> bool:
    if isinstance(v, (int, float)):
        return True
    try:
        float(v)
        return True
    except (TypeError, ValueError):
        return False


def _compare(op: str, a: Any, b: Any) -> bool:
    if op in ("<", "<=", ">", ">=") or (_looks_numeric(a) and _looks_numeric(b)):
        try:
            x, y = float(a), float(b)
            return {
                "=": x == y, "!=": x != y, "<": x < y, "<=": x <= y,
                ">": x > y, ">=": x >= y,
            }[op]
        except (TypeError, ValueError):
            pass
    sa, sb = ("" if a is None else str(a)), ("" if b is None else str(b))
    return {"=": sa == sb, "!=": sa != sb}.get(op, False)


def _arith_or_concat(a: Any, b: Any, op: str) -> Any:
    if _looks_numeric(a) and _looks_numeric(b):
        return _to_num(a) + _to_num(b)
    return f"{'' if a is None else a}{'' if b is None else b}"


def _eval_expr(expr: str, row: dict[str, Any]) -> Any:
    return _ExprParser(_tokenize(expr), row).parse()


# ----------------------------------------------------------------------------
# base search parsing
# ----------------------------------------------------------------------------

@dataclass
class _BaseFilter:
    field: str
    op: str  # "=" or "!="
    value: str


@dataclass
class _BaseSearch:
    filters: list[_BaseFilter] = field(default_factory=list)
    bare_terms: list[str] = field(default_factory=list)
    earliest: float | None = None
    latest: float | None = None


def _parse_base(text: str) -> _BaseSearch:
    bs = _BaseSearch()
    # split on whitespace but keep quoted values intact
    parts = re.findall(r'[^\s"]*"(?:[^"\\]|\\.)*"[^\s]*|\S+', text)
    for p in parts:
        m = re.match(r'^([A-Za-z_][A-Za-z0-9_.:]*)(!=|=)(.*)$', p)
        if m:
            fld, op, val = m.group(1), m.group(2), m.group(3)
            if val and val[0] == '"' and val[-1] == '"':
                val = _unquote(val)
            if fld == "earliest":
                bs.earliest = float(val)
            elif fld == "latest":
                bs.latest = float(val)
            else:
                bs.filters.append(_BaseFilter(fld, op, val))
        else:
            term = p
            if term and term[0] == '"' and term[-1] == '"':
                term = _unquote(term)
            bs.bare_terms.append(term)
    return bs


def _match_base(ev: Event, bs: _BaseSearch) -> bool:
    if bs.earliest is not None or bs.latest is not None:
        t = ev.get("_time")
        if t is None:
            return False
        t = float(t)
        if bs.earliest is not None and t < bs.earliest:
            return False
        if bs.latest is not None and t > bs.latest:
            return False
    for f in bs.filters:
        actual = _field_of(ev, f.field)
        eq = ("" if actual is None else str(actual)) == f.value
        if f.op == "=" and not eq:
            return False
        if f.op == "!=" and eq:
            return False
    for term in bs.bare_terms:
        if not _contains_term(ev, term):
            return False
    return True


def _field_of(ev: Event, fld: str) -> Any:
    if fld == "index":
        return ev.index
    if fld == "sourcetype":
        return ev.sourcetype
    return ev.get(fld)


def _contains_term(ev: Event, term: str) -> bool:
    needle = term.lower()
    raw = ev.get("_raw")
    if raw and needle in str(raw).lower():
        return True
    for v in ev.data.values():
        if needle in str(v).lower():
            return True
    return False


# ----------------------------------------------------------------------------
# pipeline commands
# ----------------------------------------------------------------------------

def _row_view(ev: Event) -> dict[str, Any]:
    row = dict(ev.data)
    row["index"] = ev.index
    row["sourcetype"] = ev.sourcetype
    row[REF_KEY] = [ev.ref]
    return row


def _cmd_where(rows: list[dict[str, Any]], arg: str) -> list[dict[str, Any]]:
    return [r for r in rows if bool(_eval_expr(arg, r))]


def _cmd_eval(rows: list[dict[str, Any]], arg: str) -> list[dict[str, Any]]:
    if "=" not in arg:
        raise SplError("eval requires field=expr")
    name, expr = arg.split("=", 1)
    name = name.strip()
    for r in rows:
        r[name] = _eval_expr(expr.strip(), r)
    return rows


_STATS_FN = re.compile(r"(count|sum|avg|min|max|dc|values)\(([^)]*)\)", re.IGNORECASE)

# One aggregator term: `fn(field)` or bare `count`, optionally `as <name>`.
_AGG_TERM = re.compile(
    r"""\s*(?:
          (?P<fn>count|sum|avg|min|max|dc|values)\s*\(\s*(?P<field>[\w.]*)\s*\)
        | (?P<count>count)
        )
        (?:\s+as\s+(?P<name>[A-Za-z_]\w*))?
        \s*,?
    """,
    re.IGNORECASE | re.VERBOSE,
)


def _parse_aggregators(arg: str) -> list[tuple[str, str, str]]:
    """Parse a stats aggregator list -> [(fn, field, out_name), ...]."""
    aggs: list[tuple[str, str, str]] = []
    pos = 0
    arg = arg.strip()
    while pos < len(arg):
        m = _AGG_TERM.match(arg, pos)
        if not m or m.end() == pos:
            raise SplError(f"unsupported stats clause near: {arg[pos:pos+30]!r}")
        pos = m.end()
        if m.group("count"):
            fn, fld = "count", ""
        else:
            fn, fld = m.group("fn").lower(), (m.group("field") or "").strip()
        name = m.group("name") or (fn if fn == "count" else f"{fn}({fld})")
        aggs.append((fn, fld, name))
    return aggs


def _cmd_stats(rows: list[dict[str, Any]], arg: str) -> list[dict[str, Any]]:
    by_fields: list[str] = []
    if " by " in (" " + arg + " ").lower():
        idx = arg.lower().rindex(" by ")
        by_fields = [f.strip() for f in arg[idx + 4:].split(",") if f.strip()]
        arg = arg[:idx]
    # parse aggregators. SPL allows them whitespace- OR comma-separated, each
    # optionally followed by "as <name>", e.g.:
    #   count as exports sum(bytes) as total_bytes
    #   count, sum(bytes) as total
    aggs = _parse_aggregators(arg)
    if not aggs:
        aggs = [("count", "", "count")]

    groups: dict[tuple, list[dict[str, Any]]] = {}
    order: list[tuple] = []
    for r in rows:
        key = tuple(str(r.get(f, "")) for f in by_fields)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(r)

    out: list[dict[str, Any]] = []
    for key in order:
        members = groups[key]
        res: dict[str, Any] = {by_fields[i]: key[i] for i in range(len(by_fields))}
        for fn, fld, name in aggs:
            res[name] = _aggregate(fn, fld, members)
        res[REF_KEY] = _collect_refs(members)
        out.append(res)
    return out


def _aggregate(fn: str, fld: str, members: list[dict[str, Any]]) -> Any:
    if fn == "count":
        return len(members)
    vals = [m.get(fld) for m in members if m.get(fld) is not None]
    nums = [_to_num(v) for v in vals if _looks_numeric(v)]
    if fn == "sum":
        return sum(nums)
    if fn == "avg":
        return round(sum(nums) / len(nums), 4) if nums else 0
    if fn == "min":
        return min(nums) if nums else None
    if fn == "max":
        return max(nums) if nums else None
    if fn == "dc":
        return len(set(str(v) for v in vals))
    if fn == "values":
        return sorted(set(str(v) for v in vals))
    raise SplError(f"unsupported stats function {fn}")


def _cmd_sort(rows: list[dict[str, Any]], arg: str) -> list[dict[str, Any]]:
    limit = None
    m = re.match(r"\s*(\d+)\s+(.*)$", arg)
    if m:
        limit, arg = int(m.group(1)), m.group(2)
    keys: list[tuple[str, bool]] = []
    for part in arg.split(","):
        part = part.strip()
        desc = part.startswith("-")
        fld = part.lstrip("+-").strip()
        keys.append((fld, desc))

    def sort_key(r: dict[str, Any]):
        out = []
        for fld, _desc in keys:
            v = r.get(fld)
            out.append((0, _to_num(v)) if _looks_numeric(v) else (1, str(v)))
        return out

    rows = sorted(rows, key=sort_key)
    # apply descending per-key (stable multi-pass)
    for fld, desc in reversed(keys):
        if desc:
            rows.sort(key=lambda r: (_to_num(r.get(fld))
                                     if _looks_numeric(r.get(fld))
                                     else 0), reverse=True)
    if limit is not None:
        rows = rows[:limit]
    return rows


def _cmd_head(rows: list[dict[str, Any]], arg: str) -> list[dict[str, Any]]:
    n = int(arg.strip()) if arg.strip() else 10
    return rows[:n]


def _cmd_dedup(rows: list[dict[str, Any]], arg: str) -> list[dict[str, Any]]:
    fields = [f.strip() for f in arg.split(",") if f.strip()]
    seen: set[tuple] = set()
    out: list[dict[str, Any]] = []
    for r in rows:
        key = tuple(str(r.get(f, "")) for f in fields)
        if key in seen:
            continue
        seen.add(key)
        out.append(r)
    return out


def _cmd_table(rows: list[dict[str, Any]], arg: str) -> list[dict[str, Any]]:
    fields = [f.strip() for f in arg.split(",") if f.strip()]
    out = []
    for r in rows:
        nr = {f: r.get(f) for f in fields}
        nr[REF_KEY] = r.get(REF_KEY, [])
        out.append(nr)
    return out


def _cmd_rename(rows: list[dict[str, Any]], arg: str) -> list[dict[str, Any]]:
    pairs: list[tuple[str, str]] = []
    for clause in arg.split(","):
        m = re.match(r"\s*([\w.]+)\s+as\s+([\w]+)\s*$", clause, re.IGNORECASE)
        if not m:
            raise SplError(f"bad rename clause {clause!r}")
        pairs.append((m.group(1), m.group(2)))
    for r in rows:
        for old, new in pairs:
            if old in r:
                r[new] = r.pop(old)
    return rows


_COMMANDS: dict[str, Callable[[list[dict[str, Any]], str], list[dict[str, Any]]]] = {
    "where": _cmd_where,
    "eval": _cmd_eval,
    "stats": _cmd_stats,
    "sort": _cmd_sort,
    "head": _cmd_head,
    "dedup": _cmd_dedup,
    "table": _cmd_table,
    "fields": _cmd_table,
    "rename": _cmd_rename,
}


# ----------------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------------

def _split_top(s: str, sep: str) -> list[str]:
    """Split on `sep` but not inside parens or quotes."""
    out, depth, buf, in_str = [], 0, [], False
    for ch in s:
        if ch == '"':
            in_str = not in_str
        if not in_str:
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            elif ch == sep and depth == 0:
                out.append("".join(buf))
                buf = []
                continue
        buf.append(ch)
    out.append("".join(buf))
    return out


def _split_pipeline(query: str) -> list[str]:
    """Split a query on top-level `|` (not inside quotes)."""
    out, buf, in_str = [], [], False
    for ch in query:
        if ch == '"':
            in_str = not in_str
        if ch == "|" and not in_str:
            out.append("".join(buf))
            buf = []
            continue
        buf.append(ch)
    out.append("".join(buf))
    return [s.strip() for s in out]


def _collect_refs(rows: list[dict[str, Any]]) -> list[str]:
    refs: list[str] = []
    for r in rows:
        for ref in r.get(REF_KEY, []):
            if ref not in refs:
                refs.append(ref)
    return refs


# ----------------------------------------------------------------------------
# public engine
# ----------------------------------------------------------------------------

@dataclass
class SearchResult:
    spl: str
    rows: list[dict[str, Any]]

    @property
    def count(self) -> int:
        return len(self.rows)

    @property
    def refs(self) -> list[str]:
        """Provenance refs of every source event behind these results."""
        return _collect_refs(self.rows)

    def values(self, field_name: str) -> list[Any]:
        return [r.get(field_name) for r in self.rows]


@dataclass
class SplEngine:
    store: EventStore
    _trace: Any = None  # optional TraceRecorder

    def attach_trace(self, trace: Any) -> None:
        self._trace = trace

    def search(self, spl: str) -> SearchResult:
        stages = _split_pipeline(spl)
        if not stages:
            raise SplError("empty query")
        bs = _parse_base(stages[0])
        rows = [_row_view(ev) for ev in self.store.events if _match_base(ev, bs)]
        for stage in stages[1:]:
            if not stage:
                continue
            head, _, arg = stage.partition(" ")
            cmd = _COMMANDS.get(head.lower())
            if cmd is None:
                raise SplError(f"unsupported pipeline command: {head!r}")
            rows = cmd(rows, arg.strip())
        result = SearchResult(spl=spl, rows=rows)
        if self._trace is not None:
            self._trace.tool_call(
                tool="splunk.search",
                args={"spl": spl},
                result_refs=result.refs,
            )
        return result
