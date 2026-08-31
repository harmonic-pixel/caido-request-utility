"""
idor_finder.py — surface IDOR candidates from a Caido Request Utility (CRU) database.

PASSIVE ONLY. This reads the `requests` table that CRU builds and emits a
prioritised list of object-reference endpoints worth testing. It sends no traffic
of its own — confirmation is a separate, *authorised* step you run with a replay
tool such as idox (the same author's IDOR tester) or a Caido workflow.

What it does:
  1. Pulls every request/response row from the CRU `requests` table.
  2. Extracts object-reference-looking identifiers from the path, query string,
     and request body (ints, UUIDs, Mongo ObjectIds, long hex hashes).
  3. Normalises each path into an endpoint *template* so the same route with
     different IDs collapses together (that clustering is the whole point:
     "we saw /api/users/{int} hit with 40 distinct IDs" is a strong signal).
  4. Scores each candidate by identifier type, whether the endpoint is
     access-controlled, whether it returns object data, request method impact,
     and how many distinct IDs were actually observed.
  5. Prints a ranked report (or JSON) you can hand to a replay tool.

Usage:
    python -m cru.idor_finder path/to/test.db
    python -m cru.idor_finder test.db --json > candidates.json
    python -m cru.idor_finder test.db --min-distinct 2 --min-severity medium

Stdlib only.
"""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
import statistics
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from urllib.parse import parse_qsl

# --------------------------------------------------------------------------- #
# Identifier detection
# --------------------------------------------------------------------------- #

_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}" r"-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_OBJECTID_RE = re.compile(r"^[0-9a-fA-F]{24}$")
_HASH_RE = re.compile(r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$")
_INT_RE = re.compile(r"^\d+$")

# Query/body parameter names that commonly reference an object even when the
# value itself doesn't look like a classic ID.
ID_PARAM_HINTS = {
    "id",
    "uid",
    "user",
    "user_id",
    "userid",
    "account",
    "account_id",
    "acct",
    "customer",
    "customer_id",
    "order",
    "order_id",
    "invoice",
    "invoice_id",
    "doc",
    "document",
    "document_id",
    "file",
    "file_id",
    "fileid",
    "pid",
    "product_id",
    "ref",
    "record",
    "record_id",
    "object",
    "obj",
    "objectid",
    "key",
    "num",
    "number",
    "seq",
    "node",
    "item",
    "item_id",
    "group",
    "group_id",
    "org",
    "org_id",
    "tenant",
    "tenant_id",
    "profile",
    "profile_id",
    "msg",
    "message",
    "message_id",
    "ticket",
    "ticket_id",
    "case",
    "case_id",
    "report",
    "report_id",
    "transaction",
    "txn",
    "payment",
    "payment_id",
    "card",
    "address",
    "address_id",
    "note",
    "note_id",
    "session",
    "token",
}

# Truly-static asset extensions. Note: pdf/zip/csv/xlsx/docx are deliberately
# NOT here — a numeric-named download is a classic IDOR object.
STATIC_EXT = {
    "js",
    "css",
    "png",
    "jpg",
    "jpeg",
    "gif",
    "svg",
    "ico",
    "woff",
    "woff2",
    "ttf",
    "otf",
    "eot",
    "map",
    "webp",
    "mp4",
    "webm",
    "avif",
}

TYPE_LABEL = {
    "int": "sequential/numeric-int",
    "uuid": "uuid",
    "objectid": "mongo-objectid",
    "hash": "hex-hash",
}
# Kept per candidate. The text renderer shows the first few; the HTML report
# lists them all, which is what you actually enumerate against.
_ID_SAMPLE = 100
_TEXT_SAMPLE = 5

_TYPE_WEIGHT = {"int": 5, "objectid": 3, "uuid": 3, "hash": 1}


def _classify(token: str) -> str | None:
    """Return the id-type of a bare token, or None if it isn't id-shaped."""
    if not token:
        return None
    if _INT_RE.match(token):
        return "int"
    if _UUID_RE.match(token):
        return "uuid"
    if _OBJECTID_RE.match(token):
        return "objectid"
    if _HASH_RE.match(token):
        return "hash"
    return None


def _split_ext(segment: str) -> tuple[str, str]:
    """Return (stem, ext_lower_without_dot). ext is '' when absent."""
    if "." in segment:
        stem, ext = segment.rsplit(".", 1)
        return stem, ext.lower()
    return segment, ""


# --------------------------------------------------------------------------- #
# Candidate extraction from a single row
# --------------------------------------------------------------------------- #


@dataclass
class Candidate:
    location: str  # human label, e.g. "path:/users/{int}" or "query:user_id"
    id_type: str  # int | uuid | objectid | hash
    raw_value: str  # the observed identifier
    ext: str = ""  # file extension if the id lived in a filename
    confidence: str = "primary"  # primary | review


def _clean_path(path: str) -> str:
    return (path or "").split("?", 1)[0].split("#", 1)[0]


def endpoint_template(path: str) -> str:
    """Collapse id-shaped path segments to typed placeholders."""
    clean = _clean_path(path)
    out = []
    for seg in clean.split("/"):
        if seg == "":
            out.append(seg)
            continue
        stem, ext = _split_ext(seg)
        t = _classify(stem)
        if t and ext not in STATIC_EXT:
            out.append(f"{{{t}}}{"." + ext if ext else ""}")
        else:
            out.append(seg)
    return "/".join(out) or "/"


def path_candidates(path: str) -> list[Candidate]:
    clean = _clean_path(path)
    segs = clean.split("/")
    out: list[Candidate] = []
    for i, seg in enumerate(segs):
        if seg == "":
            continue
        stem, ext = _split_ext(seg)
        t = _classify(stem)
        if not t or ext in STATIC_EXT:
            continue
        prev = ""
        for j in range(i - 1, -1, -1):
            if segs[j] and not _classify(_split_ext(segs[j])[0]):
                prev = segs[j]
                break
        label = f"path:/{prev}/{{{t}}}" if prev else f"path:/{{{t}}}"
        out.append(Candidate(label, t, stem, ext))
    return out


def _param_candidates(pairs, source: str) -> list[Candidate]:
    out: list[Candidate] = []
    for k, v in pairs:
        t = _classify(v)
        hinted = k.lower() in ID_PARAM_HINTS
        # High-entropy refs (uuid/objectid/hash) are always worth flagging.
        # Hinted names are primary at any value (int id or opaque slug).
        # A bare int on an *unnamed* param is kept but demoted to `review`:
        # it's often a quantity/page/flag, occasionally a real object ref.
        if t in ("uuid", "objectid", "hash") or hinted:
            confidence = "primary"
        elif t == "int":
            confidence = "review"
        else:
            continue  # non-hinted, non-id-shaped value — genuinely not a ref
        out.append(Candidate(f"{source}:{k}", t or "hash", v, confidence=confidence))
    return out


def query_candidates(query: str) -> list[Candidate]:
    if not query:
        return []
    return _param_candidates(parse_qsl(query, keep_blank_values=True), "query")


def _walk_json(obj, prefix=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, (dict, list)):
                yield from _walk_json(v, key)
            else:
                yield key, v
    elif isinstance(obj, list):
        for idx, v in enumerate(obj):
            key = f"{prefix}[{idx}]"
            if isinstance(v, (dict, list)):
                yield from _walk_json(v, key)
            else:
                yield key, v


def body_candidates(body: str, headers: str) -> list[Candidate]:
    if not body:
        return []
    b = body.strip()
    if b[:1] in "{[":
        try:
            data = json.loads(b)
        except (ValueError, TypeError):
            return []
        pairs = []
        for k, v in _walk_json(data):
            leaf = k.split(".")[-1].split("[")[0].lower()
            pairs.append(
                (k if leaf in ID_PARAM_HINTS or _classify(str(v)) else leaf, str(v))
            )
        return _param_candidates(pairs, "body")
    # fall back to form-encoded
    return _param_candidates(parse_qsl(b, keep_blank_values=True), "body")


# --------------------------------------------------------------------------- #
# Auth context
# --------------------------------------------------------------------------- #

_AUTH_HEADERS = {
    "authorization",
    "x-api-key",
    "x-auth-token",
    "api-key",
    "x-access-token",
    "x-csrf-token",
}


def is_authed(cookies: str | None, headers: str | None) -> bool:
    if cookies and cookies.strip():
        return True
    if headers:
        for line in headers.splitlines():
            if line.split(":", 1)[0].strip().lower() in _AUTH_HEADERS:
                return True
    return False


# --------------------------------------------------------------------------- #
# Aggregation
# --------------------------------------------------------------------------- #


@dataclass
class Finding:
    host: str
    method: str
    endpoint: str  # templated path
    location: str
    id_type: str
    distinct_ids: int
    sample_ids: list[str]
    auth_observed: bool
    unauth_observed: bool
    statuses: list[int]
    returns_body: bool
    avg_body_bytes: int
    request_count: int
    confidence: str = "primary"
    score: int = 0
    severity: str = "low"
    note: str = ""


@dataclass
class _Agg:
    values: set = field(default_factory=set)
    statuses: set = field(default_factory=set)
    lengths: list = field(default_factory=list)
    auth: bool = False
    unauth: bool = False
    count: int = 0
    ext: str = ""
    confidence: str = "primary"


def analyse(rows) -> list[Finding]:
    groups: dict[tuple, _Agg] = defaultdict(_Agg)

    for r in rows:
        host = r["host"]
        method = (r["method"] or "GET").upper()
        template = endpoint_template(r["path"])
        authed = is_authed(r["cookies"], r["headers"])

        cands = (
            path_candidates(r["path"])
            + query_candidates(r["query"])
            + body_candidates(r["body"], r["headers"])
        )
        if not cands:
            continue

        status = r["response_status_code"]
        rlen = r["response_length"]

        for c in cands:
            key = (host, method, template, c.location, c.id_type)
            g = groups[key]
            g.values.add(c.raw_value)
            g.count += 1
            g.ext = c.ext or g.ext
            if c.confidence == "review":
                g.confidence = "review"
            if status is not None:
                try:
                    g.statuses.add(int(status))
                except (ValueError, TypeError):
                    pass
            if rlen is not None:
                try:
                    g.lengths.append(int(rlen))
                except (ValueError, TypeError):
                    pass
            if authed:
                g.auth = True
            else:
                g.unauth = True

    findings: list[Finding] = []
    for (host, method, template, location, id_type), g in groups.items():
        statuses = sorted(g.statuses)
        any_2xx = any(200 <= s < 300 for s in statuses)
        avg_len = int(statistics.mean(g.lengths)) if g.lengths else 0
        returns_body = avg_len > 200

        score = _TYPE_WEIGHT.get(id_type, 1)
        if g.auth:
            score += 2  # object is access-controlled
        if any_2xx:
            score += 2  # endpoint actually serves it
        if returns_body:
            score += 1  # ...and returns object data
        if method in {"PUT", "PATCH", "DELETE"}:
            score += 2  # state-changing => higher impact
        score += min(len(g.values), 5)  # observed enumeration evidence

        if score >= 11:
            severity = "high"
        elif score >= 7:
            severity = "medium"
        else:
            severity = "low"

        note = _note(id_type, g, method, any_2xx)

        findings.append(
            Finding(
                host=host,
                method=method,
                endpoint=template,
                location=location,
                id_type=id_type,
                distinct_ids=len(g.values),
                sample_ids=sorted(g.values, key=_sort_key)[:_ID_SAMPLE],
                auth_observed=g.auth,
                unauth_observed=g.unauth,
                statuses=statuses,
                returns_body=returns_body,
                avg_body_bytes=avg_len,
                request_count=g.count,
                confidence=g.confidence,
                score=score,
                severity=severity,
                note=note,
            )
        )

    findings.sort(key=lambda f: (-f.score, f.host, f.endpoint))
    return findings


def _sort_key(v: str):
    return (0, int(v)) if v.isdigit() else (1, v)


def _note(id_type, g: _Agg, method, any_2xx) -> str:
    bits = []
    if id_type == "int":
        bits.append("sequential integer — trivially enumerable")
    elif id_type in ("uuid", "objectid"):
        bits.append(
            "non-sequential ref — test for leakage/reuse rather than "
            "blind enumeration"
        )
    else:
        bits.append("opaque ref — check whether the value leaks elsewhere")
    if g.auth and g.unauth:
        bits.append("seen both with and without auth — compare responses")
    elif g.auth:
        bits.append("access-controlled — replay with a second user's session")
    if method in {"PUT", "PATCH", "DELETE"}:
        bits.append("state-changing — potential unauthorised write/delete")
    if not any_2xx:
        bits.append("no 2xx captured — may need valid IDs to confirm")
    return "; ".join(bits)


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #

_SEV_ORDER = {"high": 3, "medium": 2, "low": 1}


def load_rows(db_path: str, table: str = "requests"):
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    cols = (
        "host, method, path, query, cookies, headers, body, "
        "response_status_code, response_length"
    )
    try:
        return con.execute(f"SELECT {cols} FROM {table}").fetchall()
    finally:
        con.close()


def _fmt_bytes(n: int) -> str:
    if n >= 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n} B"


def _render_block(f: Finding) -> list[str]:
    shown = f.sample_ids[:_TEXT_SAMPLE]
    sample = ", ".join(shown)
    more = f.distinct_ids - len(shown)
    if more > 0:
        sample += f" (+{more} more, {f.distinct_ids} distinct)"
    else:
        sample += f" ({f.distinct_ids} distinct)"
    auth = "yes" if f.auth_observed else "no"
    if f.auth_observed and f.unauth_observed:
        auth = "mixed"
    return [
        (
            f"[{f.severity.upper():<6} score {f.score:>2}] "
            f"{f.method} {f.host}  {f.endpoint}"
        ),
        f"    where : {f.location}   type: {TYPE_LABEL[f.id_type]}",
        f"    IDs   : {sample}",
        (
            f"    resp  : {f.statuses or '—'}   "
            f"auth: {auth}   avg body: {_fmt_bytes(f.avg_body_bytes)}   "
            f"reqs: {f.request_count}"
        ),
        f"    -> {f.note}",
        "",
    ]


def render_text(findings: list[Finding]) -> str:
    if not findings:
        return "No IDOR candidates found."
    primary = [f for f in findings if f.confidence == "primary"]
    review = [f for f in findings if f.confidence == "review"]

    lines: list[str] = []
    if primary:
        lines += [f"{len(primary)} IDOR candidate(s), highest-value first:", ""]
        for f in primary:
            lines += _render_block(f)
    else:
        lines += ["No primary IDOR candidates found.", ""]

    if review:
        lines += [
            "-" * 70,
            (
                f"{len(review)} lower-confidence candidate(s) "
                "(bare integer on an unnamed parameter — likely a page/quantity/"
            ),
            "flag, occasionally a real object ref; review by hand):",
            "",
        ]
        for f in review:
            lines += _render_block(f)
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Surface IDOR candidates from a CRU requests database (passive)."
    )
    ap.add_argument("db", help="path to the SQLite DB CRU produced")
    ap.add_argument(
        "--table", default="requests", help="table name (default: requests)"
    )
    ap.add_argument("--json", action="store_true", help="emit JSON instead of a report")
    ap.add_argument(
        "--min-distinct",
        type=int,
        default=1,
        help="only show candidates with >= N distinct observed IDs",
    )
    ap.add_argument("--min-severity", choices=("low", "medium", "high"), default="low")
    ap.add_argument(
        "--primary-only",
        action="store_true",
        help="hide the lower-confidence (unnamed bare-int) list",
    )
    args = ap.parse_args(argv)

    rows = load_rows(args.db, args.table)
    findings = analyse(rows)

    floor = _SEV_ORDER[args.min_severity]
    findings = [
        f
        for f in findings
        if f.distinct_ids >= args.min_distinct
        and _SEV_ORDER[f.severity] >= floor
        and not (args.primary_only and f.confidence == "review")
    ]

    if args.json:
        print(json.dumps([asdict(f) for f in findings], indent=2))
    else:
        print(render_text(findings))


if __name__ == "__main__":
    main()
