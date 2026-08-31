"""Shared primitives every check builds on.

`Finding` and the field-access helpers are the seam described in CLAUDE.md:
checks read rows through `request_inputs`, `iter_fields`, `request_param_values`
and `response_text` rather than touching columns directly, so encoding coverage
and the corpus limits stay in one place.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import re
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, unquote_plus

from cru.field_decode import JWT_DECODED_RE, JWT_RE

__all__ = ["JWT_DECODED_RE", "JWT_RE"]  # re-exported: one definition, in field_decode

# --------------------------------------------------------------------------- #
# Finding + field iteration
# --------------------------------------------------------------------------- #


@dataclass
class _Finding:
    check: str
    signature: str  # detector / payload family name
    host: str
    method: str
    path: str
    location: str  # which field: request-body, response-headers, ...
    evidence: str  # redacted/truncated snippet
    detail: str = ""
    # Every request this finding was seen on, as "METHOD /path". One entry for
    # an ordinary finding; several once `group` has merged occurrences. The
    # method is part of it because a merged finding spans requests: listing a
    # bare path implicates the OPTIONS preflight alongside the GET that
    # actually carried the token.
    paths: list[str] = field(default_factory=list)
    # An identity that replaces `key()` for dedup: occurrences sharing it are
    # the same finding wearing different paths. `jwt_identity` builds one.
    group: str | None = None
    # Observed values behind the finding — the IDs an IDOR candidate was seen
    # with. Listed in the report the way `paths` is.
    ids: list[str] = field(default_factory=list)
    # Every rule behind a combined finding: `code` reports one finding per
    # request and lists what fired, rather than one per signature.
    rules: list[str] = field(default_factory=list)

    def key(self):
        return (
            self.check,
            self.signature,
            self.host,
            self.path,
            # The "#json" view re-presents a field it shares its text with, so a
            # hit visible in both is one finding, reported against the field.
            self.location.replace("#json", ""),
            self.evidence,
        )


def Finding(
    check,
    severity,
    signature,
    host,
    method,
    path,
    location,
    evidence,
    detail="",
    group=None,
    ids=None,
    rules=None,
):
    """Construct a finding.

    `severity` is still accepted so the individual checks don't need changing,
    but it is intentionally discarded — this tool does not rank findings by
    severity. Everything downstream (dedup, output, report) ignores it.

    `group` is optional: pass one when several occurrences are the same finding
    seen on different paths, and `_dedupe` will collapse them into one carrying
    every path. `ids` is optional too: the observed values behind the finding,
    listed in the report, as is `rules` for a finding that combines several.
    """
    return _Finding(
        check,
        signature,
        host,
        method,
        path,
        location,
        evidence,
        detail,
        group=group,
        ids=list(ids or []),
        rules=list(rules or []),
    )


# Claims that change on every issue of the same token, so two tokens differing
# only in these are the same credential to a reviewer. Alongside the timestamps
# and the token id, the OIDC binding hashes belong here: `at_hash` and friends
# are digests of whatever else was minted in that exchange, so a Google ID token
# for one subject differs on `at_hash` at every refresh and on nothing else.
# What is *not* here matters as much: `type` separates an access token from a
# refresh token, and those are different credentials.
_JWT_VOLATILE_CLAIMS = frozenset(
    {
        "iat",
        "exp",
        "nbf",
        "jti",
        "auth_time",
        "nonce",
        "at_hash",
        "c_hash",
        "s_hash",
        "rt_hash",
        "sid",
    }
)


def value_identity(value):
    """A dedup identity for a literal value, hashed so it stays out of output.

    `group` is serialised into the report, so it must not carry the secret it
    identifies.
    """
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:16]


def jwt_identity(token):
    """A stable identity for a JWT: its header and its non-volatile claims.

    Refreshing a session mints a new token with new `iat`/`exp` and a new
    signature, so a browsing session leaves dozens of findings that are all the
    same credential on the same subject. Grouping on the decoded content
    collapses them; `None` means the token would not decode and cannot be
    grouped, so it stays on its own.
    """
    parts = token.split(".")
    header = _b64url_json(parts[0])
    if not isinstance(header, dict):
        return None
    payload = _b64url_json(parts[1]) if len(parts) > 1 else None
    claims = (
        {k: v for k, v in payload.items() if k not in _JWT_VOLATILE_CLAIMS}
        if isinstance(payload, dict)
        else payload
    )
    canonical = json.dumps(
        [header, claims], sort_keys=True, separators=(",", ":"), default=str
    )
    return hashlib.sha256(canonical.encode()).hexdigest()[:16]


# Fields worth scanning, with a stable label. We scan the response side too.
_SCAN_FIELDS = (
    ("request-cookies", "cookies"),
    ("request-headers", "headers"),
    ("request-query", "query"),
    ("request-body", "body"),
    ("response-headers", "response_headers"),
    ("response-body", "response_body"),
)

_MAX_FIELD = 400_000  # cap per-field bytes scanned to keep it quick


# Injection checks care about direction: a payload lives in the *request*, its
# effect (error/evaluated result) shows in the *response*.
_REQUEST_FIELDS = (
    ("request-cookies", "cookies"),
    ("request-headers", "headers"),
    ("request-query", "query"),
    ("request-body", "body"),
)
_RESPONSE_FIELDS = (
    ("response-headers", "response_headers"),
    ("response-body", "response_body"),
)

# Encoding coverage: many payloads are wrapped in base64 or hex to slip past a
# naive scan. The decoded plaintext is computed ONCE at import time and stored in
# `<field>_decoded` columns (see field_decode). The field-access helpers surface
# those columns as extra "#decoded" views so every pattern check gets encoding
# coverage without decoding per row. DBs imported before these columns existed
# simply have no decoded views (see _decoded_col).

# base column -> its decoded companion column
_DECODED_COL = {
    "query": "query_decoded",
    "body": "body_decoded",
    "cookies": "cookies_decoded",
    "headers": "headers_decoded",
    "response_body": "response_body_decoded",
}


# --------------------------------------------------------------------------- #
# Pattern gating
# --------------------------------------------------------------------------- #

# A scan costs (patterns x bytes): one compiled pattern over a 15MB corpus is
# ~0.2s whether or not it matches, and there are over a hundred of them. The
# same corpus takes 0.01s to search for a literal, so naming the literal a
# pattern cannot match without lets almost every field skip the regex entirely.

_LOW_SRC: str | None = None
_LOW: str | None = None


def _lower(text):
    """The lowercase twin of `text`, memoised, or None if folding shifts offsets.

    Checks run their whole pattern table against one field before moving to the
    next, so a single-entry memo hits every time after the first pattern.
    `str.lower()` is length-preserving for everything but a handful of
    codepoints (U+0130 folds to two characters); on those, offsets into the
    folded text would point at the wrong place in the original, so the caller
    is told to scan the text as it is.
    """
    global _LOW_SRC, _LOW
    if text is not _LOW_SRC:
        low = text.lower()
        _LOW_SRC, _LOW = text, low if len(low) == len(text) else None
    return _LOW


class _FoldedMatch:
    """A match found in the folded text, read back out of the original.

    Evidence keeps the case it was written in, and the spans are the original's
    because folding preserved every offset.
    """

    __slots__ = ("_m", "_text")

    def __init__(self, m, text):
        self._m, self._text = m, text

    def group(self, i=0):
        start, end = self._m.span(i)
        return self._text[start:end] if start >= 0 else None

    def groups(self):
        return tuple(self.group(i) for i in range(1, self._m.re.groups + 1))

    def span(self, i=0):
        return self._m.span(i)

    def start(self, i=0):
        return self._m.start(i)

    def end(self, i=0):
        return self._m.end(i)


class _Gated:
    """A compiled pattern plus the literals it cannot match without."""

    __slots__ = ("folded", "literals", "rx")

    def __init__(self, pattern, literals, flags):
        ci = pattern.startswith("(?i)")
        self.rx = re.compile(pattern, flags | (re.IGNORECASE if ci else 0))
        # Case-folded matching costs ~10x a plain pass, and the folded text is
        # already built for the gate — so a case-insensitive pattern can drop
        # its flag and match the folded text instead, with the evidence read
        # back out of the original. Only when the pattern itself holds no
        # uppercase: `MySQL` or `[A-Z]{16}` would find nothing in folded text.
        # The test is deliberately blunt — `\S` lowercases to `\s`, so any
        # pattern where case carries meaning simply keeps its flag.
        body = pattern[4:] if ci else pattern
        self.folded = re.compile(body, flags) if ci and body == body.lower() else None
        self.literals = literals

    @property
    def pattern(self):
        return self.rx.pattern

    def _target(self, text):
        """(haystack, pattern, folded) — haystack None when the gate rejects."""
        low = _lower(text)
        if low is None:
            return text, self.rx, False
        if self.literals and not any(lit in low for lit in self.literals):
            return None, None, False
        if self.folded is not None:
            return low, self.folded, True
        return text, self.rx, False

    def search(self, text):
        hay, rx, folded = self._target(text)
        if hay is None:
            return None
        m = rx.search(hay)
        return _FoldedMatch(m, text) if (m and folded) else m

    def finditer(self, text):
        hay, rx, folded = self._target(text)
        if hay is None:
            return iter(())
        if not folded:
            return rx.finditer(hay)
        return (_FoldedMatch(m, text) for m in rx.finditer(hay))


def gate(pattern, *literals, flags=0):
    """Compile `pattern`, skipped on any text missing all of `literals`.

    Give the literals in lowercase; they are matched case-insensitively, so a
    case-sensitive pattern still gates (a lowercase-only literal lets through
    text the pattern then rejects — slower, never wrong). Name literals that
    every match must contain: one per top-level alternative, and none at all
    for a pattern with nothing worth naming — `re.compile` still works there.
    A leading `(?i)` is honoured, and matching moves to the folded text.
    """
    return _Gated(pattern, tuple(literals), flags)


# Responses whose body is bytes: the corpus stores a lossy text decode of them,
# so scanning costs their whole size and can only match noise. SVG is XML, and
# the checks that read markup want it.
_BINARY_CT = re.compile(r"(?im)^content-type:\s*(?:image/(?!svg)|video/|audio/|font/)")


def _binary_response(row):
    return bool(_BINARY_CT.search(row["response_headers"] or ""))


def response_body(row):
    """The response body, or "" when it is binary and not worth scanning."""
    return "" if _binary_response(row) else (row["response_body"] or "")


def _row_has(row, col):
    """True if the sqlite Row actually carries a column (older DBs may not)."""
    try:
        return row[col] is not None
    except (IndexError, KeyError):
        return False


def _decoded_for(row, col):
    """Return the precomputed decoded plaintext for a base column, or ''."""
    dcol = _DECODED_COL.get(col)
    if dcol and _row_has(row, dcol):
        return row[dcol] or ""
    return ""


def _json_view(text):
    """The string leaves of a JSON document, unescaped, one per line.

    A JSON string escapes its newlines, so code carried in one runs together —
    `"...Operation\\ndef operation("` reads as `ndef operation(`, and every
    `\\b`-anchored pattern misses it. Parsing the document and handing back the
    leaves gives every check the value as it will actually be interpreted,
    whatever language it is written in. Returns "" when the text is not JSON.
    """
    # Only worth a view when the document escapes whitespace: that is what glues
    # a value's lines together and hides them from a \\b-anchored pattern. Without
    # one the leaves read the same as the raw field, and every check would report
    # the same hit twice under two labels.
    if not any(esc in text for esc in ("\\n", "\\r", "\\t")):
        return ""
    stripped = text.lstrip()
    if stripped[:1] not in ("{", "["):
        return ""
    try:
        doc = json.loads(stripped)
    except (ValueError, RecursionError):
        return ""
    leaves = [v for _k, v in _walk_json(doc) if isinstance(v, str) and v]
    return "\n".join(leaves) if leaves else ""


def _views(label, text):
    """Yield a field's text and, when it is JSON, its unescaped leaves."""
    yield label, text
    leaves = _json_view(text)
    if leaves:
        yield f"{label}#json", leaves[:_MAX_FIELD]


def request_inputs(row):
    """Yield (label, text) for request-side inputs.

    Emits the URL-decoded field, plus a "#decoded" view holding the base64/hex
    plaintext recovered at import time, so pattern checks get encoding coverage,
    plus a "#json" view of the unescaped string leaves when the field is JSON.
    """
    for label, col in _REQUEST_FIELDS:
        val = row[col]
        if val:
            yield from _views(label, unquote_plus(str(val)[:_MAX_FIELD]))
        dec = _decoded_for(row, col)
        if dec:
            yield from _views(f"{label}#decoded", dec[:_MAX_FIELD])


def iter_fields(row):
    """Yield (label, text) per scannable field, plus its "#decoded"/"#json" views.

    A binary response body is skipped: it is stored as a lossy decode of the
    bytes, so every check would pay for the corpus's images and fonts to match
    noise in them.
    """
    binary = _binary_response(row)
    for label, col in _SCAN_FIELDS:
        if binary and col == "response_body":
            continue
        val = row[col]
        if val:
            text = val if isinstance(val, str) else str(val)
            yield from _views(label, text[:_MAX_FIELD])
        dec = _decoded_for(row, col)
        if dec:
            yield from _views(f"{label}#decoded", dec[:_MAX_FIELD])


def response_text(row):
    """Return concatenated response headers+body (for error/result matching)."""
    parts = []
    binary = _binary_response(row)
    for _, col in _RESPONSE_FIELDS:
        if binary and col == "response_body":
            continue
        val = row[col]
        if val:
            parts.append(str(val)[:_MAX_FIELD])
    return "\n".join(parts)


def _status(row):
    try:
        return int(row["response_status_code"])
    except (ValueError, TypeError):
        return None


# --------------------------------------------------------------------------- #
# base64 / entropy helpers
# --------------------------------------------------------------------------- #

_B64_TOKEN = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_B64URL_TOKEN = re.compile(r"[A-Za-z0-9_-]{16,}")


def _b64_decode_variants(tok: str):
    """Try standard and url-safe base64; return decoded bytes or None."""
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            pad = "=" * (-len(tok) % 4)
            raw = decoder(tok + pad)
            if raw:
                return raw
        except (ValueError, binascii.Error):
            continue
    return None


def b64_blobs(text: str):
    """Yield (token, decoded_bytes) for base64-ish tokens, deduped by content."""
    seen_tokens, seen_decoded = set(), set()
    for rx in (_B64_TOKEN, _B64URL_TOKEN):
        for m in rx.finditer(text):
            tok = m.group(0)
            if tok in seen_tokens or len(tok) < 16:
                continue
            seen_tokens.add(tok)
            raw = _b64_decode_variants(tok)
            if raw and raw not in seen_decoded:
                seen_decoded.add(raw)
                yield tok, raw


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _walk_json(obj, prefix=""):
    """Yield (key_path, leaf_value) pairs from nested JSON."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, (dict, list)):
                yield from _walk_json(v, key)
            else:
                yield key, v
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            key = f"{prefix}[{i}]"
            if isinstance(v, (dict, list)):
                yield from _walk_json(v, key)
            else:
                yield key, v


def request_param_values(row):
    """Yield (location, value) for individual request parameter values."""
    if row["query"]:
        for k, v in parse_qsl(row["query"], keep_blank_values=True):
            if v:
                yield f"query:{k}", v
    body = row["body"]
    if body:
        b = body.strip()
        if b[:1] in "{[":
            try:
                for k, v in _walk_json(json.loads(b)):
                    if isinstance(v, str) and v:
                        yield f"body:{k.split('.')[-1].split('[')[0]}", v
            except (ValueError, TypeError):
                pass
        else:
            for k, v in parse_qsl(b, keep_blank_values=True):
                if v:
                    yield f"body:{k}", v


# --------------------------------------------------------------------------- #
# Shared helpers for the remaining checks
# --------------------------------------------------------------------------- #


def _parse_headers(blob):
    out = []
    if not blob:
        return out
    for line in str(blob).splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            out.append((k.strip(), v.strip()))
    return out


def _header_map(blob):
    return {k.lower(): v for k, v in _parse_headers(blob)}


def _b64url_json(seg):
    try:
        pad = "=" * (-len(seg) % 4)
        return json.loads(base64.urlsafe_b64decode(seg + pad))
    except Exception:  # noqa: BLE001 - any malformed JWT segment is simply not a JWT
        return None


def jwt_claims(token, limit=90):
    """The claims that make a token what it is, compact enough for a detail line.

    Two tokens for one subject can be identical for the first 60 characters —
    same header, same opening claims — so the evidence snippet cannot tell them
    apart. What separates them (a `type` of access vs refresh, an audience, a
    scope) sits further in, and without it the report shows two findings that
    look like one reported twice.
    """
    parts = token.split(".")
    payload = _b64url_json(parts[1]) if len(parts) > 1 else None
    if not isinstance(payload, dict):
        return ""
    claims = {k: v for k, v in payload.items() if k not in _JWT_VOLATILE_CLAIMS}
    if not claims:
        return ""
    text = ", ".join(f"{k}={v}" for k, v in claims.items())
    return text if len(text) <= limit else text[:limit] + "…"


def _emit(
    out, check, sev, sig, r, location, evidence, detail, host_level=False, group=None
):
    out.append(
        Finding(
            check,
            sev,
            sig,
            r["host"],
            r["method"],
            "" if host_level else r["path"],
            location,
            _snippet(evidence),
            detail,
            group=group,
        )
    )


def _snippet(s: str, n: int = 60) -> str:
    s = s.replace("\n", "\\n")
    return s if len(s) <= n else s[:n] + "…"


def _dedupe(findings):
    """Collapse repeats, keeping every path the survivor stood for.

    A finding with a `group` merges across paths: one row per distinct thing
    found, carrying the list of paths it was seen on. Without one, `key()`
    already includes the path, so nothing merges and `paths` is just that path.
    """
    seen, out = {}, []
    for f in findings:
        k = (f.check, f.signature, f.host, f.group) if f.group else f.key()
        first = seen.get(k)
        where = f"{f.method} {f.path}".strip()
        if first is None:
            seen[k] = f
            f.paths = [where] if f.path else []
            out.append(f)
        elif f.path and where not in first.paths:
            first.paths.append(where)
    for f in out:
        f.paths.sort()
    return out
