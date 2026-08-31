"""Shared primitives every check builds on.

`Finding` and the field-access helpers are the seam described in CLAUDE.md:
checks read rows through `request_inputs`, `iter_fields`, `request_param_values`
and `response_text` rather than touching columns directly, so encoding coverage
and the corpus limits stay in one place.
"""

from __future__ import annotations

import base64
import binascii
import json
import math
import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, unquote_plus

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

    def key(self):
        return (
            self.check,
            self.signature,
            self.host,
            self.path,
            self.location,
            self.evidence,
        )


def Finding(
    check, severity, signature, host, method, path, location, evidence, detail=""
):
    """Construct a finding.

    `severity` is still accepted so the individual checks don't need changing,
    but it is intentionally discarded — this tool does not rank findings by
    severity. Everything downstream (dedup, output, report) ignores it.
    """
    return _Finding(check, signature, host, method, path, location, evidence, detail)


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


def request_inputs(row):
    """Yield (label, text) for request-side inputs.

    Emits the URL-decoded field, plus a "#decoded" view holding the base64/hex
    plaintext recovered at import time, so pattern checks get encoding coverage.
    """
    for label, col in _REQUEST_FIELDS:
        val = row[col]
        if val:
            yield label, unquote_plus(str(val)[:_MAX_FIELD])
        dec = _decoded_for(row, col)
        if dec:
            yield f"{label}#decoded", dec[:_MAX_FIELD]


def iter_fields(row):
    """Yield (label, text) for each scannable field, plus its "#decoded" view."""
    for label, col in _SCAN_FIELDS:
        val = row[col]
        if val:
            text = val if isinstance(val, str) else str(val)
            yield label, text[:_MAX_FIELD]
        dec = _decoded_for(row, col)
        if dec:
            yield f"{label}#decoded", dec[:_MAX_FIELD]


def response_text(row):
    """Return concatenated response headers+body (for error/result matching)."""
    parts = []
    for _, col in _RESPONSE_FIELDS:
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


def _emit(out, check, sev, sig, r, location, evidence, detail, host_level=False):
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
        )
    )


def _snippet(s: str, n: int = 60) -> str:
    s = s.replace("\n", "\\n")
    return s if len(s) <= n else s[:n] + "…"


def _dedupe(findings):
    seen, out = set(), []
    for f in findings:
        k = f.key()
        if k not in seen:
            seen.add(k)
            out.append(f)
    return out
