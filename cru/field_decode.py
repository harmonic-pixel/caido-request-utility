"""
field_decode.py — surface decoded (base64 / hex) plaintext from HTTP fields.

Payloads are often wrapped in base64 or hex to slip past a naive scan. This
module finds such tokens in a field and returns the decoded plaintext, so the
pattern checks can match against it. Decoding is done ONCE at import time (the
importers store the result in dedicated `*_decoded` columns), not per-check, so
all checks share the work.

`decoded_view(text)` returns a single string that concatenates the decoded
plaintext of every base64/hex token found in `text` (empty string if none). We
concatenate rather than keep per-token views because the checks only need the
plaintext to be *present* somewhere scannable; storing one string per field
keeps the schema simple and the scan fast.

JWTs get one extra step. A token is base64 all the way down, but it reads as a
single opaque blob to the passes below — and when it arrives wrapped inside
another base64 field it survives the one decode layer intact. So the decoded
view also carries every JWT rewritten as its decoded parts, still dot-separated:
`{"alg": "HS256", ...}.{"sub": "42", ...}.<signature>`. The claims are then
plain text, both to a check and to a reader of the report's decoded pane.
"""

from __future__ import annotations

import base64
import binascii
import json
import re

_MAX = 400_000

_B64_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}|[A-Za-z0-9_-]{16,}")
_HEX_PCT_RE = re.compile(r"(?:%[0-9A-Fa-f]{2}){6,}")
_HEX_RUN_RE = re.compile(r"\b(?:0x)?[0-9A-Fa-f]{16,}\b")
_PRINTABLE = re.compile(rb"[\x09\x0a\x0d\x20-\x7e]")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*")
# Bound the work per field: a response can carry a great many tokens.
_MAX_JWTS = 64


def _b64_decode_variants(tok: str):
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            pad = "=" * (-len(tok) % 4)
            raw = decoder(tok + pad)
            if raw:
                return raw
        except (ValueError, binascii.Error):
            continue
    return None


def _mostly_printable(b: bytes, threshold=0.85) -> bool:
    if not b:
        return False
    return len(_PRINTABLE.findall(b)) / len(b) >= threshold


def _iter_decoded(text: str):
    """Yield decoded plaintext strings for base64/hex tokens that look real."""
    if not text:
        return
    seen = {text}

    for m in _B64_RE.finditer(text):
        raw = _b64_decode_variants(m.group(0))
        if raw and len(raw) >= 4 and _mostly_printable(raw):
            dec = raw.decode("utf-8", "replace")
            if dec not in seen and any(
                not c.isspace() and c.isprintable() for c in dec
            ):
                seen.add(dec)
                yield dec

    for m in _HEX_PCT_RE.finditer(text):
        raw = bytes(int(h, 16) for h in re.findall(r"%([0-9A-Fa-f]{2})", m.group(0)))
        if raw and len(raw) >= 4 and _mostly_printable(raw):
            dec = raw.decode("utf-8", "replace")
            if dec not in seen:
                seen.add(dec)
                yield dec

    for m in _HEX_RUN_RE.finditer(text):
        tok = m.group(0)
        h = tok[2:] if tok.lower().startswith("0x") else tok
        if len(h) % 2:
            continue
        try:
            raw = bytes.fromhex(h)
        except ValueError:
            continue
        if raw and len(raw) >= 4 and _mostly_printable(raw):
            dec = raw.decode("utf-8", "replace")
            if dec not in seen:
                seen.add(dec)
                yield dec


def _jwt_view(token: str) -> str | None:
    """Rewrite a JWT as its decoded parts, still dot-separated.

    Returns None when either segment is not base64url JSON — that is not a JWT,
    whatever it looked like, and the raw token is better left alone.
    """
    parts = token.split(".")
    decoded = []
    for seg in parts[:2]:
        try:
            claims = json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))
        except (ValueError, binascii.Error):
            return None
        if not isinstance(claims, dict):
            return None
        # Not sorted: the claim order a token was minted with is worth keeping.
        decoded.append(json.dumps(claims, ensure_ascii=False))
    # The signature is not JSON and stays as it is.
    return ".".join(decoded + parts[2:])


def _jwt_views(sources) -> list[str]:
    """Expanded views of every JWT across the field and what it decoded to."""
    out, seen = [], set()
    for src in sources:
        for m in _JWT_RE.finditer(src):
            token = m.group(0)
            if token in seen:
                continue
            seen.add(token)
            view = _jwt_view(token)
            if view:
                out.append(view)
            if len(seen) >= _MAX_JWTS:
                return out
    return out


def decoded_view(text) -> str:
    """Return the concatenated decoded plaintext of base64/hex tokens in text.

    Returns "" when there is nothing worth decoding. Safe on None. This is the
    single entry point importers call per field.
    """
    if not text:
        return ""
    text = str(text)[:_MAX]
    parts = list(_iter_decoded(text))
    # Over the decoded parts too: a JWT wrapped in an outer base64 field comes
    # out of that layer still a token, so this is where it becomes readable.
    parts += _jwt_views([text] + parts)
    return "\n".join(parts)[:_MAX] if parts else ""
