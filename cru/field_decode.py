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
"""

from __future__ import annotations

import base64
import binascii
import re

_MAX = 400_000

_B64_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}|[A-Za-z0-9_-]{16,}")
_HEX_PCT_RE = re.compile(r"(?:%[0-9A-Fa-f]{2}){6,}")
_HEX_RUN_RE = re.compile(r"\b(?:0x)?[0-9A-Fa-f]{16,}\b")
_PRINTABLE = re.compile(rb"[\x09\x0a\x0d\x20-\x7e]")


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


def decoded_view(text) -> str:
    """Return the concatenated decoded plaintext of base64/hex tokens in text.

    Returns "" when there is nothing worth decoding. Safe on None. This is the
    single entry point importers call per field.
    """
    if not text:
        return ""
    text = str(text)[:_MAX]
    parts = list(_iter_decoded(text))
    return "\n".join(parts)[:_MAX] if parts else ""
