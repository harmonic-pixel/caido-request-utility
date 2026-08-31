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

Unwrapping repeats: what a token decodes to is scanned again, so base64 of hex
of the payload comes out as plaintext rather than as one more opaque blob. It
is bounded by a depth cap, a cap on decode attempts per field, and the set of
plaintexts already seen — see `_iter_decoded`.

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

# Eight base64 characters is six bytes — enough for `_decoded_text` to judge
# what came out. Shorter than that, the padding has to say so: `YWRtaW4=` is
# "admin", where a bare `answer` is indistinguishable from any other word. Six
# is the floor even padded, below which there are three bytes to go on.
_B64_RE = re.compile(
    r"[A-Za-z0-9+/]{8,}={0,2}|[A-Za-z0-9_-]{8,}|[A-Za-z0-9+/_-]{6,7}={1,2}"
)
_HEX_PCT_RE = re.compile(r"(?:%[0-9A-Fa-f]{2}){6,}")
# Hex keeps its longer floor: eight hex characters is four bytes, too few to
# judge, and a minified bundle is full of eight-digit hex runs — measured on a
# 565-request corpus, dropping this floor bought fourteen junk decodes and no
# real one.
_HEX_RUN_RE = re.compile(r"\b(?:0x)?[0-9A-Fa-f]{16,}\b")
_PRINTABLE = re.compile(rb"[\x09\x0a\x0d\x20-\x7e]")
# The canonical "where are the JWTs" patterns, shared with the checks so the
# scanner and the decoder always agree on what counts as a token.
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*")
# The form `_jwt_view` writes: two JSON dictionaries and a signature. Greedy
# to the last `}` on the line, anchored on the header's alg claim; a line
# holding two expanded tokens matches as one, which is harmless — everything
# between them is JWT either way.
JWT_DECODED_RE = re.compile(r'\{"alg":.*\}\.[A-Za-z0-9_-]*')
# Bound the work per field: a response can carry a great many tokens.
_MAX_JWTS = 64
# How many layers of wrapping to unwrap (base64 of hex of the payload is two),
# and how many decode attempts the layers *below the first* are worth per field.
# The first layer is the scan that has always happened and stays uncapped —
# `_MAX_FIELD` already bounds it, and cutting it short would lose coverage that
# predates the unwrapping. What recursion adds is small: over a 565-request
# corpus the busiest field spent 24 attempts below the first layer, and 99% of
# fields spent eight or fewer.
_MAX_DEPTH = 4
_MAX_NESTED_DECODES = 500


def _b64_decode(tok: str):
    """Decode a token in whichever base64 alphabet it is written in.

    `b64decode` does not validate: hand it a url-safe token and it drops the
    `-`/`_` and decodes the rest into bytes that were never there.
    """
    decoder = (
        base64.urlsafe_b64decode if ("-" in tok or "_" in tok) else base64.b64decode
    )
    try:
        return decoder(tok + "=" * (-len(tok) % 4)) or None
    except (ValueError, binascii.Error):
        return None


def _mostly_printable(b: bytes, threshold=0.85) -> bool:
    if not b:
        return False
    return len(_PRINTABLE.findall(b)) / len(b) >= threshold


# A short decode cannot be judged by how printable it is: any six-letter word is
# valid base64, and "answer" decodes to `j{0z` — four printable characters of
# nothing. So a short one has to *read* as a value: printable ASCII throughout,
# nothing but the characters a value is written with, and one of the marks that
# says text rather than noise — a three-letter run, a bare number, a `key=`, a
# path, a tag, the opening of a JSON document or a URL.
_SHORT_DECODE = 12
_VALUE_CHARS = re.compile(r"^[\w .,:;/@+=&?%$#!*()\[\]{}<>'\"~^|\\-]+$")
_READS_AS_TEXT = re.compile(
    r"[{\[]\s*[\"']|://|\.\./|<[A-Za-z/]|[a-z]{3}|[A-Z]{3}|^\d+$|\w="
)


def _decoded_text(raw: bytes) -> str | None:
    """The plaintext `raw` stands for, or None when it is not worth carrying.

    The length of the *token* says nothing — a wrapped payload is as short as
    the value someone wrapped — so the decision is made on the bytes that came
    out of it.
    """
    if not raw or len(raw) < 4:
        return None
    if len(raw) >= _SHORT_DECODE:
        if not _mostly_printable(raw):
            return None
        text = raw.decode("utf-8", "replace")
        return text if any(not c.isspace() and c.isprintable() for c in text) else None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not text.isascii() or not all(c.isprintable() or c in "\t\n\r" for c in text):
        return None
    if not _VALUE_CHARS.match(text) or not _READS_AS_TEXT.search(text):
        return None
    return text


def _decode_layer(text: str, budget: list[int] | None):
    """Yield the plaintext of every base64/hex token in one pass over `text`.

    `budget` is the remaining decode attempts, or None for the first layer,
    which is not on a budget.
    """
    for m in _B64_RE.finditer(text):
        if budget is not None:
            if budget[0] <= 0:
                return
            budget[0] -= 1
        dec = _decoded_text(_b64_decode(m.group(0)) or b"")
        if dec:
            yield dec

    for m in _HEX_PCT_RE.finditer(text):
        if budget is not None:
            if budget[0] <= 0:
                return
            budget[0] -= 1
        raw = bytes(int(h, 16) for h in re.findall(r"%([0-9A-Fa-f]{2})", m.group(0)))
        dec = _decoded_text(raw)
        if dec:
            yield dec

    for m in _HEX_RUN_RE.finditer(text):
        if budget is not None and budget[0] <= 0:
            return
        tok = m.group(0)
        h = tok[2:] if tok.lower().startswith("0x") else tok
        if len(h) % 2:
            continue
        if budget is not None:
            budget[0] -= 1
        try:
            raw = bytes.fromhex(h)
        except ValueError:
            continue
        dec = _decoded_text(raw)
        if dec:
            yield dec


def _iter_decoded(text: str):
    """Yield decoded plaintext for the tokens in `text`, layer after layer.

    Wrapping twice is a way to get past a scanner that only unwraps once —
    base64 of hex of the payload reads as one opaque token either way — so each
    layer's plaintext is scanned again, breadth first, down to `_MAX_DEPTH`.

    What keeps that cheap: every layer is smaller than the token it came out
    of, so there is no cycle to fall into; `seen` drops a plaintext reached
    twice, which the overlapping alphabets make likely (a hex run is valid
    base64 too, so both branches can arrive at the same bytes); and the layers
    below the first draw on one budget for the whole field, so a response that
    carries a great many wrapped tokens cannot turn into a great deal of work.
    """
    if not text:
        return
    seen = {text}
    queue = [(text, 0)]
    budget = [_MAX_NESTED_DECODES]

    while queue:
        src, depth = queue.pop(0)
        for dec in _decode_layer(src, budget if depth else None):
            if dec in seen:
                continue
            seen.add(dec)
            yield dec
            if depth + 1 < _MAX_DEPTH:
                queue.append((dec, depth + 1))


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
        for m in JWT_RE.finditer(src):
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
