"""Check 1: deserialization / serialized-object payloads"""

from __future__ import annotations

import re
from urllib.parse import unquote_plus

from cru.checks.base import Finding, _dedupe, _snippet, b64_blobs, iter_fields

# Raw-string signatures: (family, compiled regex, severity, detail)
_DESER_STRING_SIGS = [
    (
        "php-serialized-object",
        re.compile(r'O:\d+:"[^"]+":\d+:\{'),
        "high",
        'PHP serialized object (O:len:"class":...) — insecure unserialize()/POP chain',
    ),
    (
        "php-serialized-array",
        re.compile(r"a:\d+:\{[si]:\d+"),
        "review",
        "PHP serialized array — often benign, but an unserialize() sink",
    ),
    (
        "phar-wrapper",
        re.compile(r"phar://"),
        "high",
        "phar:// stream wrapper — PHAR deserialization",
    ),
    (
        "node-serialize-rce",
        re.compile(r"_\$\$ND_FUNC\$\$_"),
        "high",
        "node-serialize IIFE marker — RCE on unserialize()",
    ),
    (
        "java-xmldecoder",
        re.compile(r"<(?:java|object\s+class=)", re.IGNORECASE),
        "high",
        "Java XMLDecoder / bean XML — RCE via <object class=...>",
    ),
    (
        "jackson-fastjson-polymorphic",
        re.compile(r'"@(?:type|class)"\s*:'),
        "high",
        "Polymorphic type hint (@type/@class) — Jackson/fastjson gadget vector",
    ),
    (
        "yaml-object-tag",
        re.compile(r"!!?(?:python/object|ruby/object|javax\.|com\.|java\.)"),
        "high",
        "YAML language/object tag — unsafe load() gadget",
    ),
    (
        "dotnet-viewstate-param",
        re.compile(r"__VIEWSTATE=|__VIEWSTATEGENERATOR="),
        "medium",
        "ASP.NET __VIEWSTATE — check for missing MAC (ViewState deserialization)",
    ),
    (
        "java-serialized-b64",
        re.compile(r"\brO0AB[A-Za-z0-9+/]"),
        "high",
        "Java serialized object, base64 (magic AC ED 00 05)",
    ),
    (
        "dotnet-binaryformatter-b64",
        re.compile(r"AAEAAAD/////"),
        "high",
        "..NET BinaryFormatter header, base64 (00 01 00 00 00 FF FF FF FF)",
    ),
    (
        "ruby-marshal-b64",
        re.compile(r"\bBAh[A-Za-z0-9+/]{8,}"),
        "medium",
        "Ruby Marshal blob, base64 (magic 04 08)",
    ),
    (
        "java-serialized-content-type",
        re.compile(r"application/x-java-serialized-object", re.IGNORECASE),
        "high",
        "Content-Type advertises a Java serialized object",
    ),
]

# Magic-byte signatures checked against base64-DECODED blobs.
_DESER_MAGIC_SIGS = [
    (
        "java-serialized",
        b"\xac\xed\x00\x05",
        "high",
        "Java serialized object magic (decoded)",
    ),
    (
        "dotnet-binaryformatter",
        b"\x00\x01\x00\x00\x00\xff\xff\xff\xff",
        "high",
        ".NET BinaryFormatter magic (decoded)",
    ),
    ("ruby-marshal", b"\x04\x08", "medium", "Ruby Marshal magic (decoded)"),
    (
        "gzip-wrapped-blob",
        b"\x1f\x8b",
        "review",
        "gzip stream (decoded) — decompress and re-check for a nested payload",
    ),
]

_PICKLE_OPCODES = (
    b"c__builtin__",
    b"cos\nsystem",
    b"cposix\nsystem",
    b"csubprocess",
    b"cnt\nsystem",
    b"\x80\x02",
    b"\x80\x03",
    b"\x80\x04",
    b"\x80\x05",
)


def _looks_pickle(raw: bytes) -> bool:
    head = raw[:2]
    if head[:1] == b"\x80" and head[1:2] in (b"\x02", b"\x03", b"\x04", b"\x05"):
        return True
    return any(op in raw[:64] for op in _PICKLE_OPCODES)


class DeserializationScanner:
    name = "deser"

    def run(self, rows):
        out = []
        for r in rows:
            for label, text in iter_fields(r):
                probe = unquote_plus(text)
                # raw-string signatures
                for fam, rx, sev, detail in _DESER_STRING_SIGS:
                    m = rx.search(probe)
                    if m:
                        out.append(
                            Finding(
                                self.name,
                                sev,
                                fam,
                                r["host"],
                                r["method"],
                                r["path"],
                                label,
                                _snippet(m.group(0)),
                                detail,
                            )
                        )
                # base64 magic-byte signatures
                for tok, raw in b64_blobs(probe):
                    for fam, magic, sev, detail in _DESER_MAGIC_SIGS:
                        if raw.startswith(magic):
                            out.append(
                                Finding(
                                    self.name,
                                    sev,
                                    fam,
                                    r["host"],
                                    r["method"],
                                    r["path"],
                                    label,
                                    _snippet(tok),
                                    detail,
                                )
                            )
                    if _looks_pickle(raw):
                        out.append(
                            Finding(
                                self.name,
                                "high",
                                "python-pickle",
                                r["host"],
                                r["method"],
                                r["path"],
                                label,
                                _snippet(tok),
                                "Python pickle opcodes (decoded) — RCE on loads()",
                            )
                        )
        return _dedupe(out)
