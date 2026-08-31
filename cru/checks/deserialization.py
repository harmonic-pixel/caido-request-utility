"""Check 1: deserialization / serialized-object payloads"""

from __future__ import annotations

from urllib.parse import unquote_plus

from cru.checks.base import (
    Finding,
    _dedupe,
    _snippet,
    b64_blobs,
    gate,
    iter_fields,
)

# Raw-string signatures: (family, compiled regex, severity, detail)
_DESER_STRING_SIGS = [
    (
        "php-serialized-object",
        gate(r'O:\d+:"[^"]+":\d+:\{', "o:"),
        "high",
        'PHP serialized object (O:len:"class":...) — insecure unserialize()/POP chain',
    ),
    (
        "php-serialized-array",
        gate(r"a:\d+:\{[si]:\d+", "a:"),
        "review",
        "PHP serialized array — often benign, but an unserialize() sink",
    ),
    (
        "phar-wrapper",
        gate(r"phar://", "phar://"),
        "high",
        "phar:// stream wrapper — PHAR deserialization",
    ),
    (
        "node-serialize-rce",
        gate(r"_\$\$ND_FUNC\$\$_", "nd_func"),
        "high",
        "node-serialize IIFE marker — RCE on unserialize()",
    ),
    (
        "java-xmldecoder",
        gate(r"(?i)<(?:java|object\s+class=)", "<java", "<object"),
        "high",
        "Java XMLDecoder / bean XML — RCE via <object class=...>",
    ),
    (
        "jackson-fastjson-polymorphic",
        gate(r'"@(?:type|class)"\s*:', '"@type"', '"@class"'),
        "high",
        "Polymorphic type hint (@type/@class) — Jackson/fastjson gadget vector",
    ),
    (
        "yaml-object-tag",
        gate(
            r"!!?(?:python/object|ruby/object|javax\.|com\.|java\.)",
            "!python/object",
            "!ruby/object",
            "!javax.",
            "!com.",
            "!java.",
        ),
        "high",
        "YAML language/object tag — unsafe load() gadget",
    ),
    (
        "dotnet-viewstate-param",
        gate(r"__VIEWSTATE=|__VIEWSTATEGENERATOR=", "__viewstate"),
        "medium",
        "ASP.NET __VIEWSTATE — check for missing MAC (ViewState deserialization)",
    ),
    (
        "java-serialized-b64",
        gate(r"\brO0AB[A-Za-z0-9+/]", "ro0ab"),
        "high",
        "Java serialized object, base64 (magic AC ED 00 05)",
    ),
    (
        "dotnet-binaryformatter-b64",
        gate(r"AAEAAAD/////", "aaeaaad/////"),
        "high",
        "..NET BinaryFormatter header, base64 (00 01 00 00 00 FF FF FF FF)",
    ),
    (
        "ruby-marshal-b64",
        gate(r"\bBAh[A-Za-z0-9+/]{8,}", "bah"),
        "medium",
        "Ruby Marshal blob, base64 (magic 04 08)",
    ),
    (
        "java-serialized-content-type",
        gate(r"(?i)application/x-java-serialized-object", "x-java-serialized-object"),
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
)

_PICKLE_PROTOS = (b"\x02", b"\x03", b"\x04", b"\x05")


def _looks_pickle(raw: bytes) -> bool:
    """Whether decoded bytes look like a pickle stream.

    A protocol-2+ pickle opens with PROTO (`\x80` + protocol) and closes with
    STOP (`.`). Both ends are required on purpose: those two opening bytes turn
    up constantly inside ordinary binary — roughly one blob in 16k — so matching
    them loose, anywhere in the first 64 bytes, flagged base64-ish URL segments
    as pickles. The textual opcodes below are distinctive enough to stand alone.
    """
    if raw[:1] == b"\x80" and raw[1:2] in _PICKLE_PROTOS:
        return raw.endswith(b".")
    return any(op in raw[:64] for op in _PICKLE_OPCODES)


class DeserializationScanner:
    name = "deserialization"

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
