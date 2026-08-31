"""Check 8: XXE — XML external-entity indicators"""

from __future__ import annotations

from urllib.parse import unquote_plus

from cru.checks.base import (
    _MAX_FIELD,
    _REQUEST_FIELDS,
    Finding,
    _dedupe,
    _snippet,
    gate,
    response_body,
)

#
# Flags request inputs carrying XML entity/DOCTYPE constructs that enable XXE
# (external SYSTEM/PUBLIC entities, parameter entities, file:// and stream
# wrappers), and a response-side tell that a file read succeeded (/etc/passwd,
# win.ini). Scans both raw and URL-decoded input so encoding can't hide it.

_XXE_SIGS = [
    (
        "external-entity",
        gate(r"(?i)<!ENTITY\s+\S+\s+(?:SYSTEM|PUBLIC)\b", "<!entity"),
        "high",
        "external entity (SYSTEM/PUBLIC) declaration — XXE",
    ),
    (
        "parameter-entity",
        gate(r"(?i)<!ENTITY\s+%\s+\S+", "<!entity"),
        "high",
        "parameter entity — blind/OOB XXE vector",
    ),
    (
        "file-uri",
        gate(r"(?i)(?:SYSTEM|PUBLIC|href|src)[^\n]{0,40}?file://", "file://"),
        "high",
        "file:// URI in XML — local file read attempt",
    ),
    (
        "stream-wrapper",
        gate(
            r"(?i)php://filter|php://input|expect://|jar:|netdoc:|gopher://",
            "php://",
            "expect://",
            "jar:",
            "netdoc:",
            "gopher://",
        ),
        "high",
        "PHP/exotic stream wrapper — XXE/SSRF exfil vector",
    ),
    (
        "doctype-subset",
        gate(r"(?i)<!DOCTYPE\s+\S+\s*\[", "<!doctype"),
        "medium",
        "DOCTYPE with internal subset — entity-injection surface",
    ),
    (
        "doctype",
        gate(r"(?i)<!DOCTYPE\b", "<!doctype"),
        "review",
        "DOCTYPE declaration in input — XML entity surface",
    ),
]

# Response contents indicating a successful local file read (XXE/LFI/SSRF).
_XXE_FILE_DISCLOSURE = gate(
    r"root:.?:0:0:|\[fonts\]\r?\n|\[extensions\]\r?\n|" r"; for 16-bit app support",
    "root:",
    "[fonts]",
    "[extensions]",
    "; for 16-bit app support",
)


class XxeScanner:
    name = "xxe"

    def run(self, rows):
        out = []
        for r in rows:
            # scan request inputs in both raw and URL-decoded form
            raw_fields = []
            for label, col in _REQUEST_FIELDS:
                val = r[col]
                if val:
                    raw = str(val)[:_MAX_FIELD]
                    raw_fields.append((label, raw))
                    dec = unquote_plus(raw)
                    if dec != raw:
                        raw_fields.append((label, dec))

            for label, text in raw_fields:
                for name, rx, sev, detail in _XXE_SIGS:
                    m = rx.search(text)
                    if m:
                        out.append(
                            Finding(
                                self.name,
                                sev,
                                f"xxe:{name}",
                                r["host"],
                                r["method"],
                                r["path"],
                                label,
                                _snippet(m.group(0)),
                                detail,
                            )
                        )

            # response-side: file contents came back
            resp = response_body(r)
            m = _XXE_FILE_DISCLOSURE.search(resp)
            if m:
                out.append(
                    Finding(
                        self.name,
                        "high",
                        "xxe:file-disclosure",
                        r["host"],
                        r["method"],
                        r["path"],
                        "response",
                        _snippet(m.group(0)),
                        "local file contents in response — successful file read "
                        "(XXE/LFI/SSRF)",
                    )
                )
        return _dedupe(out)
