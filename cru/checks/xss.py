"""Check 7: XSS — request payload vectors + unencoded reflection"""

from __future__ import annotations

import re

from cru.checks.base import (
    Finding,
    _dedupe,
    _snippet,
    request_inputs,
    request_param_values,
    response_body,
)

#
# Two signals: (1) request inputs carrying XSS payload syntax, tagged by vector;
# (2) reflection — a request parameter value echoed back in the response body.
# Reflection is the core passive XSS tell: if the value comes back with its
# dangerous characters UNENCODED, that's likely-exploitable reflected XSS; if
# encoded, it's noted only at review. Payload matches also escalate to high when
# the same payload string is found reflected in the response.

_XSS_PAYLOAD_SIGS = [
    ("script-tag", re.compile(r"(?i)<\s*script\b|<\s*/\s*script\s*>"), "high"),
    ("javascript-uri", re.compile(r"(?i)javascript:\s*\S"), "high"),
    (
        "tag-with-handler",
        re.compile(
            r"(?i)<\s*(?:img|svg|body|iframe|video|audio|details|math|object|embed|"
            r"input|marquee|form|isindex)\b[^>]{0,200}?\bon\w+\s*="
        ),
        "high",
    ),
    (
        "event-handler",
        re.compile(
            r"(?i)\bon(?:error|load|mouseover|click|focus|toggle|"
            r"animationstart|pointerover|beforetoggle)\s*="
        ),
        "medium",
    ),
    (
        "js-sink-call",
        re.compile(
            r"(?i)\b(?:alert|prompt|confirm)\s*\(|document\.(?:cookie|location|write)\b|"
            r"String\.fromCharCode\s*\("
        ),
        "medium",
    ),
    (
        "attribute-breakout",
        re.compile(r"(?:\"|')\s*>\s*<\s*\w|\"\s*on\w+\s*="),
        "medium",
    ),
    ("data-uri-html", re.compile(r"(?i)data:text/html"), "medium"),
    ("svg-math-vector", re.compile(r"(?i)<\s*svg\b|<\s*math\b"), "review"),
]

_XSS_SPECIAL = ("<", ">", '"')


class XssScanner:
    name = "xss"

    def run(self, rows):
        out = []
        for r in rows:
            resp_body = response_body(r)

            # (1) payload vectors in request inputs
            for label, text in request_inputs(r):
                for name, rx, sev in _XSS_PAYLOAD_SIGS:
                    m = rx.search(text)
                    if not m:
                        continue
                    frag = m.group(0)
                    # Reflection only counts as exploitable if the tag-forming
                    # characters (< >) themselves came back unencoded. Inert
                    # fragments like 'alert(' or 'onerror=' can reflect even when
                    # the surrounding < > were HTML-encoded, so they don't escalate.
                    dangerous = "<" in frag or ">" in frag
                    if dangerous and frag in resp_body:
                        out.append(
                            Finding(
                                self.name,
                                "high",
                                f"xss-payload-reflected:{name}",
                                r["host"],
                                r["method"],
                                r["path"],
                                label,
                                _snippet(frag),
                                "XSS payload reflected unencoded in response — "
                                "likely exploitable",
                            )
                        )
                    else:
                        out.append(
                            Finding(
                                self.name,
                                sev,
                                f"xss-payload:{name}",
                                r["host"],
                                r["method"],
                                r["path"],
                                label,
                                _snippet(frag),
                                "XSS payload syntax in request input — review",
                            )
                        )

            # (2) reflection of parameter values (independent of payload sigs)
            for loc, val in request_param_values(r):
                if len(val) < 4 or val not in resp_body:
                    continue
                has_special = any(c in val for c in _XSS_SPECIAL)
                if has_special:
                    out.append(
                        Finding(
                            self.name,
                            "high",
                            "reflected-unencoded-input",
                            r["host"],
                            r["method"],
                            r["path"],
                            loc,
                            _snippet(val),
                            "input reflected with dangerous chars unencoded — "
                            "reflected-XSS candidate",
                        )
                    )
                elif len(val) >= 8:
                    out.append(
                        Finding(
                            self.name,
                            "review",
                            "input-reflected",
                            r["host"],
                            r["method"],
                            r["path"],
                            loc,
                            _snippet(val),
                            "input reflected in response — check output context/encoding",
                        )
                    )
        return _dedupe(out)
