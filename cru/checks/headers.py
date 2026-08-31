"""Check 15: missing / weak response security headers (host-level)"""

from __future__ import annotations

import re

from cru.checks.base import _dedupe, _emit, _header_map, _status


class SecurityHeadersScanner:
    name = "headers"

    def run(self, rows):
        out = []
        for r in rows:
            status = _status(r)
            if status is None or not (200 <= status < 400) or not r["response_body"]:
                continue
            hm = _header_map(r["response_headers"])
            ct = hm.get("content-type", "").lower()
            is_html = "text/html" in ct

            if r["is_tls"] and "strict-transport-security" not in hm:
                _emit(
                    out,
                    self.name,
                    "medium",
                    "missing-hsts",
                    r,
                    "response-headers",
                    "Strict-Transport-Security",
                    "HTTPS response without HSTS",
                    host_level=True,
                )
            if not is_html:
                continue
            csp = hm.get("content-security-policy", "")
            if not csp:
                _emit(
                    out,
                    self.name,
                    "medium",
                    "missing-csp",
                    r,
                    "response-headers",
                    "Content-Security-Policy",
                    "HTML response without a CSP",
                    host_level=True,
                )
            elif re.search(r"unsafe-inline|unsafe-eval|(?:^|\s)\*(?:\s|;|$)", csp):
                _emit(
                    out,
                    self.name,
                    "medium",
                    "weak-csp",
                    r,
                    "response-headers",
                    csp,
                    "CSP allows unsafe-inline/unsafe-eval/wildcard",
                    host_level=True,
                )
            if "x-frame-options" not in hm and "frame-ancestors" not in csp:
                _emit(
                    out,
                    self.name,
                    "medium",
                    "missing-frame-protection",
                    r,
                    "response-headers",
                    "X-Frame-Options/frame-ancestors",
                    "no clickjacking protection",
                    host_level=True,
                )
            if "x-content-type-options" not in hm:
                _emit(
                    out,
                    self.name,
                    "low",
                    "missing-nosniff",
                    r,
                    "response-headers",
                    "X-Content-Type-Options",
                    "missing nosniff",
                    host_level=True,
                )
            if "referrer-policy" not in hm:
                _emit(
                    out,
                    self.name,
                    "low",
                    "missing-referrer-policy",
                    r,
                    "response-headers",
                    "Referrer-Policy",
                    "missing",
                    host_level=True,
                )
            if "permissions-policy" not in hm:
                _emit(
                    out,
                    self.name,
                    "low",
                    "missing-permissions-policy",
                    r,
                    "response-headers",
                    "Permissions-Policy",
                    "missing",
                    host_level=True,
                )
        return _dedupe(out)
