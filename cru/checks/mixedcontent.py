"""Check 22: mixed content (HTTP resources on an HTTPS page)"""

from __future__ import annotations

import re

from cru.checks.base import _dedupe, _emit, _header_map

_MIXED = re.compile(r"(?i)(?:src|href|action)\s*=\s*[\"']http://[^\"']+")


class MixedContentScanner:
    name = "mixedcontent"

    def run(self, rows):
        out = []
        for r in rows:
            if not r["is_tls"]:
                continue
            ct = _header_map(r["response_headers"]).get("content-type", "").lower()
            if "text/html" not in ct:
                continue
            m = _MIXED.search(r["response_body"] or "")
            if m:
                _emit(
                    out,
                    self.name,
                    "medium",
                    "mixed-content",
                    r,
                    "response-body",
                    m.group(0),
                    "HTTP sub-resource referenced from an HTTPS page",
                    host_level=True,
                )
        return _dedupe(out)
