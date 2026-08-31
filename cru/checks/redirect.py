"""Check 10: Open redirect — redirect params + Location reflection"""

from __future__ import annotations

import re

from cru.checks.base import _dedupe, _emit, _header_map, _status, request_param_values

_REDIRECT_PARAM = {
    "next",
    "return",
    "returnurl",
    "returnto",
    "return_url",
    "redirect",
    "redirect_uri",
    "redirect_url",
    "url",
    "dest",
    "destination",
    "continue",
    "goto",
    "out",
    "target",
    "r",
    "u",
    "forward",
    "callback",
    "link",
    "to",
    "checkout_url",
    "success_url",
    "cancel_url",
    "back",
    "backurl",
}
_OFFSITE = re.compile(r"(?i)^(?:https?:)?//|^https?:\\|^/\\|^\\/|^https?://")


class OpenRedirectScanner:
    name = "redirect"

    def run(self, rows):
        out = []
        for r in rows:
            status = _status(r)
            location = _header_map(r["response_headers"]).get("location", "")
            for loc, val in request_param_values(r):
                pname = loc.split(":")[-1].lower()
                if pname not in _REDIRECT_PARAM:
                    continue
                if not _OFFSITE.match(val.strip()):
                    continue
                if status and 300 <= status < 400 and val.strip() in location:
                    _emit(
                        out,
                        self.name,
                        "high",
                        "open-redirect-reflected",
                        r,
                        loc,
                        val,
                        "redirect param reflected into 3xx Location — " "open redirect",
                    )
                else:
                    _emit(
                        out,
                        self.name,
                        "medium",
                        "open-redirect-candidate",
                        r,
                        loc,
                        val,
                        "offsite URL in a redirect param — test for " "open redirect",
                    )
        return _dedupe(out)
