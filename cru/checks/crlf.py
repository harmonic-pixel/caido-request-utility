"""Check 12: CRLF / HTTP header injection payloads (request-side)"""

from __future__ import annotations

import re

from cru.checks.base import _REQUEST_FIELDS, _dedupe, _emit

# NOTE: idox parses response headers into a dict, so injected/duplicate headers
# collapse in this corpus — response-side confirmation is unreliable here. This
# flags the request-side probe only.

_CRLF = re.compile(
    r"(?i)%0d%0a|%0a%0d|%0d%0A|\r\n|%23%0a|%e5%98%8a|%e5%98%8d|" r"\u2028|\u2029"
)


class CrlfScanner:
    name = "crlf"

    def run(self, rows):
        out = []
        for r in rows:
            for label, col in _REQUEST_FIELDS:
                val = r[col]
                if not val:
                    continue
                m = _CRLF.search(str(val))
                if m:
                    _emit(
                        out,
                        self.name,
                        "medium",
                        "crlf-injection-payload",
                        r,
                        label,
                        m.group(0),
                        "CR/LF sequence in request input — header-injection / "
                        "response-splitting probe (confirm out-of-band)",
                    )
        return _dedupe(out)
