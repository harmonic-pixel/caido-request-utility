"""Check 24: missing CSRF protection (heuristic)"""

from __future__ import annotations

import re

from cru.checks.base import _dedupe, _emit

_STATE_CHANGING = {"POST", "PUT", "DELETE", "PATCH"}
_CSRF_TOKEN = re.compile(
    r"(?i)csrf|xsrf|authenticity_token|__requestverification|"
    r"_token\b|anti.?forgery|request_?token"
)


class CsrfScanner:
    name = "csrf"

    def run(self, rows):
        out = []
        for r in rows:
            if (r["method"] or "").upper() not in _STATE_CHANGING:
                continue
            if not r["cookies"]:
                continue  # no cookie-based session -> CSRF less relevant
            hay = " ".join(filter(None, [r["query"], r["body"], r["headers"]]))
            if _CSRF_TOKEN.search(hay):
                continue
            _emit(
                out,
                self.name,
                "review",
                "missing-csrf-token",
                r,
                "request",
                f"{r['method']} {r['path']}",
                "state-changing cookie-authenticated request with no visible "
                "CSRF token — verify anti-CSRF protection",
            )
        return _dedupe(out)
