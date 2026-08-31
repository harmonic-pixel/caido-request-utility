"""Check 17: cookie flags (from Set-Cookie)"""

from __future__ import annotations

import re

from cru.checks.base import _dedupe, _emit, _parse_headers

# NOTE: idox collapses duplicate headers, so multiple Set-Cookie lines may not
# all survive in this corpus — treat absence of a cookie as "not observed".

_SESSION_COOKIE = re.compile(r"(?i)sess|sid|token|auth|jwt|login|remember|csrf")


class CookieScanner:
    name = "cookies"

    def run(self, rows):
        out = []
        for r in rows:
            for k, v in _parse_headers(r["response_headers"]):
                if k.lower() != "set-cookie":
                    continue
                name = v.split("=", 1)[0].strip()
                low = v.lower()
                sessionish = bool(_SESSION_COOKIE.search(name))
                if "httponly" not in low and sessionish:
                    _emit(
                        out,
                        self.name,
                        "medium",
                        "cookie-no-httponly",
                        r,
                        "set-cookie",
                        name,
                        f"session-like cookie '{name}' without HttpOnly",
                        host_level=True,
                    )
                if r["is_tls"] and "secure" not in low:
                    _emit(
                        out,
                        self.name,
                        "medium" if sessionish else "low",
                        "cookie-no-secure",
                        r,
                        "set-cookie",
                        name,
                        f"cookie '{name}' without Secure over HTTPS",
                        host_level=True,
                    )
                if "samesite" not in low:
                    _emit(
                        out,
                        self.name,
                        "low",
                        "cookie-no-samesite",
                        r,
                        "set-cookie",
                        name,
                        f"cookie '{name}' without SameSite",
                        host_level=True,
                    )
        return _dedupe(out)
