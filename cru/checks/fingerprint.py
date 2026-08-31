"""Check 20: technology / version fingerprint disclosure (host-level)"""

from __future__ import annotations

import re

from cru.checks.base import _dedupe, _emit, _parse_headers

_BANNER_HEADERS = (
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
    "x-runtime",
    "x-drupal-cache",
    "x-varnish",
)
_VERSIONED = re.compile(r"\d+\.\d+")
_FRAMEWORK_COOKIE = re.compile(
    r"(?i)^(PHPSESSID|JSESSIONID|ASP\.NET_SessionId|ASPSESSIONID|laravel_session|"
    r"connect\.sid|_rails|CFID|CFTOKEN|symfony|django_|csrftoken|_session_id)"
)


class FingerprintScanner:
    name = "fingerprint"

    def run(self, rows):
        out = []
        for r in rows:
            for k, v in _parse_headers(r["response_headers"]):
                lk = k.lower()
                if lk in _BANNER_HEADERS and v:
                    sev = "low" if _VERSIONED.search(v) else "review"
                    _emit(
                        out,
                        self.name,
                        sev,
                        f"banner:{lk}",
                        r,
                        "response-headers",
                        f"{k}: {v}",
                        "server/framework version banner exposed"
                        + (" (version disclosed)" if sev == "low" else ""),
                        host_level=True,
                    )
                if lk == "set-cookie":
                    name = v.split("=", 1)[0].strip()
                    if _FRAMEWORK_COOKIE.match(name):
                        _emit(
                            out,
                            self.name,
                            "review",
                            "framework-cookie",
                            r,
                            "set-cookie",
                            name,
                            f"framework fingerprint via cookie '{name}'",
                            host_level=True,
                        )
        return _dedupe(out)
