"""Check 9: SSRF — URLs / internal hosts / cloud metadata in request params"""

from __future__ import annotations

import re

from cru.checks.base import _dedupe, _emit, request_param_values

_SSRF_PARAM = re.compile(
    r"(?i)^(?:url|uri|u|link|href|src|dest|destination|redirect|redirect_uri|"
    r"next|return|returnurl|returnto|continue|goto|out|target|callback|webhook|"
    r"proxy|fetch|feed|rss|load|image|imageurl|img|file|path|domain|host|site|"
    r"data|source|view|remote|upstream|forward|open|to|uri2|url2)$"
)
_URL_VALUE = re.compile(r"(?i)^(?:https?:)?//|^https?:|^ftp:|^gopher:|^dict:|^file:")
_INTERNAL_HOST = re.compile(
    r"(?i)(?:localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|10\.\d+\.\d+\.\d+|"
    r"192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|\[?::1\]?|"
    r"169\.254\.169\.254|100\.100\.100\.200|metadata\.google\.internal|"
    r"metadata\.google|169\.254\.\d+\.\d+|\.internal\b|\.local\b|"
    r"instance-data|\.consul\b)"
)
_CLOUD_META = re.compile(
    r"169\.254\.169\.254|metadata\.google|100\.100\.100\.200|" r"instance-data"
)


class SsrfScanner:
    name = "ssrf"

    def run(self, rows):
        out = []
        for r in rows:
            for loc, val in request_param_values(r):
                pname = loc.split(":")[-1].lower()
                is_url_param = bool(_SSRF_PARAM.match(pname))
                looks_url = bool(_URL_VALUE.match(val.strip()))
                internal = _INTERNAL_HOST.search(val)
                if _CLOUD_META.search(val):
                    _emit(
                        out,
                        self.name,
                        "high",
                        "ssrf:cloud-metadata",
                        r,
                        loc,
                        val,
                        "cloud metadata endpoint in a param — SSRF to "
                        "instance credentials",
                    )
                elif internal and (looks_url or is_url_param):
                    _emit(
                        out,
                        self.name,
                        "high",
                        "ssrf:internal-host",
                        r,
                        loc,
                        val,
                        "internal/loopback host in a fetch param — SSRF",
                    )
                elif is_url_param and looks_url:
                    _emit(
                        out,
                        self.name,
                        "medium",
                        "ssrf:external-url-in-param",
                        r,
                        loc,
                        val,
                        "URL in a server-fetch param — SSRF surface",
                    )
        return _dedupe(out)
