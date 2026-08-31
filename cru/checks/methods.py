"""Check 21: dangerous HTTP methods observed"""

from __future__ import annotations

from cru.checks.base import _dedupe, _emit, _status

_DANGEROUS_METHODS = {"PUT", "DELETE", "TRACE", "CONNECT", "PATCH", "TRACK"}


class MethodScanner:
    name = "methods"

    def run(self, rows):
        out = []
        for r in rows:
            method = (r["method"] or "").upper()
            if method not in _DANGEROUS_METHODS:
                continue
            status = _status(r)
            accepted = status is not None and status < 405
            sev = (
                "medium"
                if (method in {"TRACE", "TRACK", "CONNECT"} or accepted)
                else "review"
            )
            note = f"{method} observed"
            if method in {"TRACE", "TRACK"}:
                note += " — Cross-Site Tracing (XST) risk"
            elif accepted:
                note += f" — endpoint responded {status} (method allowed)"
            _emit(
                out,
                self.name,
                sev,
                f"method:{method}",
                r,
                "request",
                f"{method} {r['path']}",
                note,
                host_level=True,
            )
        return _dedupe(out)
