"""Check 16: CORS misconfiguration"""

from __future__ import annotations

from cru.checks.base import _dedupe, _emit, _header_map


class CorsScanner:
    name = "cors"

    def run(self, rows):
        out = []
        for r in rows:
            hm = _header_map(r["response_headers"])
            acao = hm.get("access-control-allow-origin")
            if acao is None:
                continue
            creds = hm.get("access-control-allow-credentials", "").lower() == "true"
            origin = _header_map(r["headers"]).get("origin", "")
            if acao == "*" and creds:
                _emit(
                    out,
                    self.name,
                    "high",
                    "cors:wildcard-with-credentials",
                    r,
                    "response-headers",
                    acao,
                    "ACAO * with credentials — invalid but often mishandled",
                )
            elif acao == "null":
                _emit(
                    out,
                    self.name,
                    "high",
                    "cors:null-origin",
                    r,
                    "response-headers",
                    acao,
                    "ACAO null — bypassable via sandboxed iframe"
                    + (" WITH credentials" if creds else ""),
                )
            elif origin and acao == origin and creds:
                _emit(
                    out,
                    self.name,
                    "high",
                    "cors:reflected-origin",
                    r,
                    "response-headers",
                    acao,
                    "ACAO reflects request Origin with credentials — "
                    "cross-origin data theft",
                )
            elif acao == "*":
                _emit(
                    out,
                    self.name,
                    "low",
                    "cors:wildcard",
                    r,
                    "response-headers",
                    acao,
                    "ACAO * (no credentials) — exposes non-cookie responses",
                )
        return _dedupe(out)
