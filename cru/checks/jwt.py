"""Check 18: JWT weaknesses"""

from __future__ import annotations

import re

from cru.checks.base import _b64url_json, _dedupe, _emit, request_inputs, response_text

_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*")


class JwtScanner:
    name = "jwt"

    def run(self, rows):
        out = []
        for r in rows:
            seen = set()
            for label, text in list(request_inputs(r)) + [
                ("response", response_text(r))
            ]:
                for m in _JWT_RE.finditer(text):
                    tok = m.group(0)
                    if tok in seen:
                        continue
                    seen.add(tok)
                    parts = tok.split(".")
                    header = _b64url_json(parts[0])
                    payload = _b64url_json(parts[1]) if len(parts) > 1 else None
                    if not header:
                        continue
                    alg = str(header.get("alg", "")).lower()
                    if alg == "none":
                        _emit(
                            out,
                            self.name,
                            "high",
                            "jwt:alg-none",
                            r,
                            label,
                            tok[:24],
                            "JWT alg=none — signature bypass",
                        )
                    elif alg.startswith("hs"):
                        _emit(
                            out,
                            self.name,
                            "review",
                            "jwt:hmac-alg",
                            r,
                            label,
                            f"alg={alg}",
                            "HMAC-signed JWT — test for weak/" "guessable signing key",
                        )
                    if len(parts) > 2 and parts[2] == "":
                        _emit(
                            out,
                            self.name,
                            "high",
                            "jwt:empty-signature",
                            r,
                            label,
                            tok[:24],
                            "JWT with empty signature segment",
                        )
                    if payload and "exp" not in payload:
                        _emit(
                            out,
                            self.name,
                            "medium",
                            "jwt:no-expiry",
                            r,
                            label,
                            "no exp claim",
                            "JWT without expiry — token never " "expires",
                        )
        return _dedupe(out)
