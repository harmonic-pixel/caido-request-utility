"""Check 18: JWT weaknesses"""

from __future__ import annotations

from cru.checks.base import (
    JWT_RE,
    _b64url_json,
    _dedupe,
    _emit,
    jwt_identity,
    request_inputs,
    response_text,
)


class JwtScanner:
    name = "jwt"

    def run(self, rows):
        out = []
        for r in rows:
            seen = set()
            for label, text in list(request_inputs(r)) + [
                ("response", response_text(r))
            ]:
                for m in JWT_RE.finditer(text):
                    tok = m.group(0)
                    if tok in seen:
                        continue
                    seen.add(tok)
                    parts = tok.split(".")
                    header = _b64url_json(parts[0])
                    payload = _b64url_json(parts[1]) if len(parts) > 1 else None
                    if not header:
                        continue
                    # One finding per distinct token, not per re-issue: a
                    # refreshed session mints a new iat/exp and signature for
                    # the same credential. The paths merge onto the survivor.
                    ident = jwt_identity(tok)
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
                            group=ident,
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
                            group=ident,
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
                            group=ident,
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
                            group=ident,
                        )
        return _dedupe(out)
