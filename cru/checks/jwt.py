"""Check 18: JWT weaknesses"""

from __future__ import annotations

from cru.checks.base import (
    JWT_RE,
    _b64url_json,
    _dedupe,
    _emit,
    gate,
    jwt_claims,
    jwt_identity,
    request_inputs,
    response_text,
)

# Every JWT starts "eyJ" — the base64 of `{"`. Naming it lets a field with no
# token in it skip the pattern entirely.
_JWT = gate(JWT_RE.pattern, "eyj")


class JwtScanner:
    name = "jwt"

    def run(self, rows):
        out = []
        for r in rows:
            seen = set()
            for label, text in list(request_inputs(r)) + [
                ("response", response_text(r))
            ]:
                for m in _JWT.finditer(text):
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
                    claims = jwt_claims(tok)
                    about = f" [{claims}]" if claims else ""
                    alg = str(header.get("alg", "")).lower()
                    # Every signature quotes the token itself. What is wrong
                    # with it is a property of its header, not a string in the
                    # traffic, so describing it in the evidence left the report
                    # with a finding it could not point at. The description
                    # belongs in the detail; the token is what you go and look
                    # at.
                    if alg == "none":
                        _emit(
                            out,
                            self.name,
                            "high",
                            "jwt:alg-none",
                            r,
                            label,
                            tok,
                            f"JWT alg=none — signature bypass{about}",
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
                            tok,
                            f"HMAC-signed JWT (alg={alg}) — test for weak/"
                            f"guessable signing key{about}",
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
                            tok,
                            f"JWT with empty signature segment{about}",
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
                            tok,
                            f"JWT without an exp claim — token never expires{about}",
                            group=ident,
                        )
        return _dedupe(out)
