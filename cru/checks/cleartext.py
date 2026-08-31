"""Check 23: cleartext transmission of secrets / session"""

from __future__ import annotations

import re

from cru.checks.base import _dedupe, _emit, _header_map

_CRED_PARAM = re.compile(
    r"(?i)(?:^|&)(?:password|passwd|pwd|pass|token|secret|"
    r"api_?key|auth|otp|pin|ssn|card|cvv)=[^&\s]"
)


class CleartextScanner:
    name = "cleartext"

    def run(self, rows):
        out = []
        for r in rows:
            if r["is_tls"]:
                continue
            rh = _header_map(r["headers"])
            reasons = []
            if r["cookies"]:
                reasons.append("session cookie")
            if "authorization" in rh:
                reasons.append("Authorization header")
            blob = f"{r['query'] or ''}&{r['body'] or ''}"
            if _CRED_PARAM.search(blob):
                reasons.append("credential parameter")
            if reasons:
                _emit(
                    out,
                    self.name,
                    "high",
                    "cleartext-transmission",
                    r,
                    "request",
                    ", ".join(reasons),
                    "sensitive data sent over plaintext HTTP: " + ", ".join(reasons),
                )
        return _dedupe(out)
