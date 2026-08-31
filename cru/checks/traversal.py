"""Check 11: Path traversal / LFI payloads in request params"""

from __future__ import annotations

from cru.checks.base import _dedupe, _emit, gate, request_inputs, response_body
from cru.checks.xxe import _XXE_FILE_DISCLOSURE

_TRAVERSAL_STRONG = gate(
    r"(?i)/etc/passwd|/etc/shadow|/etc/hosts|/proc/self/environ|boot\.ini|"
    r"\\windows\\win\.ini|/windows/win\.ini|c:\\windows",
    "/etc/",
    "/proc/self/environ",
    "boot.ini",
    "win.ini",
    "c:\\windows",
)
_TRAVERSAL_SEQ = gate(
    r"(?:\.\.[\\/]){2,}|(?:%2e%2e[\\/%]){2,}|" r"\.\.%2f|\.\.%5c|%252e%252e",
    "..",
    "%2e%2e",
    "%252e",
)


class TraversalScanner:
    name = "traversal"

    def run(self, rows):
        out = []
        for r in rows:
            file_read = _XXE_FILE_DISCLOSURE.search(response_body(r))
            for label, text in request_inputs(r):
                m = _TRAVERSAL_STRONG.search(text)
                sev = "high"
                if m is None:
                    m = _TRAVERSAL_SEQ.search(text)
                    sev = "medium"
                if m is None:
                    continue
                detail = "path traversal / LFI sequence in input"
                if file_read:
                    sev = "high"
                    detail += " — and file contents returned in response"
                _emit(
                    out, self.name, sev, "path-traversal", r, label, m.group(0), detail
                )
        return _dedupe(out)
