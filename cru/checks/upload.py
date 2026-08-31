"""Check 14: dangerous file upload filenames (multipart)"""

from __future__ import annotations

import re

from cru.checks.base import _dedupe, _emit

_UPLOAD_EXEC = re.compile(
    r'(?i)filename\s*=\s*"?([^"\r\n;]+\.(?:php\d?|phtml|phar|jsp|jspx|jsw|asp|'
    r'aspx|ashx|asmx|cshtml|pl|cgi|sh|bash|exe|dll|jar|war|py|rb))"?'
)
_UPLOAD_XSS = re.compile(
    r'(?i)filename\s*=\s*"?([^"\r\n;]+\.(?:svg|html?|shtml|xhtml|xml|xht))"?'
)
_UPLOAD_DOUBLE = re.compile(
    r'(?i)filename\s*=\s*"?([^"\r\n;]+\.(?:jpg|jpeg|png|gif|pdf|txt|doc)\.'
    r'(?:php\d?|phtml|jsp|asp|aspx|exe|sh))"?'
)


class UploadScanner:
    name = "upload"

    def run(self, rows):
        out = []
        for r in rows:
            body = r["body"]
            if not body or "filename" not in body.lower():
                continue
            for rx, sev, sig, detail in (
                (
                    _UPLOAD_DOUBLE,
                    "high",
                    "upload:double-extension",
                    "double-extension upload filename — filter bypass to code exec",
                ),
                (
                    _UPLOAD_EXEC,
                    "high",
                    "upload:executable-extension",
                    "server-executable upload extension — potential RCE via upload",
                ),
                (
                    _UPLOAD_XSS,
                    "medium",
                    "upload:markup-extension",
                    "SVG/HTML upload extension — stored XSS via upload",
                ),
            ):
                m = rx.search(body)
                if m:
                    _emit(
                        out, self.name, sev, sig, r, "request-body", m.group(1), detail
                    )
        return _dedupe(out)
