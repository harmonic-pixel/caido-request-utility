"""Check 19: info / stack-trace / debug disclosure in responses"""

from __future__ import annotations

import re

from cru.checks.base import _dedupe, _emit, response_text

_INFOLEAK_SIGS = [
    (
        "python-traceback",
        re.compile(
            r"Traceback \(most recent call last\)|"
            r"Werkzeug Debugger|django\.\w+\.exceptions"
        ),
        "medium",
        "Python traceback / debug page in response",
    ),
    (
        "java-stacktrace",
        re.compile(
            r"(?m)^\s*at [\w.$]+\([\w.]+\.java:\d+\)|"
            r"Exception in thread|org\.springframework\.\w+Exception"
        ),
        "medium",
        "Java stack trace in response",
    ),
    (
        "dotnet-stacktrace",
        re.compile(
            r"Server Error in '/' Application|"
            r"System\.\w+Exception|^\s*at System\.|Stack Trace:",
            re.MULTILINE,
        ),
        "medium",
        ".NET stack trace / error page in response",
    ),
    (
        "php-error",
        re.compile(
            r"(?i)(?:Fatal error|Warning|Notice|Parse error):"
            r"[^\n]{0,80}\bon line\b|Stack trace:|Call Stack"
        ),
        "medium",
        "PHP error/warning with path in response",
    ),
    (
        "ruby-trace",
        re.compile(
            r"(?m)app/controllers/\w+\.rb:\d+|"
            r"ActionController::\w+|(?:gems|lib)/[\w/]+\.rb:\d+:in "
        ),
        "medium",
        "Ruby/Rails backtrace in response",
    ),
    (
        "node-trace",
        re.compile(
            r"at Object\.<anonymous>|" r"\(/[\w./-]*node_modules/[\w./-]+:\d+:\d+\)"
        ),
        "medium",
        "Node.js stack trace in response",
    ),
    (
        "dir-listing",
        re.compile(
            r"<title>Index of /|Directory listing for /|" r"\[To Parent Directory\]"
        ),
        "medium",
        "directory listing page in response",
    ),
    (
        "graphql-introspection",
        re.compile(
            r'"__schema"\s*:|"__typename"\s*:\s*"__'
            r'|"types"\s*:\s*\[\s*\{[^\]]*"kind"'
        ),
        "medium",
        "GraphQL introspection data in response",
    ),
]


class InfoLeakScanner:
    name = "infoleak"

    def run(self, rows):
        out = []
        for r in rows:
            resp = response_text(r)
            for sig, rx, sev, detail in _INFOLEAK_SIGS:
                m = rx.search(resp)
                if m:
                    _emit(out, self.name, sev, sig, r, "response", m.group(0), detail)
        return _dedupe(out)
