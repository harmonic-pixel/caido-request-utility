"""Check 19: info / stack-trace / debug disclosure in responses"""

from __future__ import annotations

import re

from cru.checks.base import _dedupe, _emit, gate, response_text

_INFOLEAK_SIGS = [
    (
        "python-traceback",
        gate(
            r"Traceback \(most recent call last\)|"
            r"Werkzeug Debugger|django\.\w+\.exceptions",
            "traceback (most recent",
            "werkzeug debugger",
            "django.",
        ),
        "medium",
        "Python traceback / debug page in response",
    ),
    (
        "java-stacktrace",
        gate(
            r"(?m)^\s*at [\w.$]+\([\w.]+\.java:\d+\)|"
            r"Exception in thread|org\.springframework\.\w+Exception",
            ".java:",
            "exception in thread",
            "org.springframework.",
        ),
        "medium",
        "Java stack trace in response",
    ),
    (
        "dotnet-stacktrace",
        gate(
            r"Server Error in '/' Application|"
            r"System\.\w+Exception|^\s*at System\.|Stack Trace:",
            "server error in '/' application",
            "system.",
            "stack trace:",
            flags=re.MULTILINE,
        ),
        "medium",
        ".NET stack trace / error page in response",
    ),
    (
        "php-error",
        gate(
            r"(?i)(?:fatal error|warning|notice|parse error):"
            r"[^\n]{0,80}\bon line\b|stack trace:|call stack",
            "fatal error",
            "warning",
            "notice",
            "parse error",
            "stack trace:",
            "call stack",
        ),
        "medium",
        "PHP error/warning with path in response",
    ),
    (
        "ruby-trace",
        gate(
            r"(?m)app/controllers/\w+\.rb:\d+|"
            r"ActionController::\w+|(?:gems|lib)/[\w/]+\.rb:\d+:in ",
            ".rb:",
            "actioncontroller::",
        ),
        "medium",
        "Ruby/Rails backtrace in response",
    ),
    (
        "node-trace",
        gate(
            r"at Object\.<anonymous>|" r"\(/[\w./-]*node_modules/[\w./-]+:\d+:\d+\)",
            "at object.<anonymous>",
            "node_modules/",
        ),
        "medium",
        "Node.js stack trace in response",
    ),
    (
        "dir-listing",
        gate(
            r"<title>Index of /|Directory listing for /|" r"\[To Parent Directory\]",
            "index of /",
            "directory listing for /",
            "[to parent directory]",
        ),
        "medium",
        "directory listing page in response",
    ),
    (
        "graphql-introspection",
        gate(
            r'"__schema"\s*:|"__typename"\s*:\s*"__'
            r'|"types"\s*:\s*\[\s*\{[^\]]*"kind"',
            '"__schema"',
            '"__typename"',
            '"types"',
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
