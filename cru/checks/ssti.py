"""Check 4: Server-Side Template Injection — request-side syntax flagging"""

from __future__ import annotations

import re

from cru.checks.base import Finding, _dedupe, _snippet, request_inputs

#
# Reads request inputs and flags any that carry template-expression syntax,
# tagged by templating style. It does not look at responses. A match means the
# input *contains* templating syntax — often a probe or payload, sometimes
# benign data (a JS template literal, a value that happens to use braces) — so
# review the flagged requests. Inputs are URL-decoded before matching.

# (style label, regex, base severity). The generic {{…}} pattern excludes a
# leading #/ so Handlebars block helpers are tagged separately rather than twice.
_TEMPLATE_SYNTAX_SIGS = [
    (
        "jinja2/twig/angular {{…}}",
        re.compile(r"\{\{\s*(?![#/])[^{}]{1,300}?\}\}"),
        "review",
    ),
    ("jinja2/twig statement {%…%}", re.compile(r"\{%[^%]{1,300}?%\}"), "medium"),
    (
        "handlebars block {{#…}}/{{/…}}",
        re.compile(r"\{\{[#/][\w.][^{}]{0,200}?\}\}"),
        "review",
    ),
    (
        "EL/FreeMarker/Thymeleaf ${…}",
        re.compile(r"\$\{[^{}\s][^{}]{0,300}?\}"),
        "review",
    ),
    ("ruby/JSF/Thymeleaf #{…}", re.compile(r"#\{[^{}\s][^{}]{0,300}?\}"), "review"),
    ("thymeleaf selection *{…}", re.compile(r"\*\{[^{}\s][^{}]{0,300}?\}"), "medium"),
    ("thymeleaf link @{…}", re.compile(r"@\{[^{}\s][^{}]{0,300}?\}"), "medium"),
    ("ERB/JSP/EJS/ASP <%…%>", re.compile(r"<%[=#@]?[^%]{1,300}?%>"), "medium"),
    (
        "velocity directive #set/#foreach/…",
        re.compile(r"#(?:set|foreach|if|elseif|parse|include|macro|evaluate)\b"),
        "medium",
    ),
    (
        "freemarker directive <#…>/[#…]",
        re.compile(r"<#\w+|\[#\w+[^\]]{0,100}?\]"),
        "medium",
    ),
    (
        "smarty {$var}/{tag}",
        re.compile(
            r"\{(?:\$\w+|if|foreach|literal|php|assign|include)\b[^{}]{0,200}?\}"
        ),
        "medium",
    ),
    ("SSTI polyglot", re.compile(r"\$\{\{<%\[%"), "high"),
]

# Tokens that, when they appear inside the templating syntax, strongly suggest
# an SSTI probe/exploit rather than benign data — these escalate the severity.
_SSTI_DANGEROUS = re.compile(
    r"(?i)\b(?:config|self|request|settings|application|session|cycler|joiner|"
    r"namespace|lipsum|url_for|get_flashed_messages|"
    r"__class__|__globals__|__mro__|__subclasses__|__builtins__|__import__|"
    r"Runtime|getClass|getRuntime|ProcessBuilder|forName|freemarker|"
    r"popen|system|exec|eval|subprocess|os\.)\b|T\(|new\s+\w+\("
)


class SstiScanner:
    name = "ssti"

    def run(self, rows):
        out = []
        for r in rows:
            for label, text in request_inputs(r):
                for style, rx, base_sev in _TEMPLATE_SYNTAX_SIGS:
                    for m in rx.finditer(text):
                        frag = m.group(0)
                        danger = _SSTI_DANGEROUS.search(frag)
                        if danger:
                            sev = "high"
                            detail = (
                                f"templating syntax containing SSTI-sensitive "
                                f"token '{danger.group(0)}' — likely payload"
                            )
                        else:
                            sev = base_sev
                            detail = (
                                "templating syntax in request input — "
                                "review for SSTI"
                            )
                        out.append(
                            Finding(
                                self.name,
                                sev,
                                f"template-syntax: {style}",
                                r["host"],
                                r["method"],
                                r["path"],
                                label,
                                _snippet(frag),
                                detail,
                            )
                        )
        return _dedupe(out)
