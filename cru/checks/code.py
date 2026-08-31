"""Check 5: code-bearing inputs — flag fields that look like source/commands"""

from __future__ import annotations

import re

from cru.checks.base import (
    Finding,
    _dedupe,
    _snippet,
    request_inputs,
    request_param_values,
)

#
# Reads request inputs and flags ones that look like they carry code — Python,
# JavaScript/Node, PHP, Ruby, shell, Java/OGNL, PowerShell, or a JNDI lookup.
# A field taking raw code is a signal it may reach an eval()/exec()/command
# sink. Two tiers per language: `exec` (execution/eval/command sinks -> high)
# and `syntax` (language keywords/structure -> review/medium). Cross-language
# sinks (eval/exec/system/...) are one generic signature so a single `eval(`
# isn't reported once per language.

# (language, tier, severity, regex)
_CODE_SIGS = [
    # ---- language-agnostic execution / eval / command sinks ----
    (
        "generic-eval-exec-sink",
        "exec",
        "high",
        re.compile(r"\b(?:eval|exec|system|passthru|shell_exec|popen|proc_open)\s*\("),
    ),
    # ---- Log4Shell / JNDI expression lookups ----
    (
        "jndi-lookup",
        "exec",
        "high",
        re.compile(r"(?i)\$\{jndi:(?:ldaps?|rmi|dns|iiop|corba|nis|nds|http)s?:"),
    ),
    (
        "log4j-nested-lookup",
        "syntax",
        "medium",
        re.compile(r"(?i)\$\{(?:lower|upper|env|sys|date|main|java|ctx):"),
    ),
    # ---- Python ----
    (
        "python",
        "exec",
        "high",
        re.compile(
            r"\b__import__\s*\(|\bos\.(?:system|popen|exec\w*)\s*\(|"
            r"\bsubprocess\.\w+\s*\(|\b(?:pickle|marshal)\.loads?\s*\(|"
            r"\bgetattr\s*\(\s*__|\bcompile\s*\("
        ),
    ),
    (
        "python",
        "syntax",
        "review",
        re.compile(
            r"\bimport\s+(?:os|sys|subprocess|socket|pickle)\b|"
            r"\bfrom\s+\w+\s+import\b|\bdef\s+\w+\s*\(|\blambda\b\s*\w*\s*:|"
            r"\[\s*\w+\s+for\s+\w+\s+in\b"
        ),
    ),
    # ---- JavaScript / Node ----
    (
        "javascript",
        "exec",
        "high",
        re.compile(
            r"\brequire\s*\(\s*['\"]child_process['\"]|\bchild_process\b|"
            r"\bprocess\.(?:mainModule|binding)\b|new\s+Function\s*\(|"
            r"\bconstructor\s*\.\s*constructor\b|\bFunction\s*\(\s*['\"]"
        ),
    ),
    (
        "javascript",
        "syntax",
        "review",
        re.compile(
            r"\brequire\s*\(|\bmodule\.exports\b|\bconsole\.(?:log|error)\s*\(|"
            r"=>\s*[{(]|\bfunction\s*\*?\s*\w*\s*\([^)]*\)\s*\{|"
            r"\b(?:document|window)\.\w+"
        ),
    ),
    # ---- PHP ----
    (
        "php",
        "exec",
        "high",
        re.compile(
            r"\bpreg_replace\s*\(\s*['\"][^'\"]*/e|\bbase64_decode\s*\(|"
            r"\bcall_user_func(?:_array)?\s*\(|\bassert\s*\(|\bcreate_function\s*\("
        ),
    ),
    (
        "php",
        "syntax",
        "review",
        re.compile(
            r"<\?php\b|<\?=|\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES|SESSION)\b|"
            r"\bphpinfo\s*\("
        ),
    ),
    # ---- Ruby ----
    (
        "ruby",
        "exec",
        "high",
        re.compile(
            r"%x[\(\{\[/]|\bIO\.popen\b|\bOpen3\.\w+|\b__send__\b|"
            r"\.constantize\b|\b(?:instance|class)_eval\s*\(?"
        ),
    ),
    (
        "ruby",
        "syntax",
        "review",
        re.compile(
            r"\brequire\s+['\"]\w+['\"]|\bputs\s+['\"]|\bdo\s*\|\w+\||\.each\s*\{\s*\|"
        ),
    ),
    # ---- Java / OGNL / expression ----
    (
        "java-ognl",
        "exec",
        "high",
        re.compile(
            r"Runtime\.getRuntime\s*\(\)|\bProcessBuilder\b|@java\.lang\.Runtime@|"
            r"T\(\s*java\.|Class\.forName\s*\(|#context\b|#request\b|\(#\w+\s*="
        ),
    ),
    # ---- PowerShell ----
    (
        "powershell",
        "exec",
        "high",
        re.compile(
            r"(?i)\b(?:Invoke-Expression|IEX|Invoke-WebRequest|Start-Process)\b|"
            r"-EncodedCommand\b|\$env:\w+|\bNew-Object\s+\w"
        ),
    ),
    # ---- shell / OS command ----
    (
        "shell",
        "exec",
        "high",
        re.compile(
            r"\$\([^)]{1,200}\)|"
            # Backtick substitution, but not a word in backticks: markdown-style
            # inline code in a comment or a description is not a command, and
            # `[^`]+` alone flagged prose. Take a command line (something with a
            # space, path, pipe, redirect or flag in it) or a bare command name.
            r"`[^`\n]{0,200}[\s/;|&$><-][^`\n]{0,200}`|"
            r"`(?:cat|ls|id|pwd|whoami|uname|curl|wget|nc|ncat|ping|nslookup|"
            r"chmod|rm|env|printenv|sh|bash|zsh)`|"
            r"/bin/(?:ba|z|)sh\b|"
            r"\b(?:ba)?sh\s+-c\b|(?:^|[;&|])\s*(?:cat|ls|id|whoami|uname|curl|wget|"
            r"nc|ncat|ping|nslookup|chmod|rm)\s"
        ),
    ),
]


class CodeScanner:
    name = "code"

    def run(self, rows):
        out = []
        for r in rows:
            # Whole fields first, then each parameter on its own. Code inside a
            # JSON string arrives with its newlines escaped, so every line runs
            # into the previous one (`...Operation\ndef operation(`) and a
            # \b-anchored pattern never fires on the raw field. The per-leaf
            # view has the value unescaped, which is where code actually shows.
            fields = list(request_inputs(r)) + list(request_param_values(r))
            for label, text in fields:
                for lang, tier, sev, rx in _CODE_SIGS:
                    m = rx.search(text)
                    if not m:
                        continue
                    detail = (
                        "execution/eval/command sink pattern — field may be "
                        "interpreted as code"
                        if tier == "exec"
                        else "language syntax present — field may accept code"
                    )
                    out.append(
                        Finding(
                            self.name,
                            sev,
                            f"code:{lang} ({tier})",
                            r["host"],
                            r["method"],
                            r["path"],
                            label,
                            _snippet(m.group(0)),
                            detail,
                        )
                    )
        return _dedupe(out)
