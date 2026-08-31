"""Check 5: code-bearing inputs — flag fields that look like source/commands"""

from __future__ import annotations

import re

from cru.checks.base import Finding, _dedupe, _snippet, gate, request_inputs

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
        gate(
            r"\b(?:eval|exec|system|passthru|shell_exec|popen|proc_open)\s*\(",
            "eval",
            "exec",
            "system",
            "passthru",
            "popen",
            "proc_open",
        ),
    ),
    # ---- Log4Shell / JNDI expression lookups ----
    (
        "jndi-lookup",
        "exec",
        "high",
        gate(r"(?i)\$\{jndi:(?:ldaps?|rmi|dns|iiop|corba|nis|nds|http)s?:", "${jndi:"),
    ),
    (
        "log4j-nested-lookup",
        "syntax",
        "medium",
        gate(r"(?i)\$\{(?:lower|upper|env|sys|date|main|java|ctx):", "${"),
    ),
    # ---- Python ----
    (
        "python",
        "exec",
        "high",
        gate(
            r"\b__import__\s*\(|\bos\.(?:system|popen|exec\w*)\s*\(|"
            r"\bsubprocess\.\w+\s*\(|\b(?:pickle|marshal)\.loads?\s*\(|"
            r"\bgetattr\s*\(\s*__|\bcompile\s*\(",
            "__import__",
            "os.",
            "subprocess.",
            "pickle.",
            "marshal.",
            "getattr",
            "compile",
        ),
    ),
    (
        "python",
        "syntax",
        "review",
        gate(
            r"\bimport\s+(?:os|sys|subprocess|socket|pickle)\b|"
            r"\bfrom\s+\w+\s+import\b|\b(?:async\s+)?def\s+\w+\s*\(|"
            r"\blambda\b\s*\w*\s*:|\[\s*\w+\s+for\s+\w+\s+in\b|"
            r"\bprint\s*\(|\bclass\s+\w+\s*[:(]|"
            # An indented return is a statement; "return to sender" is prose.
            r"^\s+return\b|\bif\s+__name__\s*==|\bself\.\w+\s*=|"
            r"\bexcept\s+\w*\s*(?:as\s+\w+\s*)?:|\bwith\s+open\s*\(|"
            r"\byield\s+\w",
            "import",
            "def",
            "lambda",
            " for ",
            "print",
            "class",
            "return",
            "self.",
            "except",
            "with open",
            "yield",
            flags=re.MULTILINE,
        ),
    ),
    # ---- JavaScript / Node ----
    (
        "javascript",
        "exec",
        "high",
        gate(
            r"\brequire\s*\(\s*['\"]child_process['\"]|\bchild_process\b|"
            r"\bprocess\.(?:mainModule|binding)\b|new\s+Function\s*\(|"
            r"\bconstructor\s*\.\s*constructor\b|\bFunction\s*\(\s*['\"]",
            "child_process",
            "process.",
            "function",
            "constructor",
        ),
    ),
    (
        "javascript",
        "syntax",
        "review",
        gate(
            r"\brequire\s*\(|\bmodule\.exports\b|\bconsole\.(?:log|error)\s*\(|"
            r"=>\s*[{(]|\bfunction\s*\*?\s*\w*\s*\([^)]*\)\s*\{|"
            r"\b(?:document|window)\.\w+|"
            r"\breturn\s+[^;\n]{0,120};|\b(?:const|let|var)\s+\w+\s*=|"
            r"\bJSON\.(?:parse|stringify)\s*\(|\basync\s+function\b|"
            r"\bawait\s+\w|\bnew\s+Promise\s*\(|"
            r"\bexport\s+(?:default|const|function)\b|"
            r"\bimport\s+[^;\n]{0,80}\bfrom\s+['\"]",
            "require",
            "module.exports",
            "console.",
            "=>",
            "function",
            "document.",
            "window.",
            "return",
            "const",
            "let",
            "var",
            "json.",
            "await",
            "promise",
            "export",
            "import",
        ),
    ),
    # ---- PHP ----
    (
        "php",
        "exec",
        "high",
        gate(
            r"\bpreg_replace\s*\(\s*['\"][^'\"]*/e|\bbase64_decode\s*\(|"
            r"\bcall_user_func(?:_array)?\s*\(|\bassert\s*\(|\bcreate_function\s*\(",
            "preg_replace",
            "base64_decode",
            "call_user_func",
            "assert",
            "create_function",
        ),
    ),
    (
        "php",
        "syntax",
        "review",
        gate(
            r"<\?php\b|<\?=|\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES|SESSION)\b|"
            r"\bphpinfo\s*\(|\becho\s+[$'\"]|\bprint_r\s*\(|"
            r"\bfunction\s+\w+\s*\([^)]*\)\s*\{|\$\w+\s*=\s*\S|"
            r"->\w+\s*\(|\bforeach\s*\(\s*\$|\bnamespace\s+\w+|"
            r"\buse\s+\w+\\\\",
            "<?",
            "$",
            "phpinfo",
            "echo",
            "print_r",
            "function",
            "->",
            "foreach",
            "namespace",
            "use",
        ),
    ),
    # ---- Ruby ----
    (
        "ruby",
        "exec",
        "high",
        gate(
            r"%x[\(\{\[/]|\bIO\.popen\b|\bOpen3\.\w+|\b__send__\b|"
            r"\.constantize\b|\b(?:instance|class)_eval\s*\(?",
            "%x",
            "io.popen",
            "open3.",
            "__send__",
            ".constantize",
            "_eval",
        ),
    ),
    (
        "ruby",
        "syntax",
        "review",
        gate(
            r"\brequire\s+['\"]\w+['\"]|\bputs\s+\S|\bdo\s*\|\w+\||"
            r"\.each\s*(?:\{\s*\||do\b)|\battr_(?:accessor|reader|writer)\b|"
            r"^\s*end\s*$|\bunless\s+\w|@\w+\s*=\s*\S|"
            r"\bdef\s+\w+[!?]|\bnil\b",
            "require",
            "puts",
            "do",
            ".each",
            "attr_",
            "end",
            "unless",
            "@",
            "def",
            "nil",
            flags=re.MULTILINE,
        ),
    ),
    # ---- Java / OGNL / expression ----
    (
        "java-ognl",
        "exec",
        "high",
        gate(
            r"Runtime\.getRuntime\s*\(\)|\bProcessBuilder\b|@java\.lang\.Runtime@|"
            r"T\(\s*java\.|Class\.forName\s*\(|#context\b|#request\b|\(#\w+\s*=",
            "runtime",
            "processbuilder",
            "t(",
            "class.forname",
            "#context",
            "#request",
            "(#",
        ),
    ),
    (
        "java-ognl",
        "syntax",
        "review",
        gate(
            r"\bpublic\s+(?:static\s+)?(?:class|void|int|String)\b|"
            r"\bSystem\.out\.print(?:ln)?\s*\(|\bimport\s+java(?:x)?\.|"
            r"\bnew\s+[A-Z]\w*\s*\(|@Override\b|\bpackage\s+[\w.]+;|"
            r"\bpublic\s+static\s+void\s+main\b",
            "public",
            "system.out.print",
            "import java",
            "new ",
            "@override",
            "package",
        ),
    ),
    # ---- PowerShell ----
    (
        "powershell",
        "exec",
        "high",
        gate(
            r"(?i)\b(?:invoke-expression|iex|invoke-webrequest|start-process)\b|"
            r"-encodedcommand\b|\$env:\w+|\bnew-object\s+\w",
            "invoke-",
            "iex",
            "start-process",
            "-encodedcommand",
            "$env:",
            "new-object",
        ),
    ),
    (
        "powershell",
        "syntax",
        "review",
        gate(
            r"(?i)\bwrite-(?:host|output|error|verbose)\b|\bparam\s*\(\s*\[|"
            r"\bforeach\s*\(\s*\$\w+\s+in\b|\$(?:true|false|null)\b|"
            r"\s-(?:eq|ne|gt|lt|match|like|contains)\s|\bget-\w+\b",
            "write-",
            "param",
            "foreach",
            "$true",
            "$false",
            "$null",
            "-eq",
            "-ne",
            "-gt",
            "-lt",
            "-match",
            "-like",
            "-contains",
            "get-",
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
    (
        "shell",
        "syntax",
        "review",
        gate(
            r"#!\s*/(?:usr/)?bin/(?:env\s+)?(?:ba|z|k)?sh\b|"
            r"^\s*(?:export|unset|local|readonly)\s+\w+=|"
            r"\bif\s+\[\[?\s|^\s*(?:fi|done|esac)\s*$|"
            r"\bfor\s+\w+\s+in\s+[^;\n]{0,80};\s*do\b|\becho\s+[\"$']",
            "#!",
            "export",
            "unset",
            "local",
            "readonly",
            "if",
            "fi",
            "done",
            "esac",
            "for",
            "echo",
            flags=re.MULTILINE,
        ),
    ),
]


class CodeScanner:
    name = "code"

    def run(self, rows):
        out = []
        for r in rows:
            hits = {}
            for label, text in request_inputs(r):
                # `print(`, `return ...;` and `echo` belong to several
                # languages, so one snippet can satisfy several signatures. The
                # first to claim a fragment keeps it — the table runs from the
                # most specific (cross-language sinks) to the least.
                claimed = set()
                for lang, tier, sev, rx in _CODE_SIGS:
                    m = rx.search(text)
                    if not m or m.group(0) in claimed:
                        continue
                    claimed.add(m.group(0))
                    hits.setdefault((lang, tier, sev), []).append((label, m.group(0)))
            # One finding per rule per request, not one per field it fired in:
            # a snippet reachable through the raw body and its #json view is
            # one lead. Rules stay apart — shell and PHP in the same body are
            # different findings — and each lists where it matched.
            for (lang, tier, sev), matches in hits.items():
                seen, where = set(), []
                for label, frag in matches:
                    entry = f"{_snippet(frag, 40)} in {label}"
                    if entry not in seen:
                        seen.add(entry)
                        where.append(entry)
                label, frag = matches[0]
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
                        _snippet(frag),
                        detail,
                        rules=where,
                    )
                )
        return _dedupe(out)
