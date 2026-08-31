"""Check 6: source-code / config disclosure in responses"""

from __future__ import annotations

import re

from cru.checks.base import Finding, _dedupe, _snippet, _status, response_text

#
# Flags responses that return server-side source or config that should never
# reach the client: PHP/JSP/ASP tags served unexecuted, dumped source files,
# leaked .env / settings / web.config credentials, exposed .git metadata, or a
# backup/dotfile path served 200. It keys on SERVER-SIDE-ONLY markers, never on
# ordinary client-side JavaScript, so a normal .js response is not a finding.

# Server-side script/template tags that must never appear verbatim in output.
_SRCLEAK_SERVER_TAGS = [
    (
        "php-source",
        re.compile(r"<\?php\b|<\?="),
        "high",
        "PHP open tag in response — PHP source returned unexecuted",
    ),
    (
        "jsp-source",
        re.compile(r"<%@\s*page\b|<%!|<jsp:\w+"),
        "high",
        "JSP directive/scriptlet in response — JSP source disclosure",
    ),
    (
        "asp-source",
        re.compile(r"<%@\s*Page\b|\bResponse\.Write\b|<%#"),
        "high",
        "ASP/ASP.NET directive in response — source disclosure",
    ),
    (
        "ssi-directive",
        re.compile(r"<!--#\s*(?:exec|include|echo|config)\b"),
        "high",
        "Server-Side Include directive in response",
    ),
    (
        "erb-source",
        re.compile(r"<%-?\s*=?\s*(?:@\w+|ERB\b|Rails\b|params\b)"),
        "medium",
        "ERB template source in response",
    ),
]

# Constructs indicating a server source *file* was dumped/returned.
_SRCLEAK_SOURCE = [
    (
        "java-source",
        re.compile(
            r"\bpackage\s+[\w.]+\s*;|\bimport\s+java\.[\w.]+;|"
            r"public\s+static\s+void\s+main|@(?:RestController|Autowired|RequestMapping)\b"
        ),
        "medium",
        "Java source constructs in response",
    ),
    (
        "python-source",
        re.compile(
            r"if\s+__name__\s*==\s*['\"]__main__['\"]|def\s+__init__\s*\(\s*self\b|"
            r"\bfrom\s+(?:flask|django|fastapi)\b"
        ),
        "medium",
        "Python source constructs in response",
    ),
    (
        "php-source-constructs",
        re.compile(
            r"\brequire_once\b|\bnamespace\s+\w+\\|\buse\s+\w+\\[\w\\]+\s*;|\$this->\w+"
        ),
        "medium",
        "PHP source constructs in response",
    ),
    (
        "csharp-source",
        re.compile(r"\busing\s+System(?:\.\w+)*\s*;|\[Http(?:Get|Post|Put|Delete)\]"),
        "medium",
        "C# source constructs in response",
    ),
    (
        "node-source",
        re.compile(
            r"\brequire\s*\(\s*['\"](?:express|koa|fastify|http|fs|mongoose|mysql|pg)['\"]\)|"
            r"\bapp\.listen\s*\("
        ),
        "review",
        "Node.js server source constructs in response",
    ),
    (
        "ruby-source",
        re.compile(
            r"<\s*ApplicationController\b|\bRails\.application\b|\bActiveRecord::Base\b"
        ),
        "medium",
        "Ruby/Rails source constructs in response",
    ),
]

# Config / secrets files leaked in a response.
_SRCLEAK_CONFIG = [
    (
        "dotenv",
        re.compile(
            r"(?m)^\s*(?:DB_PASSWORD|DB_USERNAME|APP_KEY|APP_SECRET|SECRET_KEY|"
            r"AWS_SECRET_ACCESS_KEY|DATABASE_URL|REDIS_URL|JWT_SECRET)\s*="
        ),
        "high",
        ".env-style config with credentials returned in response",
    ),
    (
        "wp-config",
        re.compile(
            r"define\s*\(\s*['\"](?:DB_PASSWORD|DB_NAME|AUTH_KEY|SECURE_AUTH_KEY)['\"]"
        ),
        "high",
        "wp-config.php credentials returned in response",
    ),
    (
        "dotnet-config",
        re.compile(r"<connectionStrings>|<machineKey\b"),
        "high",
        "web.config/app.config returned in response",
    ),
    (
        "django-settings",
        re.compile(r"DATABASES\s*=\s*\{|SECRET_KEY\s*=\s*['\"]"),
        "high",
        "Django settings.py returned in response",
    ),
    (
        "php-config-array",
        re.compile(
            r"['\"](?:password|passwd|db_pass|secret)['\"]\s*=>\s*['\"][^'\"]+['\"]"
        ),
        "medium",
        "PHP config array with credentials in response",
    ),
]

# VCS metadata exposure.
_SRCLEAK_VCS = [
    (
        "git-metadata",
        re.compile(r"ref:\s+refs/heads/|\[core\][\s\S]{0,40}repositoryformatversion"),
        "high",
        ".git metadata returned in response",
    ),
]

_SRCLEAK_SHEBANG = re.compile(
    r"(?m)^#!\s*(?:\S*/)?(?:env\s+)?(?:python\d?|bash|sh|perl|ruby|node|php)\b"
)

# Paths that should never be served (backups, dotfiles, VCS, dumps).
_SRCLEAK_RISKY_PATH = re.compile(
    r"(?i)(?:\.(?:bak|old|orig|save|swp|swo|inc|dist|sample|template)|~)$|"
    r"\.(?:php|py|rb|pl|jsp|aspx?|cs|java)\.(?:bak|old|txt|save|orig|~)$|"
    r"/\.(?:git|svn|hg|env|htpasswd|htaccess|aws|ssh)(?:/|$)"
)


class SourceLeakScanner:
    name = "srcleak"

    def run(self, rows):
        out = []
        for r in rows:
            resp = response_text(r)
            path = r["path"] or ""
            clean_path = path.split("?", 1)[0]
            status = _status(r)

            for table in (
                _SRCLEAK_SERVER_TAGS,
                _SRCLEAK_SOURCE,
                _SRCLEAK_CONFIG,
                _SRCLEAK_VCS,
            ):
                for name, rx, sev, detail in table:
                    m = rx.search(resp)
                    if m:
                        out.append(
                            Finding(
                                self.name,
                                sev,
                                name,
                                r["host"],
                                r["method"],
                                path,
                                "response",
                                _snippet(m.group(0)),
                                detail,
                            )
                        )

            m = _SRCLEAK_SHEBANG.search(resp)
            if m:
                out.append(
                    Finding(
                        self.name,
                        "medium",
                        "script-shebang",
                        r["host"],
                        r["method"],
                        path,
                        "response",
                        _snippet(m.group(0)),
                        "interpreter shebang in response — raw script returned",
                    )
                )

            if (
                status == 200
                and resp.strip()
                and _SRCLEAK_RISKY_PATH.search(clean_path)
            ):
                out.append(
                    Finding(
                        self.name,
                        "medium",
                        "risky-file-served",
                        r["host"],
                        r["method"],
                        path,
                        "path",
                        _snippet(clean_path),
                        "backup/dotfile/source path returned 200 — possible disclosure",
                    )
                )
        return _dedupe(out)
