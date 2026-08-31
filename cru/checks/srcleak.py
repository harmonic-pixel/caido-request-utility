"""Check 6: source-code / config disclosure in responses"""

from __future__ import annotations

import re

from cru.checks.base import (
    Finding,
    _dedupe,
    _snippet,
    _status,
    gate,
    response_text,
)

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
        gate(r"<\?php\b|<\?=", "<?php", "<?="),
        "high",
        "PHP open tag in response — PHP source returned unexecuted",
    ),
    (
        "jsp-source",
        gate(r"<%@\s*page\b|<%!|<jsp:\w+", "<%", "<jsp:"),
        "high",
        "JSP directive/scriptlet in response — JSP source disclosure",
    ),
    (
        "asp-source",
        gate(r"<%@\s*Page\b|\bResponse\.Write\b|<%#", "<%", "response.write"),
        "high",
        "ASP/ASP.NET directive in response — source disclosure",
    ),
    (
        "ssi-directive",
        gate(r"<!--#\s*(?:exec|include|echo|config)\b", "<!--#"),
        "high",
        "Server-Side Include directive in response",
    ),
    (
        "erb-source",
        gate(r"<%-?\s*=?\s*(?:@\w+|ERB\b|Rails\b|params\b)", "<%"),
        "medium",
        "ERB template source in response",
    ),
]

# Constructs indicating a server source *file* was dumped/returned.
_SRCLEAK_SOURCE = [
    (
        "java-source",
        gate(
            r"\bpackage\s+[\w.]+\s*;|\bimport\s+java\.[\w.]+;|"
            r"public\s+static\s+void\s+main|@(?:RestController|Autowired|RequestMapping)\b",
            "package",
            "import java.",
            "public",
            "@restcontroller",
            "@autowired",
            "@requestmapping",
        ),
        "medium",
        "Java source constructs in response",
    ),
    (
        "python-source",
        gate(
            r"if\s+__name__\s*==\s*['\"]__main__['\"]|def\s+__init__\s*\(\s*self\b|"
            r"\bfrom\s+(?:flask|django|fastapi)\b",
            "__name__",
            "__init__",
            "flask",
            "django",
            "fastapi",
        ),
        "medium",
        "Python source constructs in response",
    ),
    (
        "php-source-constructs",
        gate(
            r"\brequire_once\b|\bnamespace\s+\w+\\|\buse\s+\w+\\[\w\\]+\s*;|\$this->\w+",
            "require_once",
            "namespace",
            "use",
            "$this->",
        ),
        "medium",
        "PHP source constructs in response",
    ),
    (
        "csharp-source",
        gate(
            r"\busing\s+System(?:\.\w+)*\s*;|\[Http(?:Get|Post|Put|Delete)\]",
            "using system",
            "[http",
        ),
        "medium",
        "C# source constructs in response",
    ),
    (
        "node-source",
        gate(
            r"\brequire\s*\(\s*['\"](?:express|koa|fastify|http|fs|mongoose|mysql|pg)['\"]\)|"
            r"\bapp\.listen\s*\(",
            "require",
            "app.listen",
        ),
        "review",
        "Node.js server source constructs in response",
    ),
    (
        "ruby-source",
        gate(
            r"<\s*ApplicationController\b|\bRails\.application\b|\bActiveRecord::Base\b",
            "applicationcontroller",
            "rails.application",
            "activerecord::base",
        ),
        "medium",
        "Ruby/Rails source constructs in response",
    ),
]

# Config / secrets files leaked in a response.
_SRCLEAK_CONFIG = [
    (
        "dotenv",
        gate(
            r"(?m)^\s*(?:DB_PASSWORD|DB_USERNAME|APP_KEY|APP_SECRET|SECRET_KEY|"
            r"AWS_SECRET_ACCESS_KEY|DATABASE_URL|REDIS_URL|JWT_SECRET)\s*=",
            "db_password",
            "db_username",
            "app_key",
            "app_secret",
            "secret_key",
            "aws_secret_access_key",
            "database_url",
            "redis_url",
            "jwt_secret",
        ),
        "high",
        ".env-style config with credentials returned in response",
    ),
    (
        "wp-config",
        gate(
            r"define\s*\(\s*['\"](?:DB_PASSWORD|DB_NAME|AUTH_KEY|SECURE_AUTH_KEY)['\"]",
            "db_password",
            "db_name",
            "auth_key",
        ),
        "high",
        "wp-config.php credentials returned in response",
    ),
    (
        "dotnet-config",
        gate(
            r"<connectionStrings>|<machineKey\b", "<connectionstrings>", "<machinekey"
        ),
        "high",
        "web.config/app.config returned in response",
    ),
    (
        "django-settings",
        gate(r"DATABASES\s*=\s*\{|SECRET_KEY\s*=\s*['\"]", "databases", "secret_key"),
        "high",
        "Django settings.py returned in response",
    ),
    (
        "php-config-array",
        gate(
            r"['\"](?:password|passwd|db_pass|secret)['\"]\s*=>\s*['\"][^'\"]+['\"]",
            "password",
            "passwd",
            "db_pass",
            "secret",
        ),
        "medium",
        "PHP config array with credentials in response",
    ),
]

# VCS metadata exposure.
_SRCLEAK_VCS = [
    (
        "git-metadata",
        gate(
            r"ref:\s+refs/heads/|\[core\][\s\S]{0,40}repositoryformatversion",
            "refs/heads/",
            "repositoryformatversion",
        ),
        "high",
        ".git metadata returned in response",
    ),
]

_SRCLEAK_SHEBANG = gate(
    r"(?m)^#!\s*(?:\S*/)?(?:env\s+)?(?:python\d?|bash|sh|perl|ruby|node|php)\b",
    "#!",
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
