"""
passive_scan.py — passive vulnerability scanners over a Caido Request Utility DB.

PASSIVE ONLY. Reads the `requests` table CRU builds and inspects the request and
response fields you already captured. It sends no traffic. Findings are leads to
verify against systems you're authorised to test.

Two checks are implemented, both as pluggable `Check`s so more (headers, CORS,
reflection, ...) can be added behind the same runner:

  deser   — serialized-object / insecure-deserialization payload indicators
            (Java, .NET BinaryFormatter/ViewState, PHP, Python pickle, Ruby
            Marshal, node-serialize, Jackson/fastjson, YAML gadgets, XMLDecoder),
            checked both as raw strings and by base64-decoding blobs and testing
            their magic bytes.
  secrets — TruffleHog-style secret detection: a high-precision detector table
            (AWS, GitHub, GitLab, Slack, Stripe, Google, OpenAI, Anthropic,
            SendGrid, npm, private keys, JWTs, ...) plus Shannon-entropy scanning
            for unlabelled high-entropy tokens. Scans responses too — leaked keys
            in JS/JSON bodies are common and high-value.

Usage:
    python -m cru.passive_scan test.db                 # run all checks
    python -m cru.passive_scan test.db --check secrets
    python -m cru.passive_scan test.db --json > findings.json
    python -m cru.passive_scan test.db --show-secrets   # unredact matches (careful)

Handoff to real TruffleHog (its full, *verified* detector set) if you want it:
    python -m cru.passive_scan test.db --dump-fields ./corpus_fields
    trufflehog filesystem ./corpus_fields --results=verified,unknown

Stdlib only.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import math
import re
import sqlite3
from dataclasses import asdict, dataclass
from urllib.parse import parse_qsl, unquote_plus

# --------------------------------------------------------------------------- #
# Finding + field iteration
# --------------------------------------------------------------------------- #


@dataclass
class _Finding:
    check: str
    signature: str  # detector / payload family name
    host: str
    method: str
    path: str
    location: str  # which field: request-body, response-headers, ...
    evidence: str  # redacted/truncated snippet
    detail: str = ""

    def key(self):
        return (
            self.check,
            self.signature,
            self.host,
            self.path,
            self.location,
            self.evidence,
        )


def Finding(
    check, severity, signature, host, method, path, location, evidence, detail=""
):
    """Construct a finding.

    `severity` is still accepted so the individual checks don't need changing,
    but it is intentionally discarded — this tool does not rank findings by
    severity. Everything downstream (dedup, output, report) ignores it.
    """
    return _Finding(check, signature, host, method, path, location, evidence, detail)


# Fields worth scanning, with a stable label. We scan the response side too.
_SCAN_FIELDS = (
    ("request-cookies", "cookies"),
    ("request-headers", "headers"),
    ("request-query", "query"),
    ("request-body", "body"),
    ("response-headers", "response_headers"),
    ("response-body", "response_body"),
)

_MAX_FIELD = 400_000  # cap per-field bytes scanned to keep it quick


# Injection checks care about direction: a payload lives in the *request*, its
# effect (error/evaluated result) shows in the *response*.
_REQUEST_FIELDS = (
    ("request-cookies", "cookies"),
    ("request-headers", "headers"),
    ("request-query", "query"),
    ("request-body", "body"),
)
_RESPONSE_FIELDS = (
    ("response-headers", "response_headers"),
    ("response-body", "response_body"),
)

# Encoding coverage: many payloads are wrapped in base64 or hex to slip past a
# naive scan. The decoded plaintext is computed ONCE at import time and stored in
# `<field>_decoded` columns (see field_decode). The field-access helpers surface
# those columns as extra "#decoded" views so every pattern check gets encoding
# coverage without decoding per row. DBs imported before these columns existed
# simply have no decoded views (see _decoded_col).

# base column -> its decoded companion column
_DECODED_COL = {
    "query": "query_decoded",
    "body": "body_decoded",
    "cookies": "cookies_decoded",
    "headers": "headers_decoded",
    "response_body": "response_body_decoded",
}


def _row_has(row, col):
    """True if the sqlite Row actually carries a column (older DBs may not)."""
    try:
        return row[col] is not None
    except (IndexError, KeyError):
        return False


def _decoded_for(row, col):
    """Return the precomputed decoded plaintext for a base column, or ''."""
    dcol = _DECODED_COL.get(col)
    if dcol and _row_has(row, dcol):
        return row[dcol] or ""
    return ""


def request_inputs(row):
    """Yield (label, text) for request-side inputs.

    Emits the URL-decoded field, plus a "#decoded" view holding the base64/hex
    plaintext recovered at import time, so pattern checks get encoding coverage.
    """
    for label, col in _REQUEST_FIELDS:
        val = row[col]
        if val:
            yield label, unquote_plus(str(val)[:_MAX_FIELD])
        dec = _decoded_for(row, col)
        if dec:
            yield f"{label}#decoded", dec[:_MAX_FIELD]


def iter_fields(row):
    """Yield (label, text) for each scannable field, plus its "#decoded" view."""
    for label, col in _SCAN_FIELDS:
        val = row[col]
        if val:
            text = val if isinstance(val, str) else str(val)
            yield label, text[:_MAX_FIELD]
        dec = _decoded_for(row, col)
        if dec:
            yield f"{label}#decoded", dec[:_MAX_FIELD]


def response_text(row):
    """Return concatenated response headers+body (for error/result matching)."""
    parts = []
    for _, col in _RESPONSE_FIELDS:
        val = row[col]
        if val:
            parts.append(str(val)[:_MAX_FIELD])
    return "\n".join(parts)


def _status(row):
    try:
        return int(row["response_status_code"])
    except (ValueError, TypeError):
        return None


# --------------------------------------------------------------------------- #
# base64 / entropy helpers
# --------------------------------------------------------------------------- #

_B64_TOKEN = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_B64URL_TOKEN = re.compile(r"[A-Za-z0-9_-]{16,}")


def _b64_decode_variants(tok: str):
    """Try standard and url-safe base64; return decoded bytes or None."""
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            pad = "=" * (-len(tok) % 4)
            raw = decoder(tok + pad)
            if raw:
                return raw
        except (ValueError, binascii.Error):
            continue
    return None


def b64_blobs(text: str):
    """Yield (token, decoded_bytes) for base64-ish tokens, deduped by content."""
    seen_tokens, seen_decoded = set(), set()
    for rx in (_B64_TOKEN, _B64URL_TOKEN):
        for m in rx.finditer(text):
            tok = m.group(0)
            if tok in seen_tokens or len(tok) < 16:
                continue
            seen_tokens.add(tok)
            raw = _b64_decode_variants(tok)
            if raw and raw not in seen_decoded:
                seen_decoded.add(raw)
                yield tok, raw


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


# --------------------------------------------------------------------------- #
# Check 1: deserialization / serialized-object payloads
# --------------------------------------------------------------------------- #

# Raw-string signatures: (family, compiled regex, severity, detail)
_DESER_STRING_SIGS = [
    (
        "php-serialized-object",
        re.compile(r'O:\d+:"[^"]+":\d+:\{'),
        "high",
        'PHP serialized object (O:len:"class":...) — insecure unserialize()/POP chain',
    ),
    (
        "php-serialized-array",
        re.compile(r"a:\d+:\{[si]:\d+"),
        "review",
        "PHP serialized array — often benign, but an unserialize() sink",
    ),
    (
        "phar-wrapper",
        re.compile(r"phar://"),
        "high",
        "phar:// stream wrapper — PHAR deserialization",
    ),
    (
        "node-serialize-rce",
        re.compile(r"_\$\$ND_FUNC\$\$_"),
        "high",
        "node-serialize IIFE marker — RCE on unserialize()",
    ),
    (
        "java-xmldecoder",
        re.compile(r"<(?:java|object\s+class=)", re.IGNORECASE),
        "high",
        "Java XMLDecoder / bean XML — RCE via <object class=...>",
    ),
    (
        "jackson-fastjson-polymorphic",
        re.compile(r'"@(?:type|class)"\s*:'),
        "high",
        "Polymorphic type hint (@type/@class) — Jackson/fastjson gadget vector",
    ),
    (
        "yaml-object-tag",
        re.compile(r"!!?(?:python/object|ruby/object|javax\.|com\.|java\.)"),
        "high",
        "YAML language/object tag — unsafe load() gadget",
    ),
    (
        "dotnet-viewstate-param",
        re.compile(r"__VIEWSTATE=|__VIEWSTATEGENERATOR="),
        "medium",
        "ASP.NET __VIEWSTATE — check for missing MAC (ViewState deserialization)",
    ),
    (
        "java-serialized-b64",
        re.compile(r"\brO0AB[A-Za-z0-9+/]"),
        "high",
        "Java serialized object, base64 (magic AC ED 00 05)",
    ),
    (
        "dotnet-binaryformatter-b64",
        re.compile(r"AAEAAAD/////"),
        "high",
        "..NET BinaryFormatter header, base64 (00 01 00 00 00 FF FF FF FF)",
    ),
    (
        "ruby-marshal-b64",
        re.compile(r"\bBAh[A-Za-z0-9+/]{8,}"),
        "medium",
        "Ruby Marshal blob, base64 (magic 04 08)",
    ),
    (
        "java-serialized-content-type",
        re.compile(r"application/x-java-serialized-object", re.IGNORECASE),
        "high",
        "Content-Type advertises a Java serialized object",
    ),
]

# Magic-byte signatures checked against base64-DECODED blobs.
_DESER_MAGIC_SIGS = [
    (
        "java-serialized",
        b"\xac\xed\x00\x05",
        "high",
        "Java serialized object magic (decoded)",
    ),
    (
        "dotnet-binaryformatter",
        b"\x00\x01\x00\x00\x00\xff\xff\xff\xff",
        "high",
        ".NET BinaryFormatter magic (decoded)",
    ),
    ("ruby-marshal", b"\x04\x08", "medium", "Ruby Marshal magic (decoded)"),
    (
        "gzip-wrapped-blob",
        b"\x1f\x8b",
        "review",
        "gzip stream (decoded) — decompress and re-check for a nested payload",
    ),
]

_PICKLE_OPCODES = (
    b"c__builtin__",
    b"cos\nsystem",
    b"cposix\nsystem",
    b"csubprocess",
    b"cnt\nsystem",
    b"\x80\x02",
    b"\x80\x03",
    b"\x80\x04",
    b"\x80\x05",
)


def _looks_pickle(raw: bytes) -> bool:
    head = raw[:2]
    if head[:1] == b"\x80" and head[1:2] in (b"\x02", b"\x03", b"\x04", b"\x05"):
        return True
    return any(op in raw[:64] for op in _PICKLE_OPCODES)


class DeserializationScanner:
    name = "deser"

    def run(self, rows):
        out = []
        for r in rows:
            for label, text in iter_fields(r):
                probe = unquote_plus(text)
                # raw-string signatures
                for fam, rx, sev, detail in _DESER_STRING_SIGS:
                    m = rx.search(probe)
                    if m:
                        out.append(
                            Finding(
                                self.name,
                                sev,
                                fam,
                                r["host"],
                                r["method"],
                                r["path"],
                                label,
                                _snippet(m.group(0)),
                                detail,
                            )
                        )
                # base64 magic-byte signatures
                for tok, raw in b64_blobs(probe):
                    for fam, magic, sev, detail in _DESER_MAGIC_SIGS:
                        if raw.startswith(magic):
                            out.append(
                                Finding(
                                    self.name,
                                    sev,
                                    fam,
                                    r["host"],
                                    r["method"],
                                    r["path"],
                                    label,
                                    _snippet(tok),
                                    detail,
                                )
                            )
                    if _looks_pickle(raw):
                        out.append(
                            Finding(
                                self.name,
                                "high",
                                "python-pickle",
                                r["host"],
                                r["method"],
                                r["path"],
                                label,
                                _snippet(tok),
                                "Python pickle opcodes (decoded) — RCE on loads()",
                            )
                        )
        return _dedupe(out)


# --------------------------------------------------------------------------- #
# Check 2: secrets (TruffleHog-style)
# --------------------------------------------------------------------------- #

# High-precision detectors: (name, regex, severity)
_SECRET_DETECTORS = [
    (
        "aws-access-key-id",
        re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA)[0-9A-Z]{16}\b"),
        "high",
    ),
    ("github-pat", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36}\b"), "high"),
    ("github-fine-grained-pat", re.compile(r"\bgithub_pat_[0-9A-Za-z_]{82}\b"), "high"),
    ("gitlab-pat", re.compile(r"\bglpat-[0-9A-Za-z_\-]{20}\b"), "high"),
    ("slack-token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,64}\b"), "high"),
    (
        "slack-webhook",
        re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+"),
        "medium",
    ),
    ("stripe-live-key", re.compile(r"\b[sr]k_live_[0-9A-Za-z]{20,}\b"), "high"),
    ("stripe-test-key", re.compile(r"\b[sr]k_test_[0-9A-Za-z]{20,}\b"), "low"),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "high"),
    ("google-oauth-token", re.compile(r"\bya29\.[0-9A-Za-z_\-]{20,}"), "medium"),
    (
        "openai-key",
        re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}T3BlbkFJ[A-Za-z0-9_\-]{20,}\b"),
        "high",
    ),
    ("anthropic-key", re.compile(r"\bsk-ant-[0-9A-Za-z_\-]{20,}\b"), "high"),
    (
        "sendgrid-key",
        re.compile(r"\bSG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}\b"),
        "high",
    ),
    ("npm-token", re.compile(r"\bnpm_[0-9A-Za-z]{36}\b"), "high"),
    ("twilio-api-key", re.compile(r"\bSK[0-9a-fA-F]{32}\b"), "medium"),
    ("mailgun-key", re.compile(r"\bkey-[0-9a-f]{32}\b"), "medium"),
    (
        "private-key-block",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
        "high",
    ),
    (
        "jwt",
        re.compile(
            r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"
        ),
        "medium",
    ),
    (
        "basic-auth-header",
        re.compile(r"(?i)authorization:\s*basic\s+[A-Za-z0-9+/=]{8,}"),
        "medium",
    ),
    # Generic assignment — noisy, so it's reported at review tier.
    (
        "generic-secret-assignment",
        re.compile(
            r"(?i)(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|"
            r"auth[_-]?token|client[_-]?secret|private[_-]?key)"
            r"[\"'\s:=]{1,4}[\"']?([^\s\"'&;]{6,})"
        ),
        "review",
    ),
]

# entropy config
_ENTROPY_B64_MIN = 4.5
_ENTROPY_HEX_MIN = 3.0
_ENTROPY_MIN_LEN = 20
_HEXish = re.compile(r"^[0-9a-fA-F]+$")
# Skip contexts/values that entropy loves but that aren't secrets.
_ENTROPY_SKIP = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-",
)  # UUID prefix


class SecretScanner:
    name = "secrets"

    def __init__(self, entropy=True):
        self.entropy = entropy

    def run(self, rows):
        out = []
        for r in rows:
            for label, text in iter_fields(r):
                # 1) high-precision detectors
                for name, rx, sev in _SECRET_DETECTORS:
                    for m in rx.finditer(text):
                        hit = m.group(1) if (m.groups() and m.group(1)) else m.group(0)
                        out.append(
                            Finding(
                                self.name,
                                sev,
                                name,
                                r["host"],
                                r["method"],
                                r["path"],
                                label,
                                hit.strip(),
                                "matched detector pattern",
                            )
                        )
                # 2) entropy pass for unlabelled high-entropy tokens
                if self.entropy:
                    out.extend(self._entropy(r, label, text))
        return _dedupe(out)

    def _entropy(self, r, label, text):
        found = []
        for m in _B64_TOKEN.finditer(text):
            tok = m.group(0)
            if len(tok) < _ENTROPY_MIN_LEN or _ENTROPY_SKIP.match(tok):
                continue
            is_hex = bool(_HEXish.match(tok))
            ent = shannon_entropy(tok)
            thresh = _ENTROPY_HEX_MIN if is_hex else _ENTROPY_B64_MIN
            if ent >= thresh:
                # 24/32/40/64 hex are usually hashes or resource IDs, not
                # secrets -> skip. 24 is a Mongo ObjectId; those are worth
                # keeping as *enumeration* candidates rather than secrets, and
                # idor_finder already classifies them (`_OBJECTID_RE`, id_type
                # "objectid") for exactly that.
                if is_hex and len(tok) in (24, 32, 40, 64):
                    continue
                found.append(
                    Finding(
                        self.name,
                        "review",
                        "high-entropy-string",
                        r["host"],
                        r["method"],
                        r["path"],
                        label,
                        tok,
                        f"entropy={ent:.2f} len={len(tok)} — unlabelled, verify by hand",
                    )
                )
        return found


# --------------------------------------------------------------------------- #
# Check 3: SQL injection (passive)
# --------------------------------------------------------------------------- #

# DBMS error fingerprints seen in responses. A DB error leaking to the client
# means input reached the query engine and wasn't handled — strong SQLi signal.
_SQL_ERROR_SIGS = [
    (
        "mysql",
        re.compile(
            r"SQL syntax.*MySQL|Warning.*\bmysqli?_|MySqlException|"
            r"com\.mysql\.jdbc|MySQLSyntaxErrorException|valid MySQL result|"
            r"check the manual that corresponds to your (?:MySQL|MariaDB)",
            re.IGNORECASE,
        ),
    ),
    (
        "postgresql",
        re.compile(
            r"PostgreSQL.*ERROR|pg_(?:query|exec)\(\)|PG::\w*Error|"
            r"unterminated quoted string at or near|org\.postgresql\.util\.PSQLException|"
            r"invalid input syntax for",
            re.IGNORECASE,
        ),
    ),
    (
        "mssql",
        re.compile(
            r"Unclosed quotation mark after the character string|"
            r"Microsoft OLE DB Provider for SQL Server|Incorrect syntax near|"
            r"System\.Data\.SqlClient\.SqlException|com\.microsoft\.sqlserver\.jdbc|"
            r"\[SQL Server\]|SQLServer JDBC Driver|Unicode data in a Unicode-only",
            re.IGNORECASE,
        ),
    ),
    (
        "oracle",
        re.compile(
            r"\bORA-\d{5}\b|Oracle error|Oracle.*Driver|quoted string not properly terminated|"
            r"oracle\.jdbc|OracleException",
            re.IGNORECASE,
        ),
    ),
    (
        "sqlite",
        re.compile(
            r"SQLITE_ERROR|sqlite3?\.OperationalError|unrecognized token:|"
            r"SQLite/JDBCDriver|\[SQLITE_ERROR\]|SQL logic error",
            re.IGNORECASE,
        ),
    ),
    (
        "generic-jdbc-odbc",
        re.compile(
            r"java\.sql\.SQL(?:Syntax)?(?:Error)?Exception|"
            r"\[Microsoft\]\[ODBC|Microsoft JET Database Engine|DB2 SQL error|"
            r"SQLSTATE\[",
            re.IGNORECASE,
        ),
    ),
]

# SQLi-shaped payloads observed in request inputs.
_SQLI_PAYLOAD_SIGS = [
    ("tautology", re.compile(r"(?i)('|\b)(?:or|and)\b\s*'?\d+'?\s*=\s*'?\d+")),
    ("union-select", re.compile(r"(?i)\bunion\b\s+(?:all\s+)?\bselect\b")),
    ("comment-terminator", re.compile(r"(?:'|\")\s*(?:--|#|/\*)")),
    (
        "stacked-query",
        re.compile(r"(?i);\s*(?:drop|insert|update|delete|select|exec)\b"),
    ),
    (
        "time-based",
        re.compile(r"(?i)\b(?:sleep|pg_sleep|benchmark)\s*\(|\bwaitfor\s+delay\b"),
    ),
    (
        "error-based-fn",
        re.compile(r"(?i)\b(?:extractvalue|updatexml|exp|floor)\s*\(\s*"),
    ),
    ("quote-tautology", re.compile(r"(?i)'\s*or\s+'[^']*'\s*=\s*'")),
]

# Parameter *names* that hand the caller part of the query. Tiered like the code
# check: `sink` is a name advertising raw SQL, `clause` is a bare SQL clause name
# — the API composes its query from caller input even when the value is not raw
# SQL. Matching "sql" anywhere in the name covers the permutations seen in the
# wild: sqlQuery, sql_query, sql-query, SQLQuery, rawSql, execSQL, sqlStatement.
# (family, tier, severity, regex over the parameter name)
_SQL_PARAM_SIGS = [
    ("raw-sql-name", "sink", "high", re.compile(r"(?i)sql")),
    (
        "clause-name",
        "clause",
        "medium",
        re.compile(
            r"(?i)^(?:where|where[_-]?clause|order[_-]?by|orderby|sort[_-]?by|"
            r"group[_-]?by|groupby|having|select|from|table|table[_-]?name)$"
        ),
    ),
]


class SqliScanner:
    name = "sqli"

    def run(self, rows):
        out = []
        for r in rows:
            resp = response_text(r)
            status = _status(r)

            # (a) DB error leaking in the response — always report.
            errored = None
            for dbms, rx in _SQL_ERROR_SIGS:
                m = rx.search(resp)
                if m:
                    errored = dbms
                    out.append(
                        Finding(
                            self.name,
                            "high",
                            f"sql-error-in-response ({dbms})",
                            r["host"],
                            r["method"],
                            r["path"],
                            "response",
                            _snippet(m.group(0)),
                            "DBMS error reached the client — error-based SQLi surface",
                        )
                    )
                    break

            # (b) SQLi-shaped payloads in request inputs, escalated if the same
            #     response errored or 5xx'd.
            for label, text in request_inputs(r):
                for fam, rx in _SQLI_PAYLOAD_SIGS:
                    m = rx.search(text)
                    if not m:
                        continue
                    if errored:
                        sev, detail = "high", (
                            f"SQLi payload + {errored} error in same response — "
                            "likely injectable"
                        )
                    elif status and status >= 500:
                        sev, detail = "high", (
                            "SQLi payload + HTTP 5xx — likely injectable"
                        )
                    else:
                        sev, detail = "medium", (
                            "SQLi-shaped input observed — confirm response diff "
                            "vs a clean request"
                        )
                    out.append(
                        Finding(
                            self.name,
                            sev,
                            f"sqli-payload:{fam}",
                            r["host"],
                            r["method"],
                            r["path"],
                            label,
                            _snippet(m.group(0)),
                            detail,
                        )
                    )

            # (c) parameter names that advertise a query-composition sink,
            #     escalated the same way.
            for loc, val in request_param_values(r):
                pname = loc.split(":")[-1]
                for fam, tier, base_sev, rx in _SQL_PARAM_SIGS:
                    if not rx.search(pname):
                        continue
                    if errored:
                        sev, detail = "high", (
                            f"query-composition parameter + {errored} error in "
                            "same response — likely injectable"
                        )
                    elif status and status >= 500:
                        sev, detail = "high", (
                            "query-composition parameter + HTTP 5xx — likely "
                            "injectable"
                        )
                    elif tier == "sink":
                        sev, detail = base_sev, (
                            "parameter name advertises a raw SQL sink — the "
                            "caller supplies the query text"
                        )
                    else:
                        sev, detail = base_sev, (
                            "SQL clause name as a parameter — the query is "
                            "composed from caller input"
                        )
                    out.append(
                        Finding(
                            self.name,
                            sev,
                            f"sqli-param:{fam} ({tier})",
                            r["host"],
                            r["method"],
                            r["path"],
                            loc,
                            _snippet(val),
                            detail,
                        )
                    )
                    break

        return _dedupe(out)


# --------------------------------------------------------------------------- #
# Check 4: Server-Side Template Injection — request-side syntax flagging
# --------------------------------------------------------------------------- #
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


# --------------------------------------------------------------------------- #
# Check 5: code-bearing inputs — flag fields that look like source/commands
# --------------------------------------------------------------------------- #
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
            r"\$\([^)]{1,200}\)|`[^`]{1,200}`|/bin/(?:ba|z|)sh\b|"
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
            for label, text in request_inputs(r):
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


# --------------------------------------------------------------------------- #
# Check 6: source-code / config disclosure in responses
# --------------------------------------------------------------------------- #
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


# --------------------------------------------------------------------------- #
# Check 7: XSS — request payload vectors + unencoded reflection
# --------------------------------------------------------------------------- #
#
# Two signals: (1) request inputs carrying XSS payload syntax, tagged by vector;
# (2) reflection — a request parameter value echoed back in the response body.
# Reflection is the core passive XSS tell: if the value comes back with its
# dangerous characters UNENCODED, that's likely-exploitable reflected XSS; if
# encoded, it's noted only at review. Payload matches also escalate to high when
# the same payload string is found reflected in the response.

_XSS_PAYLOAD_SIGS = [
    ("script-tag", re.compile(r"(?i)<\s*script\b|<\s*/\s*script\s*>"), "high"),
    ("javascript-uri", re.compile(r"(?i)javascript:\s*\S"), "high"),
    (
        "tag-with-handler",
        re.compile(
            r"(?i)<\s*(?:img|svg|body|iframe|video|audio|details|math|object|embed|"
            r"input|marquee|form|isindex)\b[^>]{0,200}?\bon\w+\s*="
        ),
        "high",
    ),
    (
        "event-handler",
        re.compile(
            r"(?i)\bon(?:error|load|mouseover|click|focus|toggle|"
            r"animationstart|pointerover|beforetoggle)\s*="
        ),
        "medium",
    ),
    (
        "js-sink-call",
        re.compile(
            r"(?i)\b(?:alert|prompt|confirm)\s*\(|document\.(?:cookie|location|write)\b|"
            r"String\.fromCharCode\s*\("
        ),
        "medium",
    ),
    (
        "attribute-breakout",
        re.compile(r"(?:\"|')\s*>\s*<\s*\w|\"\s*on\w+\s*="),
        "medium",
    ),
    ("data-uri-html", re.compile(r"(?i)data:text/html"), "medium"),
    ("svg-math-vector", re.compile(r"(?i)<\s*svg\b|<\s*math\b"), "review"),
]

_XSS_SPECIAL = ("<", ">", '"')


def _walk_json(obj, prefix=""):
    """Yield (key_path, leaf_value) pairs from nested JSON."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, (dict, list)):
                yield from _walk_json(v, key)
            else:
                yield key, v
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            key = f"{prefix}[{i}]"
            if isinstance(v, (dict, list)):
                yield from _walk_json(v, key)
            else:
                yield key, v


def request_param_values(row):
    """Yield (location, value) for individual request parameter values."""
    if row["query"]:
        for k, v in parse_qsl(row["query"], keep_blank_values=True):
            if v:
                yield f"query:{k}", v
    body = row["body"]
    if body:
        b = body.strip()
        if b[:1] in "{[":
            try:
                for k, v in _walk_json(json.loads(b)):
                    if isinstance(v, str) and v:
                        yield f"body:{k.split('.')[-1].split('[')[0]}", v
            except (ValueError, TypeError):
                pass
        else:
            for k, v in parse_qsl(b, keep_blank_values=True):
                if v:
                    yield f"body:{k}", v


class XssScanner:
    name = "xss"

    def run(self, rows):
        out = []
        for r in rows:
            resp_body = r["response_body"] or ""

            # (1) payload vectors in request inputs
            for label, text in request_inputs(r):
                for name, rx, sev in _XSS_PAYLOAD_SIGS:
                    m = rx.search(text)
                    if not m:
                        continue
                    frag = m.group(0)
                    # Reflection only counts as exploitable if the tag-forming
                    # characters (< >) themselves came back unencoded. Inert
                    # fragments like 'alert(' or 'onerror=' can reflect even when
                    # the surrounding < > were HTML-encoded, so they don't escalate.
                    dangerous = "<" in frag or ">" in frag
                    if dangerous and frag in resp_body:
                        out.append(
                            Finding(
                                self.name,
                                "high",
                                f"xss-payload-reflected:{name}",
                                r["host"],
                                r["method"],
                                r["path"],
                                label,
                                _snippet(frag),
                                "XSS payload reflected unencoded in response — "
                                "likely exploitable",
                            )
                        )
                    else:
                        out.append(
                            Finding(
                                self.name,
                                sev,
                                f"xss-payload:{name}",
                                r["host"],
                                r["method"],
                                r["path"],
                                label,
                                _snippet(frag),
                                "XSS payload syntax in request input — review",
                            )
                        )

            # (2) reflection of parameter values (independent of payload sigs)
            for loc, val in request_param_values(r):
                if len(val) < 4 or val not in resp_body:
                    continue
                has_special = any(c in val for c in _XSS_SPECIAL)
                if has_special:
                    out.append(
                        Finding(
                            self.name,
                            "high",
                            "reflected-unencoded-input",
                            r["host"],
                            r["method"],
                            r["path"],
                            loc,
                            _snippet(val),
                            "input reflected with dangerous chars unencoded — "
                            "reflected-XSS candidate",
                        )
                    )
                elif len(val) >= 8:
                    out.append(
                        Finding(
                            self.name,
                            "review",
                            "input-reflected",
                            r["host"],
                            r["method"],
                            r["path"],
                            loc,
                            _snippet(val),
                            "input reflected in response — check output context/encoding",
                        )
                    )
        return _dedupe(out)


# --------------------------------------------------------------------------- #
# Check 8: XXE — XML external-entity indicators
# --------------------------------------------------------------------------- #
#
# Flags request inputs carrying XML entity/DOCTYPE constructs that enable XXE
# (external SYSTEM/PUBLIC entities, parameter entities, file:// and stream
# wrappers), and a response-side tell that a file read succeeded (/etc/passwd,
# win.ini). Scans both raw and URL-decoded input so encoding can't hide it.

_XXE_SIGS = [
    (
        "external-entity",
        re.compile(r"<!ENTITY\s+\S+\s+(?:SYSTEM|PUBLIC)\b", re.IGNORECASE),
        "high",
        "external entity (SYSTEM/PUBLIC) declaration — XXE",
    ),
    (
        "parameter-entity",
        re.compile(r"<!ENTITY\s+%\s+\S+", re.IGNORECASE),
        "high",
        "parameter entity — blind/OOB XXE vector",
    ),
    (
        "file-uri",
        re.compile(r"(?i)(?:SYSTEM|PUBLIC|href|src)[^\n]{0,40}?file://"),
        "high",
        "file:// URI in XML — local file read attempt",
    ),
    (
        "stream-wrapper",
        re.compile(r"(?i)php://filter|php://input|expect://|jar:|netdoc:|gopher://"),
        "high",
        "PHP/exotic stream wrapper — XXE/SSRF exfil vector",
    ),
    (
        "doctype-subset",
        re.compile(r"<!DOCTYPE\s+\S+\s*\[", re.IGNORECASE),
        "medium",
        "DOCTYPE with internal subset — entity-injection surface",
    ),
    (
        "doctype",
        re.compile(r"<!DOCTYPE\b", re.IGNORECASE),
        "review",
        "DOCTYPE declaration in input — XML entity surface",
    ),
]

# Response contents indicating a successful local file read (XXE/LFI/SSRF).
_XXE_FILE_DISCLOSURE = re.compile(
    r"root:.?:0:0:|\[fonts\]\r?\n|\[extensions\]\r?\n|" r"; for 16-bit app support"
)


class XxeScanner:
    name = "xxe"

    def run(self, rows):
        out = []
        for r in rows:
            # scan request inputs in both raw and URL-decoded form
            raw_fields = []
            for label, col in _REQUEST_FIELDS:
                val = r[col]
                if val:
                    raw = str(val)[:_MAX_FIELD]
                    raw_fields.append((label, raw))
                    dec = unquote_plus(raw)
                    if dec != raw:
                        raw_fields.append((label, dec))

            for label, text in raw_fields:
                for name, rx, sev, detail in _XXE_SIGS:
                    m = rx.search(text)
                    if m:
                        out.append(
                            Finding(
                                self.name,
                                sev,
                                f"xxe:{name}",
                                r["host"],
                                r["method"],
                                r["path"],
                                label,
                                _snippet(m.group(0)),
                                detail,
                            )
                        )

            # response-side: file contents came back
            resp = r["response_body"] or ""
            m = _XXE_FILE_DISCLOSURE.search(resp)
            if m:
                out.append(
                    Finding(
                        self.name,
                        "high",
                        "xxe:file-disclosure",
                        r["host"],
                        r["method"],
                        r["path"],
                        "response",
                        _snippet(m.group(0)),
                        "local file contents in response — successful file read "
                        "(XXE/LFI/SSRF)",
                    )
                )
        return _dedupe(out)


# --------------------------------------------------------------------------- #
# Shared helpers for the remaining checks
# --------------------------------------------------------------------------- #


def _parse_headers(blob):
    out = []
    if not blob:
        return out
    for line in str(blob).splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            out.append((k.strip(), v.strip()))
    return out


def _header_map(blob):
    return {k.lower(): v for k, v in _parse_headers(blob)}


def _b64url_json(seg):
    try:
        pad = "=" * (-len(seg) % 4)
        return json.loads(base64.urlsafe_b64decode(seg + pad))
    except Exception:  # noqa: BLE001 - any malformed JWT segment is simply not a JWT
        return None


def _emit(out, check, sev, sig, r, location, evidence, detail, host_level=False):
    out.append(
        Finding(
            check,
            sev,
            sig,
            r["host"],
            r["method"],
            "" if host_level else r["path"],
            location,
            _snippet(evidence),
            detail,
        )
    )


# --------------------------------------------------------------------------- #
# Check 9: SSRF — URLs / internal hosts / cloud metadata in request params
# --------------------------------------------------------------------------- #

_SSRF_PARAM = re.compile(
    r"(?i)^(?:url|uri|u|link|href|src|dest|destination|redirect|redirect_uri|"
    r"next|return|returnurl|returnto|continue|goto|out|target|callback|webhook|"
    r"proxy|fetch|feed|rss|load|image|imageurl|img|file|path|domain|host|site|"
    r"data|source|view|remote|upstream|forward|open|to|uri2|url2)$"
)
_URL_VALUE = re.compile(r"(?i)^(?:https?:)?//|^https?:|^ftp:|^gopher:|^dict:|^file:")
_INTERNAL_HOST = re.compile(
    r"(?i)(?:localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|10\.\d+\.\d+\.\d+|"
    r"192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|\[?::1\]?|"
    r"169\.254\.169\.254|100\.100\.100\.200|metadata\.google\.internal|"
    r"metadata\.google|169\.254\.\d+\.\d+|\.internal\b|\.local\b|"
    r"instance-data|\.consul\b)"
)
_CLOUD_META = re.compile(
    r"169\.254\.169\.254|metadata\.google|100\.100\.100\.200|" r"instance-data"
)


class SsrfScanner:
    name = "ssrf"

    def run(self, rows):
        out = []
        for r in rows:
            for loc, val in request_param_values(r):
                pname = loc.split(":")[-1].lower()
                is_url_param = bool(_SSRF_PARAM.match(pname))
                looks_url = bool(_URL_VALUE.match(val.strip()))
                internal = _INTERNAL_HOST.search(val)
                if _CLOUD_META.search(val):
                    _emit(
                        out,
                        self.name,
                        "high",
                        "ssrf:cloud-metadata",
                        r,
                        loc,
                        val,
                        "cloud metadata endpoint in a param — SSRF to "
                        "instance credentials",
                    )
                elif internal and (looks_url or is_url_param):
                    _emit(
                        out,
                        self.name,
                        "high",
                        "ssrf:internal-host",
                        r,
                        loc,
                        val,
                        "internal/loopback host in a fetch param — SSRF",
                    )
                elif is_url_param and looks_url:
                    _emit(
                        out,
                        self.name,
                        "medium",
                        "ssrf:external-url-in-param",
                        r,
                        loc,
                        val,
                        "URL in a server-fetch param — SSRF surface",
                    )
        return _dedupe(out)


# --------------------------------------------------------------------------- #
# Check 10: Open redirect — redirect params + Location reflection
# --------------------------------------------------------------------------- #

_REDIRECT_PARAM = {
    "next",
    "return",
    "returnurl",
    "returnto",
    "return_url",
    "redirect",
    "redirect_uri",
    "redirect_url",
    "url",
    "dest",
    "destination",
    "continue",
    "goto",
    "out",
    "target",
    "r",
    "u",
    "forward",
    "callback",
    "link",
    "to",
    "checkout_url",
    "success_url",
    "cancel_url",
    "back",
    "backurl",
}
_OFFSITE = re.compile(r"(?i)^(?:https?:)?//|^https?:\\|^/\\|^\\/|^https?://")


class OpenRedirectScanner:
    name = "redirect"

    def run(self, rows):
        out = []
        for r in rows:
            status = _status(r)
            location = _header_map(r["response_headers"]).get("location", "")
            for loc, val in request_param_values(r):
                pname = loc.split(":")[-1].lower()
                if pname not in _REDIRECT_PARAM:
                    continue
                if not _OFFSITE.match(val.strip()):
                    continue
                if status and 300 <= status < 400 and val.strip() in location:
                    _emit(
                        out,
                        self.name,
                        "high",
                        "open-redirect-reflected",
                        r,
                        loc,
                        val,
                        "redirect param reflected into 3xx Location — " "open redirect",
                    )
                else:
                    _emit(
                        out,
                        self.name,
                        "medium",
                        "open-redirect-candidate",
                        r,
                        loc,
                        val,
                        "offsite URL in a redirect param — test for " "open redirect",
                    )
        return _dedupe(out)


# --------------------------------------------------------------------------- #
# Check 11: Path traversal / LFI payloads in request params
# --------------------------------------------------------------------------- #

_TRAVERSAL_STRONG = re.compile(
    r"(?i)/etc/passwd|/etc/shadow|/etc/hosts|/proc/self/environ|boot\.ini|"
    r"\\windows\\win\.ini|/windows/win\.ini|c:\\windows"
)
_TRAVERSAL_SEQ = re.compile(
    r"(?:\.\.[\\/]){2,}|(?:%2e%2e[\\/%]){2,}|" r"\.\.%2f|\.\.%5c|%252e%252e"
)


class TraversalScanner:
    name = "traversal"

    def run(self, rows):
        out = []
        for r in rows:
            file_read = _XXE_FILE_DISCLOSURE.search(r["response_body"] or "")
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


# --------------------------------------------------------------------------- #
# Check 12: CRLF / HTTP header injection payloads (request-side)
# --------------------------------------------------------------------------- #
# NOTE: idox parses response headers into a dict, so injected/duplicate headers
# collapse in this corpus — response-side confirmation is unreliable here. This
# flags the request-side probe only.

_CRLF = re.compile(
    r"(?i)%0d%0a|%0a%0d|%0d%0A|\r\n|%23%0a|%e5%98%8a|%e5%98%8d|" r"\u2028|\u2029"
)


class CrlfScanner:
    name = "crlf"

    def run(self, rows):
        out = []
        for r in rows:
            for label, col in _REQUEST_FIELDS:
                val = r[col]
                if not val:
                    continue
                m = _CRLF.search(str(val))
                if m:
                    _emit(
                        out,
                        self.name,
                        "medium",
                        "crlf-injection-payload",
                        r,
                        label,
                        m.group(0),
                        "CR/LF sequence in request input — header-injection / "
                        "response-splitting probe (confirm out-of-band)",
                    )
        return _dedupe(out)


# --------------------------------------------------------------------------- #
# Check 13: NoSQL injection operators
# --------------------------------------------------------------------------- #

_NOSQL_PARAM = re.compile(
    r"\[\$(?:ne|gt|gte|lt|lte|regex|in|nin|or|and|where|"
    r"exists|expr|elemMatch|not|all)\]"
)
_NOSQL_JSON = re.compile(
    r'"\$(?:ne|gt|gte|lt|lte|regex|where|expr|function|or|'
    r'and|in|nin|exists|elemMatch)"\s*:'
)
_NOSQL_WHERE = re.compile(
    r"\$where\b|sleep\s*\(\s*\d|this\.\w+\s*==|\|\|\s*'1'\s*==\s*'1"
)


class NoSqliScanner:
    name = "nosqli"

    def run(self, rows):
        out = []
        for r in rows:
            for label, text in request_inputs(r):
                m = _NOSQL_JSON.search(text) or _NOSQL_WHERE.search(text)
                if m is not None:
                    _emit(
                        out,
                        self.name,
                        "high",
                        "nosql-operator",
                        r,
                        label,
                        m.group(0),
                        "MongoDB operator/$where in input — NoSQL " "injection",
                    )
                else:
                    m = _NOSQL_PARAM.search(text)
                    if m is None:
                        continue
                    _emit(
                        out,
                        self.name,
                        "medium",
                        "nosql-param-operator",
                        r,
                        label,
                        m.group(0),
                        "bracketed Mongo operator in param — NoSQL injection",
                    )
        return _dedupe(out)


# --------------------------------------------------------------------------- #
# Check 14: dangerous file upload filenames (multipart)
# --------------------------------------------------------------------------- #

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


# --------------------------------------------------------------------------- #
# Check 15: missing / weak response security headers (host-level)
# --------------------------------------------------------------------------- #


class SecurityHeadersScanner:
    name = "headers"

    def run(self, rows):
        out = []
        for r in rows:
            status = _status(r)
            if status is None or not (200 <= status < 400) or not r["response_body"]:
                continue
            hm = _header_map(r["response_headers"])
            ct = hm.get("content-type", "").lower()
            is_html = "text/html" in ct

            if r["is_tls"] and "strict-transport-security" not in hm:
                _emit(
                    out,
                    self.name,
                    "medium",
                    "missing-hsts",
                    r,
                    "response-headers",
                    "Strict-Transport-Security",
                    "HTTPS response without HSTS",
                    host_level=True,
                )
            if not is_html:
                continue
            csp = hm.get("content-security-policy", "")
            if not csp:
                _emit(
                    out,
                    self.name,
                    "medium",
                    "missing-csp",
                    r,
                    "response-headers",
                    "Content-Security-Policy",
                    "HTML response without a CSP",
                    host_level=True,
                )
            elif re.search(r"unsafe-inline|unsafe-eval|(?:^|\s)\*(?:\s|;|$)", csp):
                _emit(
                    out,
                    self.name,
                    "medium",
                    "weak-csp",
                    r,
                    "response-headers",
                    csp,
                    "CSP allows unsafe-inline/unsafe-eval/wildcard",
                    host_level=True,
                )
            if "x-frame-options" not in hm and "frame-ancestors" not in csp:
                _emit(
                    out,
                    self.name,
                    "medium",
                    "missing-frame-protection",
                    r,
                    "response-headers",
                    "X-Frame-Options/frame-ancestors",
                    "no clickjacking protection",
                    host_level=True,
                )
            if "x-content-type-options" not in hm:
                _emit(
                    out,
                    self.name,
                    "low",
                    "missing-nosniff",
                    r,
                    "response-headers",
                    "X-Content-Type-Options",
                    "missing nosniff",
                    host_level=True,
                )
            if "referrer-policy" not in hm:
                _emit(
                    out,
                    self.name,
                    "low",
                    "missing-referrer-policy",
                    r,
                    "response-headers",
                    "Referrer-Policy",
                    "missing",
                    host_level=True,
                )
            if "permissions-policy" not in hm:
                _emit(
                    out,
                    self.name,
                    "low",
                    "missing-permissions-policy",
                    r,
                    "response-headers",
                    "Permissions-Policy",
                    "missing",
                    host_level=True,
                )
        return _dedupe(out)


# --------------------------------------------------------------------------- #
# Check 16: CORS misconfiguration
# --------------------------------------------------------------------------- #


class CorsScanner:
    name = "cors"

    def run(self, rows):
        out = []
        for r in rows:
            hm = _header_map(r["response_headers"])
            acao = hm.get("access-control-allow-origin")
            if acao is None:
                continue
            creds = hm.get("access-control-allow-credentials", "").lower() == "true"
            origin = _header_map(r["headers"]).get("origin", "")
            if acao == "*" and creds:
                _emit(
                    out,
                    self.name,
                    "high",
                    "cors:wildcard-with-credentials",
                    r,
                    "response-headers",
                    acao,
                    "ACAO * with credentials — invalid but often mishandled",
                )
            elif acao == "null":
                _emit(
                    out,
                    self.name,
                    "high",
                    "cors:null-origin",
                    r,
                    "response-headers",
                    acao,
                    "ACAO null — bypassable via sandboxed iframe"
                    + (" WITH credentials" if creds else ""),
                )
            elif origin and acao == origin and creds:
                _emit(
                    out,
                    self.name,
                    "high",
                    "cors:reflected-origin",
                    r,
                    "response-headers",
                    acao,
                    "ACAO reflects request Origin with credentials — "
                    "cross-origin data theft",
                )
            elif acao == "*":
                _emit(
                    out,
                    self.name,
                    "low",
                    "cors:wildcard",
                    r,
                    "response-headers",
                    acao,
                    "ACAO * (no credentials) — exposes non-cookie responses",
                )
        return _dedupe(out)


# --------------------------------------------------------------------------- #
# Check 17: cookie flags (from Set-Cookie)
# --------------------------------------------------------------------------- #
# NOTE: idox collapses duplicate headers, so multiple Set-Cookie lines may not
# all survive in this corpus — treat absence of a cookie as "not observed".

_SESSION_COOKIE = re.compile(r"(?i)sess|sid|token|auth|jwt|login|remember|csrf")


class CookieScanner:
    name = "cookies"

    def run(self, rows):
        out = []
        for r in rows:
            for k, v in _parse_headers(r["response_headers"]):
                if k.lower() != "set-cookie":
                    continue
                name = v.split("=", 1)[0].strip()
                low = v.lower()
                sessionish = bool(_SESSION_COOKIE.search(name))
                if "httponly" not in low and sessionish:
                    _emit(
                        out,
                        self.name,
                        "medium",
                        "cookie-no-httponly",
                        r,
                        "set-cookie",
                        name,
                        f"session-like cookie '{name}' without HttpOnly",
                        host_level=True,
                    )
                if r["is_tls"] and "secure" not in low:
                    _emit(
                        out,
                        self.name,
                        "medium" if sessionish else "low",
                        "cookie-no-secure",
                        r,
                        "set-cookie",
                        name,
                        f"cookie '{name}' without Secure over HTTPS",
                        host_level=True,
                    )
                if "samesite" not in low:
                    _emit(
                        out,
                        self.name,
                        "low",
                        "cookie-no-samesite",
                        r,
                        "set-cookie",
                        name,
                        f"cookie '{name}' without SameSite",
                        host_level=True,
                    )
        return _dedupe(out)


# --------------------------------------------------------------------------- #
# Check 18: JWT weaknesses
# --------------------------------------------------------------------------- #

_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*")


class JwtScanner:
    name = "jwt"

    def run(self, rows):
        out = []
        for r in rows:
            seen = set()
            for label, text in list(request_inputs(r)) + [
                ("response", response_text(r))
            ]:
                for m in _JWT_RE.finditer(text):
                    tok = m.group(0)
                    if tok in seen:
                        continue
                    seen.add(tok)
                    parts = tok.split(".")
                    header = _b64url_json(parts[0])
                    payload = _b64url_json(parts[1]) if len(parts) > 1 else None
                    if not header:
                        continue
                    alg = str(header.get("alg", "")).lower()
                    if alg == "none":
                        _emit(
                            out,
                            self.name,
                            "high",
                            "jwt:alg-none",
                            r,
                            label,
                            tok[:24],
                            "JWT alg=none — signature bypass",
                        )
                    elif alg.startswith("hs"):
                        _emit(
                            out,
                            self.name,
                            "review",
                            "jwt:hmac-alg",
                            r,
                            label,
                            f"alg={alg}",
                            "HMAC-signed JWT — test for weak/" "guessable signing key",
                        )
                    if len(parts) > 2 and parts[2] == "":
                        _emit(
                            out,
                            self.name,
                            "high",
                            "jwt:empty-signature",
                            r,
                            label,
                            tok[:24],
                            "JWT with empty signature segment",
                        )
                    if payload and "exp" not in payload:
                        _emit(
                            out,
                            self.name,
                            "medium",
                            "jwt:no-expiry",
                            r,
                            label,
                            "no exp claim",
                            "JWT without expiry — token never " "expires",
                        )
        return _dedupe(out)


# --------------------------------------------------------------------------- #
# Check 19: info / stack-trace / debug disclosure in responses
# --------------------------------------------------------------------------- #

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


# --------------------------------------------------------------------------- #
# Check 20: technology / version fingerprint disclosure (host-level)
# --------------------------------------------------------------------------- #

_BANNER_HEADERS = (
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
    "x-runtime",
    "x-drupal-cache",
    "x-varnish",
)
_VERSIONED = re.compile(r"\d+\.\d+")
_FRAMEWORK_COOKIE = re.compile(
    r"(?i)^(PHPSESSID|JSESSIONID|ASP\.NET_SessionId|ASPSESSIONID|laravel_session|"
    r"connect\.sid|_rails|CFID|CFTOKEN|symfony|django_|csrftoken|_session_id)"
)


class FingerprintScanner:
    name = "fingerprint"

    def run(self, rows):
        out = []
        for r in rows:
            for k, v in _parse_headers(r["response_headers"]):
                lk = k.lower()
                if lk in _BANNER_HEADERS and v:
                    sev = "low" if _VERSIONED.search(v) else "review"
                    _emit(
                        out,
                        self.name,
                        sev,
                        f"banner:{lk}",
                        r,
                        "response-headers",
                        f"{k}: {v}",
                        "server/framework version banner exposed"
                        + (" (version disclosed)" if sev == "low" else ""),
                        host_level=True,
                    )
                if lk == "set-cookie":
                    name = v.split("=", 1)[0].strip()
                    if _FRAMEWORK_COOKIE.match(name):
                        _emit(
                            out,
                            self.name,
                            "review",
                            "framework-cookie",
                            r,
                            "set-cookie",
                            name,
                            f"framework fingerprint via cookie '{name}'",
                            host_level=True,
                        )
        return _dedupe(out)


# --------------------------------------------------------------------------- #
# Check 21: dangerous HTTP methods observed
# --------------------------------------------------------------------------- #

_DANGEROUS_METHODS = {"PUT", "DELETE", "TRACE", "CONNECT", "PATCH", "TRACK"}


class MethodScanner:
    name = "methods"

    def run(self, rows):
        out = []
        for r in rows:
            method = (r["method"] or "").upper()
            if method not in _DANGEROUS_METHODS:
                continue
            status = _status(r)
            accepted = status is not None and status < 405
            sev = (
                "medium"
                if (method in {"TRACE", "TRACK", "CONNECT"} or accepted)
                else "review"
            )
            note = f"{method} observed"
            if method in {"TRACE", "TRACK"}:
                note += " — Cross-Site Tracing (XST) risk"
            elif accepted:
                note += f" — endpoint responded {status} (method allowed)"
            _emit(
                out,
                self.name,
                sev,
                f"method:{method}",
                r,
                "request",
                f"{method} {r['path']}",
                note,
                host_level=True,
            )
        return _dedupe(out)


# --------------------------------------------------------------------------- #
# Check 22: mixed content (HTTP resources on an HTTPS page)
# --------------------------------------------------------------------------- #

_MIXED = re.compile(r"(?i)(?:src|href|action)\s*=\s*[\"']http://[^\"']+")


class MixedContentScanner:
    name = "mixedcontent"

    def run(self, rows):
        out = []
        for r in rows:
            if not r["is_tls"]:
                continue
            ct = _header_map(r["response_headers"]).get("content-type", "").lower()
            if "text/html" not in ct:
                continue
            m = _MIXED.search(r["response_body"] or "")
            if m:
                _emit(
                    out,
                    self.name,
                    "medium",
                    "mixed-content",
                    r,
                    "response-body",
                    m.group(0),
                    "HTTP sub-resource referenced from an HTTPS page",
                    host_level=True,
                )
        return _dedupe(out)


# --------------------------------------------------------------------------- #
# Check 23: cleartext transmission of secrets / session
# --------------------------------------------------------------------------- #

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


# --------------------------------------------------------------------------- #
# Check 24: missing CSRF protection (heuristic)
# --------------------------------------------------------------------------- #

_STATE_CHANGING = {"POST", "PUT", "DELETE", "PATCH"}
_CSRF_TOKEN = re.compile(
    r"(?i)csrf|xsrf|authenticity_token|__requestverification|"
    r"_token\b|anti.?forgery|request_?token"
)


class CsrfScanner:
    name = "csrf"

    def run(self, rows):
        out = []
        for r in rows:
            if (r["method"] or "").upper() not in _STATE_CHANGING:
                continue
            if not r["cookies"]:
                continue  # no cookie-based session -> CSRF less relevant
            hay = " ".join(filter(None, [r["query"], r["body"], r["headers"]]))
            if _CSRF_TOKEN.search(hay):
                continue
            _emit(
                out,
                self.name,
                "review",
                "missing-csrf-token",
                r,
                "request",
                f"{r['method']} {r['path']}",
                "state-changing cookie-authenticated request with no visible "
                "CSRF token — verify anti-CSRF protection",
            )
        return _dedupe(out)


# --------------------------------------------------------------------------- #
# Formatting helpers
# --------------------------------------------------------------------------- #


def _snippet(s: str, n: int = 60) -> str:
    s = s.replace("\n", "\\n")
    return s if len(s) <= n else s[:n] + "…"


def redact(secret: str, show=False) -> str:
    if show:
        return secret
    s = secret.strip()
    if len(s) <= 8:
        return s[0] + "…" if s else ""
    return f"{s[:4]}…{s[-2:]} ({len(s)} chars)"


def _dedupe(findings):
    seen, out = set(), []
    for f in findings:
        k = f.key()
        if k not in seen:
            seen.add(k)
            out.append(f)
    return out


def _present(findings, show_secrets=False):
    """Redact secret-check evidence for display unless show_secrets is set."""
    for f in findings:
        if f.check == "secrets" and not show_secrets:
            f.evidence = redact(f.evidence)
    return findings


def render_text(findings):
    if not findings:
        return "No findings."
    findings = sorted(findings, key=lambda f: (f.check, f.host, f.path))
    by_check = {}
    for f in findings:
        by_check.setdefault(f.check, []).append(f)

    lines = []
    for check, items in by_check.items():
        lines.append(f"== {check} : {len(items)} finding(s) ==")
        lines.append("")
        for f in items:
            lines += [
                f"  {f.signature}",
                f"    {f.method} {f.host}{f.path}",
                f"    in    : {f.location}",
                f"    match : {f.evidence}",
                f"    note  : {f.detail}",
                "",
            ]
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Runner / CLI
# --------------------------------------------------------------------------- #


def load_rows(db_path, table="requests"):
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    base = (
        "host, method, path, query, cookies, headers, body, is_tls, "
        "response_status_code, response_headers, response_body"
    )
    decoded = (
        "query_decoded, body_decoded, cookies_decoded, "
        "headers_decoded, response_body_decoded"
    )
    try:
        # Prefer the decoded columns; fall back for DBs imported before they
        # existed (e.g. an older CRU/Caido database).
        try:
            return con.execute(f"SELECT {base}, {decoded} FROM {table}").fetchall()
        except sqlite3.OperationalError:
            return con.execute(f"SELECT {base} FROM {table}").fetchall()
    finally:
        con.close()


def build_checks(selected):
    available = {
        "deser": DeserializationScanner(),
        "secrets": SecretScanner(),
        "sqli": SqliScanner(),
        "ssti": SstiScanner(),
        "code": CodeScanner(),
        "srcleak": SourceLeakScanner(),
        "xss": XssScanner(),
        "xxe": XxeScanner(),
        "ssrf": SsrfScanner(),
        "redirect": OpenRedirectScanner(),
        "traversal": TraversalScanner(),
        "crlf": CrlfScanner(),
        "nosqli": NoSqliScanner(),
        "upload": UploadScanner(),
        "headers": SecurityHeadersScanner(),
        "cors": CorsScanner(),
        "cookies": CookieScanner(),
        "jwt": JwtScanner(),
        "infoleak": InfoLeakScanner(),
        "fingerprint": FingerprintScanner(),
        "methods": MethodScanner(),
        "mixedcontent": MixedContentScanner(),
        "cleartext": CleartextScanner(),
        "csrf": CsrfScanner(),
    }
    if selected == "all":
        return list(available.values())
    return [available[selected]]


def dump_fields(rows, out_dir):
    import os

    os.makedirs(out_dir, exist_ok=True)
    for i, r in enumerate(rows):
        for label, text in iter_fields(r):
            with open(
                os.path.join(out_dir, f"{i:06d}_{label}.txt"), "w", errors="replace"
            ) as fh:
                fh.write(text)


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Passive scanners over a CRU requests DB (no traffic sent)."
    )
    ap.add_argument("db")
    ap.add_argument("--table", default="requests")
    ap.add_argument(
        "--check",
        choices=(
            "all",
            "deser",
            "secrets",
            "sqli",
            "ssti",
            "code",
            "srcleak",
            "xss",
            "xxe",
            "ssrf",
            "redirect",
            "traversal",
            "crlf",
            "nosqli",
            "upload",
            "headers",
            "cors",
            "cookies",
            "jwt",
            "infoleak",
            "fingerprint",
            "methods",
            "mixedcontent",
            "cleartext",
            "csrf",
        ),
        default="all",
    )
    ap.add_argument("--json", action="store_true")
    ap.add_argument(
        "--show-secrets",
        action="store_true",
        help="do not redact secret matches (handle with care)",
    )
    ap.add_argument(
        "--no-entropy",
        action="store_true",
        help="disable entropy scanning (detectors only)",
    )
    ap.add_argument(
        "--dump-fields",
        metavar="DIR",
        help="write each scannable field to a file for real trufflehog",
    )
    args = ap.parse_args(argv)

    rows = load_rows(args.db, args.table)

    if args.dump_fields:
        dump_fields(rows, args.dump_fields)
        print(
            f"Wrote fields to {args.dump_fields}/ — "
            f"run: trufflehog filesystem {args.dump_fields}"
        )
        return

    checks = build_checks(args.check)
    if args.no_entropy:
        for c in checks:
            if isinstance(c, SecretScanner):
                c.entropy = False

    findings = []
    for c in checks:
        findings.extend(c.run(rows))

    findings = _present(findings, show_secrets=args.show_secrets)

    if args.json:
        print(json.dumps([asdict(f) for f in findings], indent=2))
    else:
        print(render_text(findings))


if __name__ == "__main__":
    main()
