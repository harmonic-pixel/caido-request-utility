"""Check 3: SQL injection (passive)"""

from __future__ import annotations

import re

from cru.checks.base import (
    Finding,
    _dedupe,
    _snippet,
    _status,
    request_inputs,
    request_param_values,
    response_text,
)

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
