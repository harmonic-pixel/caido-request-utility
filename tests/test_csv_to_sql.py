"""The CRU import path must produce the same shape passive_scan expects.

Covers the two halves of that contract: the requests table carries the
*_decoded companion columns, and populating it actually fills them, so a
base64-wrapped payload is scannable without a separate migration.
"""

import base64
import csv
import sqlite3

import pytest

import cru.csv_to_sql as c2s

pytest.importorskip("idox")

_PAYLOAD = "<?php system(1); ?>"


def _raw_request(body=None):
    body = (
        body
        if body is not None
        else "d=" + base64.b64encode(_PAYLOAD.encode()).decode()
    )
    return (
        f"POST /a?q=1 HTTP/1.1\r\n"
        f"Host: app.test\r\n"
        f"Cookie: session=abc\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(body)}\r\n\r\n{body}"
    )


def _b64_field(text):
    # populate_requests_table appends "==" before decoding, mirroring the
    # padding-free form Caido exports.
    return base64.b64encode(text.encode()).decode().rstrip("=")


@pytest.fixture
def con():
    connection = sqlite3.connect(":memory:")
    yield connection
    connection.close()


def test_requests_table_has_decoded_columns(con):
    c2s.create_request_table(con)
    cols = {r[1] for r in con.execute("PRAGMA table_info(requests)")}
    assert {
        "query_decoded",
        "body_decoded",
        "cookies_decoded",
        "headers_decoded",
        "response_body_decoded",
    } <= cols


def _insert_raw(con, n):
    for i in range(n):
        con.execute(
            "INSERT INTO raw_requests (caido_request_id, host, method, path,"
            " length, port, raw, is_tls, query, edited, created_at,"
            " response_status_code, response_raw, response_length,"
            " response_created_at)"
            " VALUES (?,'app.test','POST','/a',10,443,?,1,'q=1',0,0,200,?,2,0)",
            (
                i,
                _b64_field(_raw_request(f"n={i}")),
                _b64_field("HTTP/1.1 200 OK\r\n\r\nok"),
            ),
        )
    con.commit()


# PAGE_SIZE boundaries: an exact multiple must not drop or duplicate the last
# page, and a short final page must still be written.
@pytest.mark.parametrize("count", [0, 1, c2s.PAGE_SIZE, c2s.PAGE_SIZE + 1])
def test_populate_pages_through_every_row(con, count):
    c2s.create_raw_table(con)
    c2s.create_request_table(con)
    _insert_raw(con, count)

    c2s.populate_requests_table(con)

    assert con.execute("SELECT COUNT(*) FROM requests").fetchone()[0] == count
    assert (
        con.execute("SELECT COUNT(DISTINCT body) FROM requests").fetchone()[0] == count
    )


def test_populate_fills_decoded_columns(con):
    c2s.create_raw_table(con)
    c2s.create_request_table(con)
    con.execute(
        "INSERT INTO raw_requests (caido_request_id, host, method, path, length,"
        " port, raw, is_tls, query, edited, created_at, response_status_code,"
        " response_raw, response_length, response_created_at)"
        " VALUES (1,'app.test','POST','/a',10,443,?,1,'q=1',0,0,200,?,2,0)",
        (_b64_field(_raw_request()), _b64_field("HTTP/1.1 200 OK\r\n\r\nok")),
    )
    con.commit()

    c2s.populate_requests_table(con)

    body, body_decoded = con.execute(
        "SELECT body, body_decoded FROM requests"
    ).fetchone()
    assert "d=" in body
    assert _PAYLOAD in body_decoded, "wrapped payload was not decoded at import"


def test_populate_rebuilds_the_cookie_header(con):
    # cookies must come back as a real Cookie header value, matching what
    # burp_to_sql stores verbatim, so the two importers agree on the column.
    c2s.create_raw_table(con)
    c2s.create_request_table(con)
    raw = (
        "GET /a HTTP/1.1\r\n"
        "Host: app.test\r\n"
        "Cookie: session=abc; theme=dark\r\n\r\n"
    )
    con.execute(
        "INSERT INTO raw_requests (caido_request_id, host, method, path, length,"
        " port, raw, is_tls, query, edited, created_at, response_status_code,"
        " response_raw, response_length, response_created_at)"
        " VALUES (1,'app.test','GET','/a',10,443,?,1,'',0,0,200,?,2,0)",
        (_b64_field(raw), _b64_field("HTTP/1.1 200 OK\r\n\r\nok")),
    )
    con.commit()

    c2s.populate_requests_table(con)

    assert (
        con.execute("SELECT cookies FROM requests").fetchone()[0]
        == "session=abc; theme=dark"
    )


def test_populate_serialises_json_bodies(con):
    # idox parses a JSON body into a dict, which SQLite cannot bind; the import
    # has to re-serialise it or the whole page fails to insert.
    c2s.create_raw_table(con)
    c2s.create_request_table(con)
    json_body = '{"user": "admin"}'
    raw = (
        "POST /a HTTP/1.1\r\n"
        "Host: app.test\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(json_body)}\r\n\r\n{json_body}"
    )
    con.execute(
        "INSERT INTO raw_requests (caido_request_id, host, method, path, length,"
        " port, raw, is_tls, query, edited, created_at, response_status_code,"
        " response_raw, response_length, response_created_at)"
        " VALUES (1,'app.test','POST','/a',10,443,?,1,'',0,0,404,?,2,0)",
        (
            _b64_field(raw),
            # A multi-word reason phrase must parse too.
            _b64_field(
                "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\n"
                '\r\n{"error": "nope"}'
            ),
        ),
    )
    con.commit()

    c2s.populate_requests_table(con)

    body, response_body = con.execute(
        "SELECT body, response_body FROM requests"
    ).fetchone()
    assert isinstance(body, str) and "admin" in body
    assert isinstance(response_body, str) and "nope" in response_body


# The bugs this guards against all came from fixtures being tidier than a real
# export: a JSON body (idox hands back a dict, which SQLite cannot bind), a
# multi-word reason phrase, and a Cookie header. It is also the only test that
# drives the real entry point, CSV parsing included.
def _write_csv(tmp_path, rows):
    """Write (request, response, status) triples out as a Caido-shaped export."""
    csv_file = tmp_path / "export.csv"
    with open(csv_file, "w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(c2s.RAW_COLUMNS)
        for i, (request, response, status) in enumerate(rows):
            writer.writerow(
                (i, "app.test", "GET", "/a", 10, 443, _b64_field(request), 1, "")
                + (
                    "",
                    "",
                    "",
                    0,
                    "",
                    0,
                    i,
                    status,
                    _b64_field(response),
                    2,
                    "",
                    0,
                    "",
                    0,
                )
            )
    return csv_file


def test_create_and_populate_from_a_realistic_csv(tmp_path, con):
    rows = [
        (
            (
                "GET /a HTTP/1.1\r\nHost: app.test\r\n"
                "Cookie: session=abc; theme=dark\r\n\r\n"
            ),
            (
                "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\n"
                '\r\n{"error": "nope"}'
            ),
            404,
        ),
        (
            (
                "POST /b HTTP/1.1\r\nHost: app.test\r\n"
                'Content-Type: application/json\r\n\r\n{"user": "admin"}'
            ),
            "HTTP/1.1 500 Internal Server Error\r\n\r\nboom",
            500,
        ),
    ]
    csv_file = _write_csv(tmp_path, rows)

    c2s.create_and_populate_from_csv(con, csv_file)

    imported = con.execute(
        "SELECT cookies, body, response_status_code, response_body FROM requests"
        " ORDER BY id"
    ).fetchall()
    assert len(imported) == len(rows), "a row failed to import"
    assert imported[0][0] == "session=abc; theme=dark"
    assert imported[0][2] == 404 and "nope" in imported[0][3]
    assert "admin" in imported[1][1], "JSON body did not survive as text"
    assert imported[1][2] == 500


def test_entry_point_imports_a_csv_and_leaves_a_database(tmp_path):
    """`python -m cru export.csv` has to do the import step for you."""
    import cru.__main__ as entry

    csv_file = _write_csv(
        tmp_path,
        [
            (
                "GET /a HTTP/1.1\r\nHost: app.test\r\n\r\n",
                "HTTP/1.1 200 OK\r\n\r\nok",
                200,
            )
        ],
    )

    db = entry.build_db(csv_file, None)

    assert db == csv_file.with_suffix(".db")
    con = sqlite3.connect(db)
    assert con.execute("SELECT COUNT(*) FROM requests").fetchone()[0] == 1
    con.close()


def test_entry_point_passes_an_existing_database_straight_through(tmp_path):
    """A source that is not an export is already a corpus; don't re-import it."""
    import cru.__main__ as entry

    db = tmp_path / "corpus.db"
    db.touch()
    assert entry.build_db(db, None) == db


def test_a_body_with_a_blank_line_in_it_imports(tmp_path, con):
    """A message body can hold a blank line; that is not malformed."""
    body = "para one\r\n\r\npara two"
    csv_file = _write_csv(
        tmp_path,
        [
            (
                (
                    "POST /a HTTP/1.1\r\nHost: app.test\r\n"
                    f"Content-Length: {len(body)}\r\n\r\n{body}"
                ),
                "HTTP/1.1 200 OK\r\n\r\nok",
                200,
            )
        ],
    )

    c2s.create_and_populate_from_csv(con, csv_file)

    stored = con.execute("SELECT body FROM requests").fetchone()[0]
    assert "para two" in stored


def test_a_binary_body_does_not_abort_the_import(tmp_path, con):
    """A corpus carries images and compressed bodies; a strict decode aborts."""
    raw = b"HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n\r\n\x89PNG\xa8\xff\x00"
    csv_file = tmp_path / "bin.csv"
    with open(csv_file, "w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(c2s.RAW_COLUMNS)
        writer.writerow(
            (
                0,
                "app.test",
                "GET",
                "/a",
                10,
                443,
                _b64_field("GET /a HTTP/1.1\r\nHost: app.test\r\n\r\n"),
                1,
                "",
            )
            + (
                "",
                "",
                "",
                0,
                "",
                0,
                0,
                200,
                base64.b64encode(raw).decode().rstrip("="),
                2,
                "",
                0,
                "",
                0,
            )
        )

    c2s.create_and_populate_from_csv(con, csv_file)

    assert con.execute("SELECT COUNT(*) FROM requests").fetchone()[0] == 1


def test_an_unparseable_message_is_skipped_and_counted(tmp_path, con):
    """One bad message must not cost the whole import, or pass unmentioned."""
    csv_file = _write_csv(
        tmp_path,
        [
            ("not an HTTP request at all", "HTTP/1.1 200 OK\r\n\r\nok", 200),
            (
                "GET /a HTTP/1.1\r\nHost: app.test\r\n\r\n",
                "HTTP/1.1 200 OK\r\n\r\nok",
                200,
            ),
        ],
    )
    c2s.create_raw_table(con)
    c2s.create_request_table(con)
    c2s.import_csv(con, csv_file)

    skipped = c2s.populate_requests_table(con)

    assert skipped == 1
    assert con.execute("SELECT COUNT(*) FROM requests").fetchone()[0] == 1
