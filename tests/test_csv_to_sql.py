"""The CRU import path must produce the same shape passive_scan expects.

Covers the two halves of that contract: the requests table carries the
*_decoded companion columns, and populating it actually fills them, so a
base64-wrapped payload is scannable without a separate migration.
"""

import base64
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
