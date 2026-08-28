"""The `requests` table: one definition, shared by every import path.

Both importers — the Caido CSV path (`csv_to_sql`) and the Burp XML path
(`burp_to_sql`) — write the same table, so the column list, the create
statement and the decoded-column derivation live here rather than in each of
them. `passive_scan` and `report_html` then read one known shape whatever
produced it.
"""

import sqlite3

from pypika import Column, Query, Table

import cru.field_decode
import cru.sql_util

REQUESTS_TABLE = Table("requests")

# Columns every importer supplies, in the order rows are built and inserted.
BASE_COLUMNS = (
    "host",
    "method",
    "path",
    "length",
    "port",
    "cookies",
    "headers",
    "body",
    "is_tls",
    "query",
    "created_at",
    "response_status_code",
    "response_headers",
    "response_body",
    "response_length",
    "response_created_at",
)

# Which base column gets a decoded companion, and the companion's name. The
# companions hold base64/hex plaintext recovered from the field at import time,
# so the checks see wrapped payloads without decoding per row.
DECODE_MAP = (
    ("query", "query_decoded"),
    ("body", "body_decoded"),
    ("cookies", "cookies_decoded"),
    ("headers", "headers_decoded"),
    ("response_body", "response_body_decoded"),
)

INSERT_COLUMNS = BASE_COLUMNS + tuple(dec for _src, dec in DECODE_MAP)

_BASE_INDEX = {name: i for i, name in enumerate(BASE_COLUMNS)}

# index name -> column it covers
_INDEXES = {
    "request_created_at": "created_at",
    "response_created_at": "response_created_at",
    "request_host": "host",
    "request_method": "method",
    "response_status_code": "response_status_code",
}


def with_decoded(base_row) -> tuple:
    """Append the decoded companion values to a BASE_COLUMNS row tuple."""
    base_row = tuple(base_row)
    return base_row + tuple(
        cru.field_decode.decoded_view(base_row[_BASE_INDEX[src]])
        for src, _dec in DECODE_MAP
    )


def drop_requests_table(con: sqlite3.Connection) -> None:
    """Drops the requests table"""
    cru.sql_util.execute(con, query=Query.drop_table(REQUESTS_TABLE).if_exists())


def create_requests_table(con: sqlite3.Connection) -> None:
    """Creates the requests table and its indexes"""
    requests_table = (
        Query.create_table(REQUESTS_TABLE)
        .if_not_exists()
        .columns(
            Column("id", "INTEGER", nullable=False),
            Column("host", "TEXT", nullable=False),
            Column("method", "TEXT", nullable=False),
            Column("path", "TEXT", nullable=False),
            Column("length", "INTEGER", nullable=False),
            Column("port", "INTEGER", nullable=False),
            Column("cookies", "TEXT", nullable=False),
            Column("headers", "TEXT", nullable=False),
            Column("body", "TEXT", nullable=False),
            Column("is_tls", "BOOLEAN", nullable=False),
            Column("query", "TEXT", nullable=True, default=None),
            Column("created_at", "INTEGER", nullable=False),
            # Requests can not have responses...
            Column("response_status_code", "INTEGER", nullable=True, default=None),
            Column("response_headers", "TEXT", nullable=True, default=None),
            Column("response_body", "TEXT", nullable=True, default=None),
            Column("response_length", "INTEGER", nullable=True, default=None),
            Column("response_created_at", "INTEGER", nullable=True, default=None),
            *(
                Column(dec, "TEXT", nullable=True, default=None)
                for _src, dec in DECODE_MAP
            ),
        )
        .primary_key("id")
    )
    cru.sql_util.execute(con, query=requests_table)
    for name, column in _INDEXES.items():
        cru.sql_util.execute(
            con,
            Query.create_index(name).on(REQUESTS_TABLE).columns(column).if_not_exists(),
        )
