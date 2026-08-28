import csv
import sqlite3
from base64 import b64decode
from copy import deepcopy
from itertools import batched
from pathlib import Path
from typing import Any

from idox import Idox, Request, Response
from pypika import Column, Query, Table

import cru.field_decode
import cru.sql_util

RAW_REQUESTS_TABLE = Table("raw_requests")
REQUESTS_TABLE = Table("requests")


def drop_raw_table(con: sqlite3.Connection) -> None:
    """Drops the raw requests table"""
    cru.sql_util.execute(con, query=Query.drop_table(RAW_REQUESTS_TABLE).if_exists())


def create_raw_table(con: sqlite3.Connection) -> None:
    """Creates a table to store the raw exported data"""
    raw_requests_table = (
        Query.create_table(RAW_REQUESTS_TABLE)
        .if_not_exists()
        .columns(
            Column("id", "INTEGER", nullable=False),
            Column("caido_request_id", "INTEGER", nullable=False),
            Column("host", "TEXT", nullable=False),
            Column("method", "TEXT", nullable=False),
            Column("path", "TEXT", nullable=False),
            Column("length", "INTEGER", nullable=False),
            Column("port", "INTEGER", nullable=False),
            Column("raw", "BLOB", nullable=False),
            Column("is_tls", "BOOLEAN", nullable=False),
            Column("query", "TEXT", nullable=True, default=None),
            Column("file_extension", "TEXT", nullable=True, default=None),
            Column("caido_source", "TEXT", nullable=True, default=None),
            Column("alteration", "TEXT", nullable=True, default=None),
            Column("edited", "BOOLEAN", nullable=False),
            Column("parent_id", "TEXT", nullable=True, default=None),
            Column("created_at", "INTEGER", nullable=False),
            # Requests can not have responses..
            Column("caido_response_id", "INTEGER", nullable=True, default=None),
            Column("response_status_code", "INTEGER", nullable=True, default=None),
            Column("response_raw", "BLOB", nullable=True, default=None),
            Column("response_length", "INTEGER", nullable=True, default=None),
            Column("response_alteration", "TEXT", nullable=True, default=None),
            Column("response_edited", "BOOLEAN", nullable=True, default=None),
            Column("response_parent_id", "TEXT", nullable=True, default=None),
            Column("response_created_at", "INTEGER", nullable=True, default=None),
        )
        .primary_key("id")
    )
    cru.sql_util.execute(con, query=raw_requests_table)


def import_csv(con: sqlite3.Connection, csv_file: Path) -> None:
    """Given an export, import it"""
    csv.field_size_limit(10000000)
    with open(csv_file, "r", newline="") as f:
        reader = csv.reader(f)
        next(reader)
        for rows in batched(reader, n=1000):
            query = Query.into(RAW_REQUESTS_TABLE).columns(
                "caido_request_id",
                "host",
                "method",
                "path",
                "length",
                "port",
                "raw",
                "is_tls",
                "query",
                "file_extension",
                "caido_source",
                "alteration",
                "edited",
                "parent_id",
                "created_at",
                "caido_response_id",
                "response_status_code",
                "response_raw",
                "response_length",
                "response_alteration",
                "response_edited",
                "response_parent_id",
                "response_created_at",
            )
            for row in rows:
                query = query.insert(*row)

            cru.sql_util.execute(con, query)


def drop_request_table(con: sqlite3.Connection) -> None:
    """Drops the requests table"""
    cru.sql_util.execute(con, query=Query.drop_table(REQUESTS_TABLE).if_exists())


def create_request_table(con: sqlite3.Connection) -> None:
    """Creates a pretty requests table with nicer data"""
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
            # base64/hex plaintext recovered from each field at populate time,
            # so passive_scan sees wrapped payloads without decoding per row.
            Column("query_decoded", "TEXT", nullable=True, default=None),
            Column("body_decoded", "TEXT", nullable=True, default=None),
            Column("cookies_decoded", "TEXT", nullable=True, default=None),
            Column("headers_decoded", "TEXT", nullable=True, default=None),
            Column("response_body_decoded", "TEXT", nullable=True, default=None),
        )
        .primary_key("id")
    )
    cru.sql_util.execute(con, query=requests_table)
    index_one = (
        Query.create_index("request_created_at")
        .on(REQUESTS_TABLE)
        .columns("created_at")
        .if_not_exists()
    )
    index_two = (
        Query.create_index("response_created_at")
        .on(REQUESTS_TABLE)
        .columns("response_created_at")
        .if_not_exists()
    )
    index_three = (
        Query.create_index("request_host")
        .on(REQUESTS_TABLE)
        .columns("host")
        .if_not_exists()
    )
    index_four = (
        Query.create_index("request_method")
        .on(REQUESTS_TABLE)
        .columns("method")
        .if_not_exists()
    )
    index_five = (
        Query.create_index("response_status_code")
        .on(REQUESTS_TABLE)
        .columns("response_status_code")
        .if_not_exists()
    )
    cru.sql_util.execute(con, index_one)
    cru.sql_util.execute(con, index_two)
    cru.sql_util.execute(con, index_three)
    cru.sql_util.execute(con, index_four)
    cru.sql_util.execute(con, index_five)


def populate_requests_table(con: sqlite3.Connection) -> None:
    """Populates the requests table"""
    base_query = (
        Query.from_(RAW_REQUESTS_TABLE)
        .select(
            "host",
            "method",
            "path",
            "length",
            "port",
            "raw",
            "is_tls",
            "query",
            "created_at",
            "response_status_code",
            "response_raw",
            "response_length",
            "response_created_at",
        )
        .orderby("id")
        .limit(100)
    )
    has_next = True
    current_offset = 0
    while has_next:
        query = deepcopy(base_query).offset(current_offset)
        requests: list[tuple[Any, ...]] = cru.sql_util.execute(
            con, query=query, single_result=False
        )  # ty:ignore[invalid-assignment]
        has_next = requests and len(requests) == 100
        if has_next:
            current_offset += 100

        insert_query = Query.into(REQUESTS_TABLE).columns(
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
            "query_decoded",
            "body_decoded",
            "cookies_decoded",
            "headers_decoded",
            "response_body_decoded",
        )
        for row in requests:
            request_model: Request = Idox.split_request(
                b64decode(f"{row[5]}==").decode()
            )
            response_model: Response = Idox.split_response(
                b64decode(f"{row[10]}==").decode()
            )
            cookies = "; ,".join(f"{i[0]}={i[1]}" for i in request_model.cookies)
            headers = "\n".join(f"{k}: {v}" for k, v in request_model.headers.items())
            response_headers = "\n".join(
                f"{k}: {v}" for k, v in response_model.headers.items()
            )
            decoded = cru.field_decode.decoded_view
            insert_query = insert_query.insert(
                row[0],  # host
                row[1],  # method
                row[2],  # path
                row[3],  # length
                row[4],  # port
                cookies,
                headers,
                request_model.body,
                row[6],  # is_tls
                row[7],  # query
                row[8],  # created_at
                row[9],  # status code
                response_headers,
                response_model.body,
                row[11],  # response length
                row[12],  # response created at
                decoded(row[7]),  # query_decoded
                decoded(request_model.body),  # body_decoded
                decoded(cookies),  # cookies_decoded
                decoded(headers),  # headers_decoded
                decoded(response_model.body),  # response_body_decoded
            )

        cru.sql_util.execute(con, query=insert_query)


def create_and_populate_from_csv(con: sqlite3.Connection, csv_file: Path) -> None:
    """Fully creates and populates all tables."""
    drop_raw_table(con)
    create_raw_table(con)
    import_csv(con, csv_file)
    drop_request_table(con)
    create_request_table(con)
    populate_requests_table(con)
