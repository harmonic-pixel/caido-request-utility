import csv
import sqlite3
from base64 import b64decode
from copy import deepcopy
from pathlib import Path
from typing import Any

from idox import Idox, Request, Response
from pypika import Column, Parameter, Query, Table

import cru.schema
import cru.sql_util

RAW_REQUESTS_TABLE = Table("raw_requests")

# Rows read from raw_requests per round trip when populating.
PAGE_SIZE = 100

# Columns of raw_requests, in Caido export order — the CSV's own column order.
RAW_COLUMNS = (
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

_RAW_INSERT_QUERY = (
    Query.into(RAW_REQUESTS_TABLE)
    .columns(*RAW_COLUMNS)
    .insert(*[Parameter("?")] * len(RAW_COLUMNS))
)


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
        next(reader)  # header
        # executemany streams the reader, so the file never lands in memory and
        # the values stay bound rather than rendered into one huge statement.
        cru.sql_util.execute_many(con, _RAW_INSERT_QUERY, reader)


def drop_request_table(con: sqlite3.Connection) -> None:
    """Drops the requests table"""
    cru.schema.drop_requests_table(con)


def create_request_table(con: sqlite3.Connection) -> None:
    """Creates a pretty requests table with nicer data"""
    cru.schema.create_requests_table(con)


def _request_row(row: tuple[Any, ...]) -> tuple[Any, ...]:
    """Turn one raw_requests row into a requests row, in BASE_COLUMNS order."""
    request_model: Request = Idox.split_request(b64decode(f"{row[5]}==").decode())
    response_model: Response = Idox.split_response(b64decode(f"{row[10]}==").decode())
    return (
        row[0],  # host
        row[1],  # method
        row[2],  # path
        row[3],  # length
        row[4],  # port
        "; ,".join(f"{i[0]}={i[1]}" for i in request_model.cookies),
        "\n".join(f"{k}: {v}" for k, v in request_model.headers.items()),
        request_model.body,
        row[6],  # is_tls
        row[7],  # query
        row[8],  # created_at
        row[9],  # status code
        "\n".join(f"{k}: {v}" for k, v in response_model.headers.items()),
        response_model.body,
        row[11],  # response length
        row[12],  # response created at
    )


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
        .limit(PAGE_SIZE)
    )
    current_offset = 0
    while True:
        query = deepcopy(base_query).offset(current_offset)
        requests: list[tuple[Any, ...]] = cru.sql_util.execute(
            con, query=query, single_result=False
        )  # ty:ignore[invalid-assignment]
        # A short page is the last one; an empty page means the previous page
        # ended exactly on the boundary. Either way there is nothing after it.
        if not requests:
            break
        current_offset += len(requests)

        cru.schema.insert_rows(con, (_request_row(row) for row in requests))

        if len(requests) < PAGE_SIZE:
            break


def create_and_populate_from_csv(con: sqlite3.Connection, csv_file: Path) -> None:
    """Fully creates and populates all tables."""
    drop_raw_table(con)
    create_raw_table(con)
    import_csv(con, csv_file)
    drop_request_table(con)
    create_request_table(con)
    populate_requests_table(con)
