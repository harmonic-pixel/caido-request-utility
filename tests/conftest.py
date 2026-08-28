"""Shared fixtures for the passive-scan suite.

The checks all take `sqlite3.Row` objects shaped like the CRU/Burp `requests`
table, so every test needs a small corpus built to that schema. `make_db` builds
one in memory from partial row dicts; `run_check` is the common case on top of
it — build a corpus, run one named check over it, hand back the findings.
"""

import sqlite3

import pytest

from cru import field_decode
from cru import passive_scan as ps

# The subset of the requests schema the checks actually read.
_BASE = (
    "host",
    "method",
    "path",
    "query",
    "cookies",
    "headers",
    "body",
    "is_tls",
    "response_status_code",
    "response_headers",
    "response_body",
)

# Which base columns get a decoded companion, and the companion's name.
_DECODE_MAP = (
    ("query", "query_decoded"),
    ("body", "body_decoded"),
    ("cookies", "cookies_decoded"),
    ("headers", "headers_decoded"),
    ("response_body", "response_body_decoded"),
)

_DEFAULTS = dict(
    host="app.test",
    method="GET",
    path="/",
    query="",
    cookies="",
    headers="",
    body="",
    is_tls=1,
    response_status_code=200,
    response_headers="",
    response_body="",
)


@pytest.fixture
def make_db():
    """Build an in-memory requests DB from a list of partial row dicts.

    Pass `decoded=False` to leave the `*_decoded` columns NULL, which is what a
    database imported before those columns existed looks like.
    """
    connections = []

    def _make_db(rows, decoded=True):
        con = sqlite3.connect(":memory:")
        connections.append(con)
        con.row_factory = sqlite3.Row
        cols = list(_BASE) + [d for _s, d in _DECODE_MAP]
        # Match real column affinities: is_tls/status are integers, not TEXT —
        # else a stored "0" would read back truthy and skew is_tls-sensitive
        # checks.
        types = {"is_tls": "INTEGER", "response_status_code": "INTEGER"}
        coldefs = ", ".join(f"{c} {types.get(c, 'TEXT')}" for c in cols)
        con.execute(f"CREATE TABLE requests ({coldefs})")
        for r in rows:
            rec: dict[str, object] = dict(_DEFAULTS)
            rec.update(r)
            for src, dec in _DECODE_MAP:
                rec[dec] = (
                    field_decode.decoded_view(rec.get(src, "")) if decoded else None
                )
            con.execute(
                f"INSERT INTO requests ({','.join(cols)}) "
                f"VALUES ({','.join('?' * len(cols))})",
                [rec[c] for c in cols],
            )
        con.commit()
        return con

    yield _make_db

    for con in connections:
        con.close()


@pytest.fixture
def run_check(make_db):
    """Run a single named check over crafted rows; return list[Finding]."""

    def _run_check(name, rows, **kw):
        con = make_db(rows, **kw)
        data = con.execute("SELECT * FROM requests").fetchall()
        check = ps.build_checks(name)[0]
        return check.run(data)

    return _run_check
