import sqlite3
from typing import Any, Protocol, overload


class GetSQL(Protocol):
    def get_sql(self) -> str: ...


QueryT = str | GetSQL


@overload
def execute(
    con: sqlite3.Connection, query: QueryT, *, single_result: bool = True
) -> tuple[Any, ...]: ...


@overload
def execute(
    con: sqlite3.Connection, query: QueryT, *, single_result: bool = False
) -> list[tuple[Any, ...]]: ...


@overload
def execute(
    con: sqlite3.Connection, query: QueryT, *, single_result: None = None
) -> None: ...


def execute(
    con: sqlite3.Connection, query: QueryT, *, single_result: bool | None = None
) -> tuple[Any, ...] | list[tuple[Any, ...]] | None:
    if not isinstance(query, str):
        query = query.get_sql()

    cur = con.cursor()
    res = cur.execute(query)
    if single_result is None:
        data = None
    elif single_result:
        data = res.fetchone()
    else:
        data = res.fetchall()
    con.commit()
    return data
