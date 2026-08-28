"""
add_decoded_columns.py — backfill base64/hex decoded columns on an existing DB.

The Burp importer (burp_to_sql.py) writes the `*_decoded` columns at import time.
The CSV import path (csv_to_sql.py) writes them too, so a database built by a
current CRU already has them. This is for one built by an older version, or by
another tool: run it once to add and populate the columns in place, and
passive_scan.py gains encoding coverage without a re-import.

    python -m cru.add_decoded_columns your.db
"""

from __future__ import annotations

import argparse
import sqlite3

from cru import field_decode

# (source column, decoded companion column)
_DECODE_MAP = (
    ("query", "query_decoded"),
    ("body", "body_decoded"),
    ("cookies", "cookies_decoded"),
    ("headers", "headers_decoded"),
    ("response_body", "response_body_decoded"),
)


def migrate(db_path, table="requests"):
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    existing = {r[1] for r in con.execute(f"PRAGMA table_info({table})")}
    if "id" not in existing:
        con.close()
        raise SystemExit(f"{table} has no `id` column — cannot migrate safely")

    added = []
    for src, dec in _DECODE_MAP:
        if src not in existing:
            continue  # source column absent (unusual schema) — skip its decode
        if dec not in existing:
            con.execute(f"ALTER TABLE {table} ADD COLUMN {dec} TEXT")
            added.append(dec)

    # Backfill any decoded column that is still NULL.
    srcs = [src for src, _ in _DECODE_MAP if src in existing]
    updated = 0
    for row in con.execute(f"SELECT id, {', '.join(srcs)} FROM {table}").fetchall():
        sets, params = [], []
        for src, dec in _DECODE_MAP:
            if src not in existing:
                continue
            sets.append(f"{dec} = ?")
            params.append(field_decode.decoded_view(row[src]))
        params.append(row["id"])
        con.execute(f"UPDATE {table} SET {', '.join(sets)} WHERE id = ?", params)
        updated += 1
    con.commit()
    con.close()
    return added, updated


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Add and backfill base64/hex decoded columns on an existing "
        "CRU/Caido requests DB."
    )
    ap.add_argument("db")
    ap.add_argument("--table", default="requests")
    args = ap.parse_args(argv)
    added, updated = migrate(args.db, args.table)
    note = f"added {added}" if added else "columns already present"
    print(f"Migrated {args.db}: {note}; backfilled {updated} rows")


if __name__ == "__main__":
    main()
