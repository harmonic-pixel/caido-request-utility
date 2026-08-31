"""
__main__.py — the whole pipeline behind one command.

`python -m cru <source>` takes a Caido CSV export, a Burp XML export or an
existing CRU database, and runs everything that follows from it: import, scan,
and — with `-o` — the HTML report. The individual commands still work on their
own; this only saves wiring them together by hand.

    python -m cru export.csv                        # import, then print findings
    python -m cru export.csv -o report.html         # ... and write the report
    python -m cru corpus.db -o report.html          # already imported, just report
    python -m cru history.xml --db burp.db          # Burp export instead

The source is recognised by extension: `.csv` is a Caido export, `.xml` a Burp
one, and anything else is taken to be a database that is already built.

The report folds in `idor_finder`'s candidates; the printed findings do not, so
run `python -m cru.idor_finder <db>` for those on the terminal.
"""

from __future__ import annotations

import argparse
import sqlite3
from pathlib import Path

import cru.burp_to_sql
import cru.csv_to_sql
from cru import passive_scan, report_html
from cru.checks import CHECKS


def build_db(source: Path, db: Path | None) -> Path:
    """Import `source` into a database and return its path.

    A source that is neither a CSV nor an XML export is assumed to be a database
    already, and is used as it is.
    """
    suffix = source.suffix.lower()
    if suffix not in (".csv", ".xml"):
        return source

    db = db or source.with_suffix(".db")
    if suffix == ".csv":
        con = sqlite3.connect(db)
        try:
            cru.csv_to_sql.create_and_populate_from_csv(con, source)
        finally:
            con.close()
    else:
        cru.burp_to_sql.import_burp(str(source), str(db), replace=True)
    return db


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="cru",
        description="Import a traffic export, scan it, and report on it.",
    )
    ap.add_argument(
        "source", type=Path, help="Caido CSV export, Burp XML export, or a CRU database"
    )
    ap.add_argument(
        "--db",
        type=Path,
        help="where to write the imported database (default: alongside the source)",
    )
    ap.add_argument(
        "-o",
        "--out",
        help="write an HTML report here; without it the findings are printed",
    )
    ap.add_argument(
        "--json", default=None, help="JSON report path (default: alongside the HTML)"
    )
    ap.add_argument("--table", default="requests")
    ap.add_argument("--check", choices=("all", *CHECKS), default="all")
    ap.add_argument(
        "--show-secrets",
        action="store_true",
        help="do not redact secret matches (handle with care)",
    )
    args = ap.parse_args(argv)

    if not args.source.exists():
        ap.error(f"{args.source} does not exist")

    db = build_db(args.source, args.db)
    if db != args.source:
        print(f"Imported {args.source} -> {db}")

    shared = ["--table", args.table, "--check", args.check]
    if args.show_secrets:
        shared.append("--show-secrets")

    if args.out:
        extra = ["--json", args.json] if args.json else []
        report_html.main([str(db), "-o", args.out, *shared, *extra])
    else:
        passive_scan.main([str(db), *shared])


if __name__ == "__main__":
    main()
