"""
passive_scan.py — passive vulnerability scanners over a Caido Request Utility DB.

PASSIVE ONLY. Reads the `requests` table CRU builds and inspects the request and
response fields you already captured. It sends no traffic. Findings are leads to
verify against systems you're authorised to test.

This module is the runner and CLI. The 24 checks live one per module in
`cru/checks/`, registered in `cru.checks.CHECKS`; the `Finding` shim and the
field-access helpers they build on are in `cru.checks.base`.

Usage:
    python -m cru.passive_scan test.db                 # run all checks
    python -m cru.passive_scan test.db --check secrets
    python -m cru.passive_scan test.db --json > findings.json
    python -m cru.passive_scan test.db --show-secrets   # unredact matches (careful)

Handoff to real TruffleHog (its full, *verified* detector set) if you want it:
    python -m cru.passive_scan test.db --dump-fields ./corpus_fields
    trufflehog filesystem ./corpus_fields --results=verified,unknown

Stdlib only.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
from dataclasses import asdict

from cru.checks import CHECKS
from cru.checks.base import iter_fields
from cru.checks.secrets import SecretScanner

# --------------------------------------------------------------------------- #
# Formatting helpers
# --------------------------------------------------------------------------- #


def _snippet(s: str, n: int = 60) -> str:
    s = s.replace("\n", "\\n")
    return s if len(s) <= n else s[:n] + "…"


def redact(secret: str, show=False) -> str:
    if show:
        return secret
    s = secret.strip()
    if len(s) <= 8:
        return s[0] + "…" if s else ""
    return f"{s[:4]}…{s[-2:]} ({len(s)} chars)"


def _present(findings, show_secrets=False):
    """Redact secret-check evidence for display unless show_secrets is set."""
    for f in findings:
        if f.check == "secrets" and not show_secrets:
            f.evidence = redact(f.evidence)
    return findings


def render_text(findings):
    if not findings:
        return "No findings."
    findings = sorted(findings, key=lambda f: (f.check, f.host, f.path))
    by_check = {}
    for f in findings:
        by_check.setdefault(f.check, []).append(f)

    lines = []
    for check, items in by_check.items():
        lines.append(f"== {check} : {len(items)} finding(s) ==")
        lines.append("")
        for f in items:
            lines += [
                f"  {f.signature}",
                f"    {f.method} {f.host}{f.path}",
                f"    in    : {f.location}",
                f"    match : {f.evidence}",
                f"    note  : {f.detail}",
                "",
            ]
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Runner / CLI
# --------------------------------------------------------------------------- #


def load_rows(db_path, table="requests"):
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    base = (
        "host, method, path, query, cookies, headers, body, is_tls, "
        "response_status_code, response_headers, response_body"
    )
    decoded = (
        "query_decoded, body_decoded, cookies_decoded, "
        "headers_decoded, response_body_decoded"
    )
    try:
        # Prefer the decoded columns; fall back for DBs imported before they
        # existed (e.g. an older CRU/Caido database).
        try:
            return con.execute(f"SELECT {base}, {decoded} FROM {table}").fetchall()
        except sqlite3.OperationalError:
            return con.execute(f"SELECT {base} FROM {table}").fetchall()
    finally:
        con.close()


def build_checks(selected):
    """Instantiate the registered checks: all of them, or the one named."""
    if selected == "all":
        return [cls() for cls in CHECKS.values()]
    return [CHECKS[selected]()]


def dump_fields(rows, out_dir):
    import os

    os.makedirs(out_dir, exist_ok=True)
    for i, r in enumerate(rows):
        for label, text in iter_fields(r):
            with open(
                os.path.join(out_dir, f"{i:06d}_{label}.txt"), "w", errors="replace"
            ) as fh:
                fh.write(text)


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Passive scanners over a CRU requests DB (no traffic sent)."
    )
    ap.add_argument("db")
    ap.add_argument("--table", default="requests")
    ap.add_argument(
        "--check",
        choices=("all", *CHECKS),
        default="all",
    )
    ap.add_argument("--json", action="store_true")
    ap.add_argument(
        "--show-secrets",
        action="store_true",
        help="do not redact secret matches (handle with care)",
    )
    ap.add_argument(
        "--no-entropy",
        action="store_true",
        help="disable entropy scanning (detectors only)",
    )
    ap.add_argument(
        "--dump-fields",
        metavar="DIR",
        help="write each scannable field to a file for real trufflehog",
    )
    args = ap.parse_args(argv)

    rows = load_rows(args.db, args.table)

    if args.dump_fields:
        dump_fields(rows, args.dump_fields)
        print(
            f"Wrote fields to {args.dump_fields}/ — "
            f"run: trufflehog filesystem {args.dump_fields}"
        )
        return

    checks = build_checks(args.check)
    if args.no_entropy:
        for c in checks:
            if isinstance(c, SecretScanner):
                c.entropy = False

    findings = []
    for c in checks:
        findings.extend(c.run(rows))

    findings = _present(findings, show_secrets=args.show_secrets)

    if args.json:
        print(json.dumps([asdict(f) for f in findings], indent=2))
    else:
        print(render_text(findings))


if __name__ == "__main__":
    main()
