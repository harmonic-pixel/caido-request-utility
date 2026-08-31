"""
passive_scan.py — passive vulnerability scanners over a Caido Request Utility DB.

PASSIVE ONLY. Reads the `requests` table CRU builds and inspects the request and
response fields you already captured. It sends no traffic. Findings are leads to
verify against systems you're authorised to test.

This module is the runner and CLI. The 23 checks live one per module in
`cru/checks/`, registered in `cru.checks.CHECKS`; the `Finding` shim and the
field-access helpers they build on are in `cru.checks.base`. A full run also
carries `idor_finder`'s candidates under the check name `idor` — it aggregates
its own way rather than registering as a check, but leaving it out meant the
scan and the report answered differently about one corpus.

Usage:
    python -m cru.passive_scan test.db                 # every check, plus idor
    python -m cru.passive_scan test.db --check secrets
    python -m cru.passive_scan test.db --check idor    # only the IDOR pass
    python -m cru.passive_scan test.db --skip idor     # everything but it
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

from cru import idor_finder as idor
from cru import progress
from cru.checks import CHECKS
from cru.checks.base import Finding, iter_fields
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
            ]
            # A merged finding stands for every path it was seen on; listing
            # them is the difference between one lead and one lead per request.
            if len(f.paths) > 1:
                lines.append(f"    paths : {len(f.paths)}")
                lines += [f"      {p}" for p in f.paths]
            if len(f.rules) > 1:
                lines.append(f"    rules : {len(f.rules)}")
                lines += [f"      {rule}" for rule in f.rules]
            lines.append("")
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


def idor_findings(db, table):
    """IDOR candidates as findings, so they filter and read like everything else.

    `idor_finder` aggregates its own way and needs `response_length`, which the
    scanner's loader does not select — hence its own read of the table. The
    evidence is one observed ID rather than the whole sample, so the report can
    point at it in the request; the rest are listed in the dropdown.
    """
    try:
        rows = idor.load_rows(db, table)
    except sqlite3.OperationalError:
        # A database built before `response_length` existed: the scan findings
        # are still worth a report, so skip the IDOR pass rather than fail.
        return []
    out = []
    for c in idor.analyse(rows):
        label = idor.TYPE_LABEL.get(c.id_type, c.id_type)
        if c.confidence != "primary":
            label += " (low confidence)"
        auth = "no"
        if c.auth_observed:
            auth = "mixed" if c.unauth_observed else "yes"
        out.append(
            Finding(
                "idor",
                "review",
                label,
                c.host,
                c.method,
                c.endpoint,
                c.location,
                c.sample_ids[0] if c.sample_ids else "",
                f"{c.note} — {c.distinct_ids} distinct; "
                f"responses {c.statuses or '—'}; auth: {auth}; "
                f"requests: {c.request_count}",
                ids=c.sample_ids,
            )
        )
    return out


def build_checks(selected, skip=()):
    """Instantiate the registered checks: all of them, or the one named.

    `skip` drops checks by name — `--check all --skip secrets` is a full run
    without the noisiest one, which is a different thing from picking one check.
    """
    names = list(CHECKS) if selected == "all" else [selected]
    # `idor` is selectable but is not a registered check — it is a separate
    # aggregation the runner adds afterwards, so it never names a class here.
    return [CHECKS[n]() for n in names if n in CHECKS and n not in skip]


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
        choices=("all", *CHECKS, "idor"),
        default="all",
    )
    ap.add_argument(
        "--skip",
        nargs="+",
        metavar="CHECK",
        choices=(*CHECKS, "idor"),
        default=[],
        help="checks to leave out, e.g. --skip secrets idor",
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
        "--no-progress",
        action="store_true",
        help="do not draw the progress bar",
    )
    ap.add_argument(
        "--dump-fields",
        metavar="DIR",
        help="write each scannable field to a file for real trufflehog",
    )
    args = ap.parse_args(argv)
    if args.no_progress:
        progress.disable()

    rows = load_rows(args.db, args.table)

    if args.dump_fields:
        dump_fields(rows, args.dump_fields)
        print(
            f"Wrote fields to {args.dump_fields}/ — "
            f"run: trufflehog filesystem {args.dump_fields}"
        )
        return

    checks = build_checks(args.check, skip=args.skip)
    if args.no_entropy:
        for c in checks:
            if isinstance(c, SecretScanner):
                c.entropy = False

    findings = []
    run_idor = args.check in ("all", "idor") and "idor" not in args.skip
    steps = len(checks) + (1 if run_idor else 0)
    for i, c in enumerate(checks, 1):
        progress.track(i - 1, steps, f"scanning ({c.name})")
        findings.extend(c.run(rows))
    # IDOR is a separate tool with its own aggregation rather than a registered
    # check, but leaving it out of the scan meant the terminal and the report
    # answered differently about the same corpus.
    if run_idor:
        progress.track(len(checks), steps, "scanning (idor)")
        findings.extend(idor_findings(args.db, args.table))
    progress.clear()

    findings = _present(findings, show_secrets=args.show_secrets)

    if args.json:
        print(json.dumps([asdict(f) for f in findings], indent=2))
    else:
        print(render_text(findings))


if __name__ == "__main__":
    main()
