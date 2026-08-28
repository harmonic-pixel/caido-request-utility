# CLAUDE.md

Orientation for Claude Code working on this project. Read this first.

## What this is

A **passive web-security scanner** for captured HTTP traffic. It reads a corpus
of request/response pairs stored in SQLite (the schema `caido-request-utility`
produces) and runs pattern checks over it to surface likely vulnerabilities. It
**never sends traffic** — every finding is a lead to confirm against a system the
user is authorised to test. Inputs come from Caido (via CRU) or Burp (via the
importer here).

Pipeline:

```
Caido export ──(CRU)──┐
                      ├─► SQLite `requests` table ─► passive_scan.py ─► findings ─► report_html.py ─► report.json + report.html
Burp XML export ─(burp_to_sql.py)─┘
```

## Files that matter (deliverables)

| File | Role |
|------|------|
| `cru/passive_scan.py` | The scanner: 24 checks + the runner/CLI. The core. |
| `cru/field_decode.py` | Shared base64/hex decoder. Importers call it at load time. |
| `cru/burp_to_sql.py` | Import a Burp "Save items" XML export into the schema. |
| `cru/schema.py` | The `requests` table definition, shared by both importers. |
| `cru/report_html.py` | Build the verbose JSON report + a self-contained HTML view from it. |
| `cru/idor_finder.py` | Standalone IDOR-candidate finder (separate tool, own aggregation). |
| `tests/test_passive_scan.py` | pytest suite: positive+negative per check, encoding, importer, report. |
| `tests/conftest.py` | Shared fixtures: `make_db` (in-memory corpus) and `run_check`. |
| `CHECKS.md` | Per-check reference: what each catches, patterns, limits. Keep in sync. |

Everything named `make_*.py` is **throwaway scaffolding** used to
build synthetic test DBs during development — not part of the product. Prefer
adding cases to `test_passive_scan.py` over creating new `make_*` scripts.

## Setup & commands

```bash
uv sync                                  # pytest, defusedxml, black, ruff, ty

pytest -q                                # run the whole suite
pytest -q -k xss                         # one check
black . && ruff check . && ty check      # formatting, lint, types

python -m cru.passive_scan corpus.db --check all          # scan
python -m cru.passive_scan corpus.db --check sqli --json   # one check, JSON out
python -m cru.burp_to_sql history.xml -o corpus.db         # import Burp export
python -m cru.report_html corpus.db -o report.html         # JSON + HTML report
```

`stdlib only` for the scanner; `defusedxml` and `brotli` are optional in the
importer (safe fallbacks exist for both).

## Architecture & conventions

### The check interface
Every check is a class with a `name` attribute and a `run(rows) -> list[Finding]`
method. `rows` are `sqlite3.Row` objects from `load_rows`. Checks are registered
in `build_checks()` (a dict) and exposed via the `--check` CLI choices — **update
both** when adding a check. There are currently **24**:

```
deser secrets sqli ssti code srcleak xss xxe ssrf redirect traversal crlf
nosqli upload headers cors cookies jwt infoleak fingerprint methods
mixedcontent cleartext csrf
```

### Finding
`Finding(check, severity, signature, host, method, path, location, evidence, detail)`
is a constructor shim. **Severity is intentionally accepted but discarded** —
this tool does not rank by severity (the user removed it deliberately; do not
re-add it). The stored dataclass `_Finding` has fields:
`check, signature, host, method, path, location, evidence, detail`. Downstream
(dedup, text/JSON output, HTML report) must not depend on severity.

Checks still pass a severity string to `Finding(...)` for readability; that's
fine — it's dropped. Don't add severity filtering, `--min-severity`, or
severity sorting.

### Field access helpers (the seam checks build on)
- `request_inputs(row)` → `(label, text)` for request-side fields (URL-decoded).
- `iter_fields(row)` → `(label, text)` for all fields incl. responses.
- `request_param_values(row)` → `(label, value)` per individual param.
- `response_text(row)` → concatenated response headers+body.
- `_status(row)` → int status or None.

### Encoding coverage (decode once, at import)
Base64/hex-wrapped payloads are decoded **at import time** by `field_decode.
decoded_view()` and stored in dedicated columns: `query_decoded`, `body_decoded`,
`cookies_decoded`, `headers_decoded`, `response_body_decoded`. The field helpers
surface these as extra `#decoded` views (e.g. `request-body#decoded`), so checks
get encoding coverage for free — **checks must not decode inline**. `load_rows`
selects the decoded columns and falls back gracefully for older DBs without them.

> Open work item the user raised: make `field_decode.decoded_view` **recursive**
> (base64-of-hex-of-payload) with guardrails — depth cap (~3–4), progress +
> printability gate, a visited-set and total-work cap, and base64/hex branch
> dedup (the alphabets overlap, so recursion can branch). It currently unwraps
> one layer. Add tests alongside.

### Correlation
Some checks raise confidence by correlating request and response in the same row
(e.g. `sqli` escalates a payload when the response also carries a DB error or a
5xx; `xss` only treats reflection as exploitable when `<`/`>` come back
unencoded; `redirect` confirms via a reflected `Location`). Preserve this when
editing.

### Security of the tooling itself
- The scanner reads attacker-controlled data; the HTML report renders findings
  via `textContent`/DOM building and escapes the embedded JSON — **never** inject
  finding values into HTML as markup.
- `burp_to_sql.py` parses XML safely (defusedxml or a hardened stdlib fallback
  that rejects DTDs/entities) — don't loosen this; it's the XXE surface the
  `xxe` check exists to catch.
- Secret findings are redacted by default (`_present`); `--show-secrets` reveals.

## Schema (the `requests` table)

Base columns: `host, method, path, length, port, cookies, headers, body, is_tls,
query, created_at, response_status_code, response_headers, response_body,
response_length, response_created_at`. `cookies` = the request Cookie header;
`headers` = newline-joined `Name: value`; `query` = query string.
Plus decoded columns: `query_decoded, body_decoded, cookies_decoded,
headers_decoded, response_body_decoded`.

Known corpus limits (documented in CHECKS.md, keep true): duplicate headers
collapse (so `crlf`/duplicate-`Set-Cookie` can't be *confirmed* from responses —
request-side probe only); everything is passive.

## Working agreements

- **Run `pytest -q` before and after changes.** Keep it green. Every check needs
  a positive and a negative case in `test_passive_scan.py`; add both when adding
  a check.
- **Keep `CHECKS.md` accurate.** If you change what a check catches or its
  patterns, update its entry. (The suite guards that the *test matrix* covers
  every registered check via `test_every_check_has_cases`; `CHECKS.md` coverage
  is a convention, not yet enforced — consider adding a test if you touch it.)
- When adding a check: implement the class, register in `build_checks()`, add to
  the `--check` choices, add positive+negative test cases, and a `CHECKS.md`
  entry.
- Don't reintroduce severity. Don't add carve/binary `.burp` parsing (the user
  chose the XML export path; see the "Importing from Burp" section of
  README.md).
- Prefer editing over new scaffolding scripts; the `make_*`/`add_*` files are not
  product.
