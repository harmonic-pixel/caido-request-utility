# CLAUDE.md

Orientation for Claude Code working on this project. Read this first.

## What this is

Two things in one package. **CRU** turns a Caido (or Burp) export into a SQLite
`requests` table for tooling to work on. On top of that sits a **passive
web-security scanner**: it reads that corpus and runs pattern checks over it to
surface likely vulnerabilities. It **never sends traffic** — every finding is a
lead to confirm against a system the user is authorised to test.

Pipeline:

```
Caido CSV export ──(cru.csv_to_sql)──┐
                                     ├─► SQLite `requests` table ─► cru.passive_scan ─► findings ─► cru.report_html ─► report.json + report.html
Burp XML export ──(cru.burp_to_sql)──┘
```

## Files that matter

| File | Role |
|------|------|
| `cru/checks/` | The scanner's core: one module per check, plus `base.py` and the `CHECKS` registry in `__init__.py`. |
| `cru/passive_scan.py` | The scan runner and CLI. Loads rows, runs the registered checks, renders text/JSON. |
| `cru/schema.py` | The `requests` table: columns, create/drop, bulk insert. One definition, shared. |
| `cru/csv_to_sql.py` | Import a Caido CSV export: `raw_requests` then `requests`. |
| `cru/burp_to_sql.py` | Import a Burp "Save items" XML export into the same schema. |
| `cru/field_decode.py` | Shared base64/hex decoder. The importers call it at load time. |
| `cru/report_html.py` | Build the verbose JSON report + a self-contained HTML view from it, including the reconstructed request/response each finding is highlighted in. |
| `cru/idor_finder.py` | Standalone IDOR-candidate finder (separate tool, own aggregation). |
| `cru/sql_util.py` | The DB seam: `execute` and `execute_many`. Override to target another DB. |
| `tests/conftest.py` | Shared fixtures: `make_db` (in-memory corpus) and `run_check`. |
| `tests/test_passive_scan.py` | Positive+negative per check, encoding, importer, report. |
| `tests/test_csv_to_sql.py` | Schema shape, decoded columns, and paging boundaries. |
| `CHECKS.md` | Per-check reference: what each catches, patterns, limits. Keep in sync. |
| `README.md` | User-facing: scanner overview, check table, Burp export procedure, roadmap. |

Anything named `make_*.py` is **throwaway scaffolding** for building synthetic
test DBs during development — not product. Prefer adding cases to the test suite
over creating new scripts.

## Setup & commands

```bash
uv sync                                  # pytest, defusedxml, black, ruff, ty

pytest -q                                # run the whole suite
pytest -q -k xss                         # one check
black . && ruff check . && ty check      # formatting, lint, types — all must pass

python -m cru.passive_scan corpus.db --check all           # scan
python -m cru.passive_scan corpus.db --check sqli --json   # one check, JSON out
python -m cru.burp_to_sql history.xml -o corpus.db         # import Burp export
python -m cru.report_html corpus.db -o report.html         # JSON + HTML report
python -m cru.idor_finder corpus.db                        # IDOR candidates
```

`passive_scan`, `report_html`, `field_decode` and `idor_finder` are **stdlib
only**. The import path pulls in `pypika` and `idox`; `defusedxml` and `brotli`
are optional in the Burp importer (safe fallbacks exist for both).

## Architecture & conventions

### The check interface
Every check is a class with a `name` attribute and a `run(rows) -> list[Finding]`
method. `rows` are `sqlite3.Row` objects from `load_rows`. Each check lives in
its own module under `cru/checks/`, holding the class and the pattern tables only
it uses; shared primitives are in `cru/checks/base.py`. Registration is one entry
in the `CHECKS` dict in `cru/checks/__init__.py` — `build_checks()` and the
`--check` CLI choices are both derived from it, so there is nothing else to keep
in sync. There are currently **24**:

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
(dedup, text/JSON output, HTML report) must not depend on severity — `report_html`
was purged of it, including its filter UI, so don't reintroduce it there either.

Checks still pass a severity string to `Finding(...)` for readability; that's
fine — it's dropped. Don't add severity filtering, `--min-severity`, or
severity sorting.

### Field access helpers (the seam checks build on)
- `request_inputs(row)` → `(label, text)` for request-side fields (URL-decoded).
- `iter_fields(row)` → `(label, text)` for all fields incl. responses.
- `request_param_values(row)` → `(label, value)` per individual param, incl.
  nested JSON leaves. Use this when the parameter *name* matters.
- `response_text(row)` → concatenated response headers+body.
- `_status(row)` → int status or None.

### One schema, one insert path
`cru/schema.py` owns the `requests` table — `BASE_COLUMNS`, `DECODE_MAP`,
`INSERT_COLUMNS`, `create_requests_table`, `drop_requests_table`,
`with_decoded`, `insert_rows`. **Both importers go through it**; neither may
spell the columns out again or hand-roll an INSERT. That is what keeps a
Caido-imported and a Burp-imported database identical in shape and indexes.

Writes go through `cru.sql_util`: `execute` for one statement, `execute_many`
for a parameterised bulk insert. Values stay **bound**, never rendered into SQL
text — building a giant statement per batch is what this replaced. `execute_many`
takes an iterable, so importers can stream generators rather than materialise
batches. Placeholders are qmark (`?`), set once in `schema.INSERT_QUERY`.

### Encoding coverage (decode once, at import)
Base64/hex-wrapped payloads are decoded **at import time** by
`field_decode.decoded_view()` — via `schema.with_decoded()`, so both importers
get it — and stored in dedicated columns: `query_decoded`, `body_decoded`,
`cookies_decoded`, `headers_decoded`, `response_body_decoded`. The field helpers
surface these as extra `#decoded` views (e.g. `request-body#decoded`), so checks
get encoding coverage for free — **checks must not decode inline**. `load_rows`
selects the decoded columns and falls back gracefully for a DB built without them.

> Two open work items on `field_decode`, best done together — both are about
> deciding "is this really encoded?" from the decoded bytes rather than from the
> token's shape, and both need the same guardrails to stay cheap:
>
> 1. **Drop the length floor.** Candidate tokens must currently be 16+ characters,
>    so short wrapped payloads are never decoded and no check ever sees them (a
>    5000-row benchmark corpus lost 1000 payloads to the floor alone). Judge a
>    candidate on the entropy and printability of what it decodes to instead.
> 2. **Make `decoded_view` recursive** (base64-of-hex-of-payload) with a depth cap
>    (~3–4), a progress + printability gate, a visited-set and total-work cap, and
>    base64/hex branch dedup (the alphabets overlap, so recursion can branch). It
>    currently unwraps one layer.
>
> Add tests alongside. Both are on the README roadmap.

### Correlation
Some checks raise confidence by correlating request and response in the same row.
`sqli` escalates both a payload and a query-composition parameter when the
response also carries a DB error or a 5xx; `xss` only treats reflection as
exploitable when `<`/`>` come back unencoded; `redirect` confirms via a reflected
`Location`; `traversal` escalates when file contents come back. Preserve this
when editing.

Several checks are tiered rather than binary — `code` splits `exec`/`syntax`,
`sqli` splits `sink`/`clause` on parameter names, `ssti` escalates on dangerous
tokens inside the template syntax. Follow that shape for a new signal instead of
adding an all-or-nothing pattern.

### Security of the tooling itself
- The scanner reads attacker-controlled data; the HTML report renders findings
  *and the message panes* via `textContent`/DOM building and escapes the embedded
  JSON — the highlight is a `<mark>` element built by the DOM. **Never** inject a
  finding value or message text into HTML as markup.
- The report embeds whole request/response bodies, so secrets are masked inside
  the message text as well as in the finding. The mask is **length-preserving**
  (`report_html._mask`) because every match offset is computed against the
  unmasked pane — shortening it would slide every later highlight off its text.
  Offsets are UTF-16 units, which is what JS string slicing counts.
- `burp_to_sql.py` parses XML safely (defusedxml or a hardened stdlib fallback
  that rejects DTDs/entities) — don't loosen this; it's the XXE surface the
  `xxe` check exists to catch.
- Secret findings are redacted by default (`_present`); `--show-secrets` reveals.

## Schema (the `requests` table)

Defined once in `cru/schema.py`. Base columns: `host, method, path, length, port,
cookies, headers, body, is_tls, query, created_at, response_status_code,
response_headers, response_body, response_length, response_created_at`.
`cookies` = the request Cookie header; `headers` = newline-joined `Name: value`;
`query` = query string. Plus decoded columns: `query_decoded, body_decoded,
cookies_decoded, headers_decoded, response_body_decoded`. Indexed on
`created_at`, `response_created_at`, `host`, `method`, `response_status_code`.

`csv_to_sql` also builds `raw_requests`, a verbatim copy of the Caido export, and
derives `requests` from it in pages of `PAGE_SIZE`.

Known corpus limits (documented in CHECKS.md, keep true): duplicate headers
collapse (so `crlf`/duplicate-`Set-Cookie` can't be *confirmed* from responses —
request-side probe only); fields truncate at 400,000 bytes; evidence truncates at
60 chars; findings dedupe, so a count is not a request count; everything is
passive.

## Working agreements

- **Run `pytest -q` before and after changes**, and `black . && ruff check . &&
  ty check`. All four must be green. Every check needs a positive and a negative
  case; add both when adding a check.
- **Keep `CHECKS.md` accurate**, and the check table in `README.md` with it. If
  you change what a check catches or its patterns, update both. (The suite guards
  that the *test matrix* covers every registered check via
  `test_every_check_has_cases`; doc coverage is a convention, not yet enforced —
  consider adding a test if you touch it.)
- When adding a check: add `cru/checks/<name>.py` with the class, register it in
  the `CHECKS` dict in `cru/checks/__init__.py`, add positive+negative test cases,
  a `CHECKS.md` entry, and a row in the README table. The CLI picks it up from the
  registry on its own.
- Tests live in `tests/`. Shared fixtures go in `conftest.py`, not in the test
  module. Row dicts are built with `dict(...)` kwargs on purpose — ruff's C408 is
  disabled for `tests/*.py` for exactly that reason.
- Don't reintroduce severity. Don't add carve/binary `.burp` parsing (the user
  chose the XML export path; see the "Importing from Burp" section of README.md).
- Prefer editing over new scaffolding scripts; the `make_*` files are not product.
