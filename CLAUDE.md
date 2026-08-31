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
| `cru/report_html.py` | Build the verbose JSON report + a self-contained HTML view from it, including the reconstructed request/response each finding is highlighted in, and a link from each rule to the check's source (`REPO_URL`, `--repo-url`). |
| `cru/idor_finder.py` | Standalone IDOR-candidate finder (separate tool, own aggregation). `passive_scan.idor_findings` folds its candidates in as `check="idor"` on a full run, for the terminal scan and the report alike. Its precision comes from what it refuses — see its module docstring before loosening any of it. |
| `cru/__main__.py` | `python -m cru <source>` — import, scan and report in one command. Thin: it calls the others. |
| `cru/sql_util.py` | The DB seam: `execute` and `execute_many`. Override to target another DB. |
| `cru/progress.py` | One-line progress for the slow phases. Stderr, and only when a terminal is attached. |
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
uv sync                                                     # pytest, defusedxml, black, ruff, ty

uv run pytest -q                                            # run the whole suite
uv run pytest -q -k xss                                     # one check
uv run black . && uv run ruff check . && uv run ty check    # format, lint, types — all must pass

uv run python -m cru export.csv -o report.html              # import + scan + report
uv run python -m cru.passive_scan corpus.db --check all     # scan
uv run python -m cru.passive_scan corpus.db --check sqli --json  # one check, JSON out
uv run python -m cru.passive_scan corpus.db --skip secrets   # all but the named checks
uv run python -m cru.burp_to_sql history.xml -o corpus.db   # import Burp export
uv run python -m cru.report_html corpus.db -o report.html   # JSON + HTML report
uv run python -m cru.idor_finder corpus.db                  # IDOR candidates
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
`--check` and `--skip` CLI choices are all derived from it, so there is nothing
else to keep in sync. There are currently **23**:

```
deserialization secrets sqli ssti code srcleak xss xxe ssrf redirect
traversal crlf nosqli upload security-headers cors cookies jwt infoleak
fingerprint mixedcontent cleartext csrf
```

### Finding
`Finding(check, severity, signature, host, method, path, location, evidence, detail, group, ids, rules)`
is a constructor shim. **Severity is intentionally accepted but discarded** —
this tool does not rank by severity (the user removed it deliberately; do not
re-add it). The stored dataclass `_Finding` has fields:
`check, signature, host, method, path, location, evidence, detail, paths, group,
ids, rules`. `ids` and `rules` are listings the report renders as dropdowns: the
values an IDOR candidate was seen with, and every place a `code` rule matched.
`paths` is every request the finding stood for, as `METHOD /path`, and `group` is an optional dedup
identity: pass one to `Finding`/`_emit` and `_dedupe` merges occurrences that
share it into a single finding carrying all their paths, instead of keying on
`path` as usual. `jwt_identity()` in `cru/checks/base.py` builds one from a
token's header and its non-volatile claims — that is how the `jwt` check and
the `jwt` detector in `secrets` collapse a re-issued session token. Anything
rendering findings should show `paths` when it holds more than one. Downstream
(dedup, text/JSON output, HTML report) must not depend on severity — `report_html`
was purged of it, including its filter UI, so don't reintroduce it there either.

Checks still pass a severity string to `Finding(...)` for readability; that's
fine — it's dropped. Don't add severity filtering, `--min-severity`, or
severity sorting.

### Field access helpers (the seam checks build on)
- `request_inputs(row)` → `(label, text)` for request-side fields (URL-decoded).
- `iter_fields(row)` → `(label, text)` for all fields incl. responses.
- Both also emit a `#json` view (e.g. `request-body#json`) holding the string
  leaves of a JSON field, unescaped. A JSON string escapes its newlines, so a
  value's lines run together (`...Operation\ndef operation(`) and no
  `\b`-anchored pattern can fire on it — the view is what lets **every** check
  see code, in any language, carried in a JSON body. It is emitted only when
  the document escapes whitespace, and `_Finding.key()` strips `#json` so a hit
  visible in both views is one finding reported against the field.
- `request_param_values(row)` → `(label, value)` per individual param, incl.
  nested JSON leaves. Use this when the parameter *name* matters.
- `response_text(row)` → concatenated response headers+body.
- `response_body(row)` → the response body, or `""` when its `Content-Type` says
  binary (`image/*` bar SVG, `video/*`, `audio/*`, `font/*`). The corpus stores
  a lossy text decode of those bytes, so scanning them buys noise at the price of
  the corpus's images and fonts. `iter_fields`/`response_text` skip them too.
- `_status(row)` → int status or None.

### Pattern gating (what keeps a scan affordable)
A scan costs **patterns × bytes**: one compiled pattern over a 15MB corpus is
~0.2s whether it matches or not, and there are over a hundred of them across the
checks. Searching that same corpus for a literal costs 0.01s. So a pattern table
declares its patterns with `gate(pattern, *literals, flags=0)` from
`cru.checks.base` instead of `re.compile`, naming the lowercase literals a match
cannot happen without — **one per top-level alternative**, or the gate will hide
real findings. `gate` returns a `search`/`finditer` drop-in, so call sites don't
change. A pattern with nothing selective to name keeps `re.compile`; a weak
literal (`use`, `return`) is honest, it just doesn't buy much.

A leading `(?i)` is honoured, and if the pattern body is all lowercase the flag
is dropped and matching moves to the folded text the gate already built — ~10x
quicker — with the match read back out of the original so evidence keeps its
case. That is why the SQL-error and PHP-error patterns are written in lowercase:
under `(?i)` the source casing was decorative, and lowercase makes them fold.
Write new case-insensitive patterns lowercase for the same reason.

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

JWTs get one extra pass (`field_decode._jwt_views`). A token is base64 all the
way down but reads as one opaque blob, and one wrapped inside another base64
field survives the single decode layer intact — so the pass runs over the field
*and* over what it just decoded, appending each token rewritten as
`{header}.{claims}.{signature}` with the two dictionaries as JSON.

**A DB imported before a `field_decode` change keeps the old decoded columns** —
the decoding happened at import. Re-import to pick a change up.

**A candidate is judged on what it decodes to, not on how long it is**
(`field_decode._decoded_text`). A wrapped payload is as short as the value
someone wrapped, so base64 tokens are taken from 8 characters up, and from 6
when the padding says base64 (`YWRtaW4=` is "admin"). Below 12 decoded bytes,
printability is not enough to judge — any six-letter word is valid base64, and
"answer" decodes to `j{0z` — so a short decode has to read as a value: printable
ASCII throughout, only the characters a value is written with, and one mark of
text (a three-letter run, a bare number, a `key=`, a path, a tag, the opening of
a JSON document or a URL). Measured on a 565-request corpus, that let 46k more
candidates in and one junk decode out the other side. **Hex keeps the
16-character floor**: eight hex digits is four bytes, too few to judge, and a
minified bundle is full of them.

**Unwrapping repeats.** `_iter_decoded` scans what each token decoded to, breadth
first, so base64-of-hex-of-payload comes out as plaintext. It is bounded by
`_MAX_DEPTH` layers, by `_MAX_NESTED_DECODES` attempts per field *below the
first layer* — the first is the scan that always happened, and capping it would
lose coverage that predates the unwrapping — and by the set of plaintexts
already seen — the alphabets overlap (a hex run is valid base64
too), so both branches can reach the same bytes. No cycle is possible: every
layer is smaller than the token it came out of.

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
- `_present` only redacts the `secrets` check, so `report_html.build_messages`
  masks known secrets everywhere else they surface: the message panes, any
  finding's `evidence`, and the `ids` list. An "identifier" is sometimes a
  credential — `idor_finder` treats a bearer token in a hinted body parameter
  as one — and nothing should be a way round the masking.
- **The masking takes its own detector pass over the text it is about to
  show** — `report_html._pane_secrets` runs `secrets.secret_literals` on each
  pane, and each finding's `evidence`/`detail`/`ids` are read the same way.
  Never the run's findings: with `--skip secrets` there were none to read and a
  report embedding whole bodies masked nothing at all, and even a full run
  knows only one occurrence per group, so a re-issued token stayed readable
  beside the sibling that got masked. Reading the pane is also the only
  complete answer — a URL-encoded token reads differently there than in the
  decoded field the checks scan. Keep it per pane: masking every corpus secret
  in every pane is quadratic (3.5M replacements on a 565-row corpus, 15s of a
  25s report) and grows with the corpus.
- **A `secrets` detector's match is what gets hidden** — in the finding and in
  the report's message pane. Match the credential, not its label: too wide and
  the pane loses the context that makes it readable, too narrow and the secret
  itself survives masking. Use a capture group when the pattern needs a prefix
  to anchor on (`basic-auth-header`), and match the whole block when the marker
  is not the secret (`private-key-block`).

## Schema (the `requests` table)

Defined once in `cru/schema.py`. Base columns: `host, method, path, length, port,
cookies, headers, body, is_tls, query, created_at, response_status_code,
response_headers, response_body, response_length, response_created_at`.
`cookies` = the request Cookie header; `headers` = newline-joined `Name: value`;
`query` = query string. Plus decoded columns: `query_decoded, body_decoded,
cookies_decoded, headers_decoded, response_body_decoded`. Indexed on
`created_at`, `response_created_at`, `host`, `method`, `response_status_code`.

`csv_to_sql` also builds `raw_requests`, a verbatim copy of the Caido export, and
derives `requests` from it in pages of `PAGE_SIZE`. Raw messages are decoded
lossily (a corpus carries images and compressed bodies), JSON bodies of any
shape are re-serialised for binding, and a message idox will not parse is
skipped and counted rather than aborting the import — `populate_requests_table`
returns the count and `create_and_populate_from_csv` prints it.

Known corpus limits (documented in CHECKS.md, keep true): duplicate headers
collapse (so `crlf`/duplicate-`Set-Cookie` can't be *confirmed* from responses —
request-side probe only); fields truncate at 400,000 bytes; evidence truncates at
60 chars; findings dedupe, so a count is not a request count; everything is
passive.

## Working agreements

- **Run `uv run pytest -q` before and after changes**, and `uv run black . &&
  uv run ruff check . && uv run ty check`. All four must be green. Every check needs a positive and a negative
  case; add both when adding a check.
- **A test that cannot fail is worse than none.** Before keeping a new one,
  break the code it covers and watch it go red — a loop over an empty list, an
  assertion compared against the constant the code reads, or evidence that was
  never located all pass forever. Assert the bound as a literal (`<= 81`), not
  as `_ID_DISPLAY + 1`, and count what you checked when a loop can be empty.
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
