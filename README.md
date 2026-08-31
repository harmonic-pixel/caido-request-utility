Caido Request Utility (CRU)
---

This tool lets you take a Caido export and turn it into a SQL database for ease of tooling interactions.

## Usage

This is a basic script to import and load data to SQLite
```python
import sqlite3
from pathlib import Path

import cru.csv_to_sql


def main():
    con: sqlite3.Connection = sqlite3.connect("test.db")
    cru.csv_to_sql.create_and_populate_from_csv(con, Path("test.csv"))


if __name__ == "__main__":
    main()
```

Technically this is SQL agnostic, just override `cru.sql_util.execute` to use your DB specific execution logic.

## Passive scanning

Once traffic is in the `requests` table, `cru.passive_scan` runs 24 pattern
checks over it and reports what looks worth a closer look. It is **passive**: it
reads the corpus and sends no traffic of its own, so every finding is a lead to
confirm by hand against a system you are authorised to test.

```
Caido export ──(csv_to_sql)──┐
                             ├─► requests table ─► passive_scan ─► findings ─► report_html
Burp XML export ─(burp_to_sql)─┘
```

One command does the lot — import, scan, report:

```bash
uv run python -m cru export.csv -o report.html  # CSV in, findings and a report out
uv run python -m cru export.csv                 # import and print the findings
uv run python -m cru corpus.db -o report.html   # already imported, just report
uv run python -m cru history.xml --db burp.db   # a Burp export instead
```

The source is recognised by extension: `.csv` is a Caido export, `.xml` a Burp
one, anything else is taken to be a database that is already built. The steps
still stand on their own:

```bash
uv run python -m cru.passive_scan corpus.db --check all          # every check
uv run python -m cru.passive_scan corpus.db --check sqli --json  # one check, JSON out
uv run python -m cru.passive_scan corpus.db --show-secrets       # unredact secret matches
uv run python -m cru.report_html corpus.db -o report.html        # JSON + self-contained HTML
uv run python -m cru.idor_finder corpus.db                       # IDOR candidates (separate tool)
```

A full report (`--check all`) also carries `idor_finder`'s candidates under the
check name `idor`, so they filter, search and show their request like any other
finding. The terminal scan does not — run `idor_finder` for those.

`idor_finder` is deliberate about what it will *not* call an object
reference: a JWT under any parameter name (a signed, expiring credential is not
enumerable — that is the `jwt` check's business), a bare integer on a parameter
named for a quantity or a position (`offset`, `per_page`, `x`, `_key`), and any
candidate seen with a single distinct ID — with nothing to enumerate and nothing
to compare, that is not a lead (`--min-distinct 1` puts them back). A short list you can act on
beats a long one you have to sift.

Findings are grouped by host. A corpus with one host opens expanded; with
several, the groups start closed — and narrowing to a single host, by filter or
by search, expands it again.

In the report, an IDOR candidate lists every ID it was observed with in its own
dropdown, the way a deduplicated finding lists its paths. A finding's rule name
links to the source of the check that raised it, so "why did this fire?" is one
click. The links point at this repo on
`main`; `--repo-url` aims them at a fork or a tag instead.

A finding offers the decoded view of the field it came from, so a token in a
cookie is one tab away from its claims. The decoded view spells JWTs out rather
than leaving them as opaque tokens:
each one appears as `{"alg": "HS256", ...}.{"sub": "42", ...}.<signature>`, so
the claims are readable in the report's `#decoded` tab and scannable by every
check. Tokens wrapped inside another base64 field are expanded too.

Findings are grouped by check and are not ranked by severity. Expanding one
shows the request it came out of — reconstructed from the stored fields, with
the matched string highlighted — and tabs for the response and for any decoded
view the evidence actually surfaced in. Secrets stay masked there too, so the
message cannot leak what the finding hides; `--show-secrets` reveals both. The
HTML report is a single self-contained file that builds every finding value and
every byte of a message through `textContent`, so it cannot be XSS'd by the
payloads it displays.

### The checks

| Check | Catches |
|-------|---------|
| `deserialization` | Serialized objects and gadget markers — PHP, Java, .NET, Ruby, pickle, YAML tags |
| `secrets` | Vendor API keys and tokens, private keys, plus a high-entropy sweep |
| `sqli` | DBMS errors in responses, SQLi-shaped payloads, and parameter names like `sqlQuery` or `orderBy` that compose the query |
| `ssti` | Template-expression syntax in request inputs, tagged by templating style |
| `code` | Fields carrying source or shell commands in 7 languages, JNDI/Log4Shell lookups |
| `srcleak` | Server-side source, `.env`/`web.config` credentials, `.git` metadata in responses |
| `xss` | XSS payload vectors, and parameter values reflected back unencoded |
| `xxe` | External and parameter entities, stream wrappers, and file-read tells |
| `ssrf` | Cloud metadata endpoints and internal hosts in server-fetch parameters |
| `redirect` | Offsite URLs in redirect params, confirmed against a 3xx `Location` |
| `traversal` | `../` sequences and absolute-path markers, escalated when a file comes back |
| `crlf` | CR/LF and overlong-UTF8 sequences in request inputs (request-side probe only) |
| `nosqli` | MongoDB operators as JSON keys or bracketed parameters |
| `upload` | Executable, double, and markup extensions in multipart filenames |
| `security-headers` | Missing or weak CSP, HSTS, frame protection, nosniff, referrer/permissions policy |
| `cors` | Wildcard with credentials, `null` origin, credentialed origin reflection |
| `cookies` | `Set-Cookie` missing HttpOnly, Secure, or SameSite |
| `jwt` | `alg=none`, empty signatures, tokens with no expiry |
| `infoleak` | Stack traces, debug pages, directory listings, GraphQL introspection |
| `fingerprint` | Version banners and framework session-cookie names |
| `methods` | `PUT`, `DELETE`, `TRACE`, `CONNECT`, `PATCH`, `TRACK` observed in traffic |
| `mixedcontent` | `http://` sub-resources referenced from an HTTPS page |
| `cleartext` | Credentials, cookies, or `Authorization` sent over plain HTTP |
| `csrf` | State-changing cookie-authenticated requests with no visible CSRF token |

[**CHECKS.md**](CHECKS.md) has the full reference: what each check reads, its
signatures, and where it stops — plus the corpus-wide limits that apply to all
of them (duplicate headers collapse, fields and evidence truncate, and findings
dedupe, so a finding count is not a request count).

### Encoding coverage

Payloads are often wrapped in base64 or hex to slip past a naive scan, so the
importers decode each field once at load time into `query_decoded`,
`body_decoded`, `cookies_decoded`, `headers_decoded` and
`response_body_decoded`. Every check sees those as extra `#decoded` views, which
is why a finding's location may read `request-body#decoded`.

Both import paths write these columns — they share one table definition in
`cru/schema.py` — so any database CRU builds has the coverage already.

## Importing from Burp

`cru.burp_to_sql` reads a Burp Suite **"Save items"** XML export into the same
`requests` schema, so everything above works on Burp data too.

### Producing the export

1. Go to **Proxy → HTTP history**, or **Target → Site map** for a crawled tree.
2. Filter first — set your scope and apply "Show only in-scope items", or filter
   by host. The export is a straight dump of what you select.
3. Select the items you want; `Ctrl-A` selects all of them. **"Save items" acts
   on the current selection**, so selecting nothing exports nothing.
4. Right-click the selection → **Save items**, and save as `.xml`.
5. Leave base64 encoding enabled (Burp's default). Raw request and response
   bytes survive base64 intact; without it, binary bodies can be mangled.

From a saved `.burp` project file, open the project in Burp first
(**File → Open project**) and follow the same steps — the binary project format
is not parsed.

### Importing

```bash
uv run python -m cru.burp_to_sql history.xml -o burp.db            # import
uv run python -m cru.burp_to_sql history.xml -o burp.db --replace  # drop existing table first
```

Items are streamed rather than loaded as one tree, so large exports do not need
to fit in memory. Per `<item>`, `<request>` is required (items without one are
skipped and counted); `<response>`, `<host>`, `<port>`, `<protocol>`,
`<status>` and `<responselength>` are used when present.

### Notes

- **`uv add defusedxml`** before importing an export you did not produce
  yourself. Without it the stdlib fallback rejects any `<!DOCTYPE>` or
  `<!ENTITY>` outright — safe, but an export that legitimately contains a DTD
  will fail to parse rather than being trusted.
- **`uv add brotli`** if the target serves `Content-Encoding: br`, or those
  response bodies stay compressed and unreadable to the checks. gzip and deflate
  need nothing extra.
- The export carries no timestamps, so `created_at` and `response_created_at`
  are written as `0`.
- A message that will not parse is skipped, counted and reported rather than
  failing the import; real traffic always has a few.
- The `*_decoded` columns are filled at import time, so a Burp-imported database
  has encoding coverage from the start. That also means a database imported
  before a decoding change keeps the old columns — re-import to pick one up.

## Idea Roadmap

- Support for providing a scope for narrowing data aggregation
- Broader test coverage
- Tests against large sample data, on the order of 10k requests, to catch
  paging and memory behaviour the small fixtures cannot
- Better base64/hex decoding: the current 16-character floor on candidate
  tokens silently misses short wrapped payloads, so judge a candidate on the
  entropy and printability of what it decodes to rather than on its length
- Make the HTML report hold up on a large corpus — 100k requests, and the
  findings that come with them. The report is a single self-contained file
  that embeds the whole document as JSON, parses it on load and renders every
  visible finding as DOM: at that size the page gets big to download, slow to
  open, and slow again on each filter or search, since `render()` rebuilds the
  list from scratch. Worth doing: virtualise the list so only the rows on
  screen exist, debounce the search, keep the message panes out of the initial
  payload (fetch or lazily expand them), and put a ceiling on how much of a
  body is embedded at all. The measurement comes first — build a corpus at
  that scale and find out which of those actually hurts

*P.s. You should contribute ideas! If you have an idea of what to do with raw request data, open an issue.*

## Reference

Table: `raw_requests`

Description: Raw data that matches the Caido export.

Definition:
```sql
 CREATE TABLE IF NOT EXISTS "raw_requests"
  (
     "id"                   INTEGER NOT NULL,
     "caido_request_id"     INTEGER NOT NULL,
     "host"                 TEXT NOT NULL,
     "method"               TEXT NOT NULL,
     "path"                 TEXT NOT NULL,
     "length"               INTEGER NOT NULL,
     "port"                 INTEGER NOT NULL,
     "raw"                  BLOB NOT NULL,
     "is_tls"               BOOLEAN NOT NULL,
     "query"                TEXT NULL,
     "file_extension"       TEXT NULL,
     "caido_source"         TEXT NULL,
     "alteration"           TEXT NULL,
     "edited"               BOOLEAN NOT NULL,
     "parent_id"            TEXT NULL,
     "created_at"           INTEGER NOT NULL,
     "caido_response_id"    INTEGER NULL,
     "response_status_code" INTEGER NULL,
     "response_raw"         BLOB NULL,
     "response_length"      INTEGER NULL,
     "response_alteration"  TEXT NULL,
     "response_edited"      BOOLEAN NULL,
     "response_parent_id"   TEXT NULL,
     "response_created_at"  INTEGER NULL,
     PRIMARY KEY ("id")
  )  
```

Table: `requests`

Description: Beautified data ready for use in tooling.

Definition:
```sql
 CREATE TABLE IF NOT EXISTS "requests"
  (
     "id"                   INTEGER NOT NULL,
     "host"                 TEXT NOT NULL,
     "method"               TEXT NOT NULL,
     "path"                 TEXT NOT NULL,
     "length"               INTEGER NOT NULL,
     "port"                 INTEGER NOT NULL,
     "cookies"              TEXT NOT NULL,
     "headers"              TEXT NOT NULL,
     "body"                 TEXT NOT NULL,
     "is_tls"               BOOLEAN NOT NULL,
     "query"                TEXT NULL,
     "created_at"           INTEGER NOT NULL,
     "response_status_code" INTEGER NULL,
     "response_headers"     TEXT NULL,
     "response_body"        TEXT NULL,
     "response_length"      INTEGER NULL,
     "response_created_at"  INTEGER NULL,
     "query_decoded"         TEXT NULL,
     "body_decoded"          TEXT NULL,
     "cookies_decoded"       TEXT NULL,
     "headers_decoded"       TEXT NULL,
     "response_body_decoded" TEXT NULL,
     PRIMARY KEY ("id")
  )  
```

The `*_decoded` columns hold base64/hex plaintext recovered from the matching
field at import time — see [Encoding coverage](#encoding-coverage).

Indexes:
```sql
CREATE INDEX IF NOT EXISTS request_created_at ON "requests"(created_at);
CREATE INDEX IF NOT EXISTS response_created_at ON "requests"(response_created_at);
CREATE INDEX IF NOT EXISTS request_host ON "requests"(host);
CREATE INDEX IF NOT EXISTS request_method ON "requests"(method);
CREATE INDEX IF NOT EXISTS response_status_code ON "requests"(response_status_code)  
```