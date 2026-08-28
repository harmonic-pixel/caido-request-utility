# EXPORTING.md

How to produce the Burp Suite XML export that `cru/burp_to_sql.py` imports.

The importer reads a Burp **"Save items"** XML file — `<item>` elements
carrying the raw request and response bytes — and writes the same SQLite
`requests` schema that caido-request-utility produces, so `cru/passive_scan.py` and
`cru/report_html.py` run unchanged on Burp data.

## From a live Burp session

1. Go to **Proxy → HTTP history**, or **Target → Site map** if you want a
   crawled tree rather than what actually passed through the proxy.
2. Filter first. Set your target scope and apply "Show only in-scope items", or
   filter by host — the export is a straight dump of what you select, and
   trimming here is much easier than trimming later.
3. Select the items you want. `Ctrl-A` in the list selects all of them.
   **"Save items" acts on the current selection**, so selecting nothing exports
   nothing.
4. Right-click the selection → **Save items**. Choose a filename ending in
   `.xml`.
5. Leave the base64-encoding option enabled (Burp's default). Raw request and
   response bytes survive base64 intact; without it, binary bodies and odd
   encodings can be mangled in the XML.

## From a saved `.burp` project file

Open the project in Burp first (**File → Open project**), then follow the steps
above. There is no way around this: the binary `.burp` project format is not
parsed by this tool and will not be — the XML export is the supported path.

## What the importer uses

Per `<item>`:

| Element | Use |
|---------|-----|
| `<request>` | **Required.** Items without it are skipped and counted. |
| `<response>` | Status, headers, body. Absent is fine — the row is imported request-only. |
| `<host>` | Preferred over the request's `Host:` header. |
| `<port>` | Falls back to 443/80 based on `<protocol>`. |
| `<protocol>` | `https` here (or port 443) sets `is_tls`. |
| `<status>` | Fallback when the raw response has no parsable status line. |
| `<responselength>` | Fallback when the raw response is absent. |

`<request>` and `<response>` are read as base64 when the element carries
`base64="true"`, and as literal text otherwise — both forms work.

## Import and scan

```bash
python -m cru.burp_to_sql history.xml -o burp.db      # import
python -m cru.burp_to_sql history.xml -o burp.db --replace   # drop existing table first

python -m cru.passive_scan burp.db --check all        # scan
python -m cru.report_html burp.db -o report.html      # JSON + HTML report
```

The importer streams `<item>` elements rather than loading the whole tree, so
large exports do not need to fit in memory. It prints how many requests were
imported, how many items were skipped for having no request data, and which XML
backend was used.

## Notes

- **`pip install defusedxml`** before importing an export you did not produce
  yourself. With it, entity expansion, billion-laughs and external-entity
  attacks are handled properly. Without it the stdlib fallback rejects any
  `<!DOCTYPE>` or `<!ENTITY>` outright — safe, but an export that legitimately
  contains a DTD will fail to parse rather than being trusted.
- **`pip install brotli`** if the target serves `Content-Encoding: br`. Without
  it those response bodies stay compressed in the database and no check can read
  them. gzip and deflate are handled by the standard library, no install needed.
- **Timestamps are not in the export.** `created_at` and `response_created_at`
  are written as `0`. Anything ordering by time will see one flat bucket.
- **Headers are stored newline-joined** as `Name: value` lines; `cookies` holds
  the request `Cookie` header; `query` holds the query string. Duplicate headers
  collapse — see the corpus-wide limits in `CHECKS.md`.
- **The `*_decoded` columns are filled at import time**, so a Burp-imported
  database has base64/hex payload coverage from the start. Nothing extra to run.
