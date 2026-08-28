"""
burp_to_sql.py — build the CRU `requests` table from a Burp Suite export.

Reads a Burp "Save items" XML export — <item> elements carrying base64-encoded
raw request and response bytes — and writes the same SQLite `requests` schema
that caido-request-utility produces, so passive_scan.py and report_html.py run
unchanged on Burp data.

    python -m cru.burp_to_sql history.xml -o burp.db
    python -m cru.passive_scan burp.db --check all
    python -m cru.report_html burp.db -o report.html

See the "Importing from Burp" section of README.md for how to produce the XML
export from Burp (including from a saved .burp project file).

Notes:
- The table definition is shared with the CSV import path; see cru/schema.py.
- Request/response headers are stored as newline-joined "Name: value" lines;
  `cookies` holds the request Cookie header; `query` is the query string.
- gzip/deflate (and brotli if the `brotli` module is installed) response bodies
  are decompressed so the response text is scannable.
- XML is parsed safely: defusedxml is used when installed; otherwise the stdlib
  parser is locked down to reject DTDs and entity declarations, so a malicious
  export cannot trigger XXE/entity-expansion in the importer. `pip install
  defusedxml` for the most robust handling of untrusted exports.

Stdlib only (defusedxml and brotli optional).
"""

from __future__ import annotations

import argparse
import base64
import gzip
import sqlite3
import xml.etree.ElementTree as ET
import zlib

import cru.schema

try:
    import brotli  # ty: ignore[unresolved-import]  # optional, for Content-Encoding: br
except ImportError:
    brotli = None

# Safe XML parsing. Prefer defusedxml (blocks entity expansion, billion-laughs,
# and external-entity/DTD attacks). If it isn't installed, fall back to the
# stdlib parser configured to reject DTDs and entity definitions outright, so a
# malicious export can't trigger XXE in the importer itself.
try:
    from defusedxml.ElementTree import iterparse as _safe_iterparse

    _XML_BACKEND = "defusedxml"
except ImportError:
    _XML_BACKEND = "stdlib-hardened"

    def _safe_iterparse(source, events=("end",)):
        """Parse with expat directly, rejecting any DOCTYPE/DTD.

        Blocking the DOCTYPE declaration outright stops entity definitions,
        external entities, and billion-laughs expansion before they occur. We
        drive expat into a TreeBuilder and yield ('end', element) so callers get
        the same interface as ElementTree.iterparse.
        """
        import xml.parsers.expat as _expat

        def _no_dtd(*_a, **_k):
            raise ValueError(
                "XML DTD/DOCTYPE is not allowed (possible XXE) — "
                "install defusedxml for full untrusted-XML parsing"
            )

        builder = ET.TreeBuilder()
        stack, done = [], []

        p = _expat.ParserCreate()
        p.StartDoctypeDeclHandler = _no_dtd  # <!DOCTYPE ...>
        p.EntityDeclHandler = _no_dtd  # <!ENTITY ...>
        p.ExternalEntityRefHandler = lambda *a: (_ for _ in ()).throw(
            ValueError("external entity reference blocked (possible XXE)")
        )
        p.buffer_text = True

        def start(tag, attrs):
            stack.append(builder.start(tag, attrs))

        def end(tag):
            el = builder.end(tag)
            if stack:
                stack.pop()
            if "end" in events:
                done.append(el)

        p.StartElementHandler = start
        p.EndElementHandler = end
        p.CharacterDataHandler = builder.data

        with open(source, "rb") as fh:
            while True:
                chunk = fh.read(65536)
                if not chunk:
                    p.Parse(b"", True)
                    break
                p.Parse(chunk, False)
                while done:
                    yield ("end", done.pop(0))
        while done:
            yield ("end", done.pop(0))


# --------------------------------------------------------------------------- #
# Raw HTTP parsing
# --------------------------------------------------------------------------- #


def _split_head_body(raw: bytes):
    idx = raw.find(b"\r\n\r\n")
    sep = 4
    if idx < 0:
        idx = raw.find(b"\n\n")
        sep = 2
    if idx < 0:
        return raw, b""
    return raw[:idx], raw[idx + sep :]


def _header_lines(head: bytes):
    text = head.replace(b"\r\n", b"\n").decode("latin-1", "replace")
    lines = text.split("\n")
    return lines[0], lines[1:]


def _parse_headers(lines):
    headers = []
    for ln in lines:
        if not ln.strip() or ":" not in ln:
            continue
        k, v = ln.split(":", 1)
        headers.append((k.strip(), v.strip()))
    return headers


def _get(headers, name):
    name = name.lower()
    for k, v in headers:
        if k.lower() == name:
            return v
    return None


def _decode_text(b: bytes) -> str:
    return b.decode("utf-8", "replace") if b else ""


def parse_request(raw: bytes) -> dict:
    head, body = _split_head_body(raw)
    start, hdr_lines = _header_lines(head)
    parts = start.split(" ")
    method = parts[0] if parts else ""
    target = parts[1] if len(parts) > 1 else ""
    path, _, query = target.partition("?")
    headers = _parse_headers(hdr_lines)
    return {
        "method": method,
        "path": path,
        "query": query,
        "headers": headers,
        "host": _get(headers, "host"),
        "cookie": _get(headers, "cookie"),
        "body": _decode_text(body),
        "length": len(raw),
    }


def _decompress(body: bytes, encoding: str) -> bytes:
    if not body or not encoding:
        return body
    enc = encoding.lower()
    try:
        if "gzip" in enc:
            return gzip.decompress(body)
        if "deflate" in enc:
            try:
                return zlib.decompress(body)
            except zlib.error:
                return zlib.decompress(body, -zlib.MAX_WBITS)
        if "br" in enc and brotli is not None:
            return brotli.decompress(body)
    except Exception:  # noqa: BLE001 - any decoder failure must not abort the import
        return body  # leave as-is if decompression fails
    return body


def parse_response(raw: bytes) -> dict:
    if not raw:
        return {"status": None, "headers": [], "body": "", "length": 0}
    head, body = _split_head_body(raw)
    start, hdr_lines = _header_lines(head)
    status = None
    bits = start.split(" ")
    if len(bits) > 1 and bits[1].isdigit():
        status = int(bits[1])
    headers = _parse_headers(hdr_lines)
    body = _decompress(body, _get(headers, "content-encoding") or "")
    return {
        "status": status,
        "headers": headers,
        "body": _decode_text(body),
        "length": len(raw),
    }


def _join_headers(headers):
    return "\n".join(f"{k}: {v}" for k, v in headers)


# --------------------------------------------------------------------------- #
# Burp XML → rows
# --------------------------------------------------------------------------- #


def _decode_field(el):
    """Return raw bytes for a <request>/<response> element (base64 or literal)."""
    if el is None or el.text is None:
        return b""
    if (el.get("base64") or "").lower() == "true":
        try:
            return base64.b64decode(el.text)
        except Exception:  # noqa: BLE001 - malformed item is skipped, not fatal
            return b""
    return el.text.encode("utf-8", "replace")


def _text(el):
    return el.text if el is not None and el.text is not None else None


def row_from_item(item) -> tuple | None:
    req_raw = _decode_field(item.find("request"))
    if not req_raw:
        return None
    resp_raw = _decode_field(item.find("response"))
    req = parse_request(req_raw)
    resp = parse_response(resp_raw)

    # Prefer Burp's structured fields for host/port/protocol/status where present.
    host = _text(item.find("host")) or req["host"] or ""
    protocol = (_text(item.find("protocol")) or "").lower()
    try:
        port = int(_text(item.find("port")) or 0)
    except (TypeError, ValueError):
        port = 443 if protocol == "https" else 80
    is_tls = 1 if (protocol == "https" or port == 443) else 0

    status = resp["status"]
    if status is None:
        try:
            status = int(_text(item.find("status")))
        except (TypeError, ValueError):
            status = None
    try:
        resp_len = int(_text(item.find("responselength")))
    except (TypeError, ValueError):
        resp_len = resp["length"]

    return (
        host,
        req["method"],
        req["path"],
        req["length"],
        port,
        req["cookie"] or "",
        _join_headers(req["headers"]),
        req["body"],
        is_tls,
        req["query"],
        0,
        status,
        _join_headers(resp["headers"]),
        resp["body"],
        resp_len,
        0,
    )


def iter_items(xml_path):
    """Stream <item> elements so large exports don't load fully into memory."""
    for _event, el in _safe_iterparse(xml_path, events=("end",)):
        if el.tag == "item":
            yield el
            el.clear()


def import_burp(xml_path, db_path, replace=False, batch=1000):
    con = sqlite3.connect(db_path)
    if replace:
        cru.schema.drop_requests_table(con)
    cru.schema.create_requests_table(con)

    total, skipped, buf = 0, 0, []
    for item in iter_items(xml_path):
        row = row_from_item(item)
        if row is None:
            skipped += 1
            continue
        buf.append(row)
        if len(buf) >= batch:
            cru.schema.insert_rows(con, buf)
            total += len(buf)
            buf.clear()
    if buf:
        cru.schema.insert_rows(con, buf)
        total += len(buf)
    con.close()
    return total, skipped


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Import a Burp Suite 'Save items' XML export into the CRU "
        "requests-table schema. See README.md for how to produce the "
        "export."
    )
    ap.add_argument("xml", help="Burp XML export (Proxy history / site map)")
    ap.add_argument(
        "-o", "--out", default="burp.db", help="output SQLite DB (default: burp.db)"
    )
    ap.add_argument(
        "--replace", action="store_true", help="drop an existing requests table first"
    )
    args = ap.parse_args(argv)

    total, skipped = import_burp(args.xml, args.out, replace=args.replace)
    msg = f"Imported {total} requests into {args.out} [xml: {_XML_BACKEND}]"
    if skipped:
        msg += f" ({skipped} items skipped — no request data)"
    print(msg)


if __name__ == "__main__":
    main()
