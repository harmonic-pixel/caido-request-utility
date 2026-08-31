"""
report_html.py — render passive_scan findings as a self-contained HTML console.

Runs the same Check interface as passive_scan (imports its runner and Finding
type), then writes a verbose JSON report document AND a self-contained .html
rendered from that same document. The JSON is the intermediary: the HTML embeds
exactly the JSON that is written to disk, and `--from-json` re-renders the HTML
from an existing results file without rescanning.

The JSON document has four parts: `meta` (db, timestamp, row count, check
selection), `summary` (counts by check / host), `messages` (the request and
response a finding came out of, reconstructed once per row) and `findings`
(every finding with full context, each pointing at its message, at the offsets
of its evidence inside it, and at the panes it should offer — the store is per
row and shared, so a finding names its own rather than showing a neighbour's
decoded view). Secret redaction is applied before the
document is built, so the JSON respects --show-secrets too — messages included:
a secret is hidden in the message text as well as in the finding.

Security note: findings and messages contain attacker-controlled payloads (XSS,
etc.). Every finding value and every byte of a message is rendered client-side
via textContent / DOM building — the highlight is a <mark> element built by the
DOM, never markup spliced into a string — and the embedded JSON escapes <, >, &,
so the report cannot be XSS'd by what it shows.

A full run (`--check all`) also folds in `idor_finder`'s candidates under the
check name `idor`, so they filter, search and show their request like any other
finding.

Each finding's rule name links to the source of the check that raised it,
resolved from the registry against `REPO_URL` (the upstream repo, on `main`,
where the rules land after merging). `--repo-url` points them somewhere else —
a fork, a tag, a local mirror.

Usage:
    python -m cru.report_html your.db -o report.html          # writes .html + .json
    python -m cru.report_html your.db -o out.html --json out.json
    python -m cru.report_html --from-json out.json -o out.html # re-render, no rescan
    python -m cru.report_html your.db -o report.html --show-secrets   # careful
"""

from __future__ import annotations

import argparse
import datetime as _dt
import inspect
import json
import sqlite3
from dataclasses import asdict
from pathlib import Path
from typing import Any

from cru import idor_finder as idor
from cru import passive_scan as ps
from cru.checks import CHECKS
from cru.checks.base import Finding

TOOL_VERSION = "1.0"

# Where the rules live once this is merged upstream. Each finding links to the
# module its check is implemented in, at the class's own line.
_REPO_ROOT = Path(__file__).resolve().parent.parent
REPO_URL = "https://github.com/Skelmis/caido-request-utility/blob/main"


def _rule_urls(repo_url):
    """Map each check name to a link to the source of the check that raised it."""
    urls = {}
    # `idor` is not a registered check; its rule is the aggregation function.
    sources: dict[str, Any] = dict(CHECKS)
    sources["idor"] = idor.analyse
    for name, obj in sources.items():
        try:
            module = inspect.getmodule(obj)
            path = Path(inspect.getfile(obj)).relative_to(_REPO_ROOT).as_posix()
            line = inspect.getsourcelines(obj)[1]
        except (OSError, TypeError, ValueError):
            continue
        if module is None:
            continue
        urls[name] = f"{repo_url}/{path}#L{line}"
    return urls


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


def collect(db, table, check, show_secrets):
    rows = ps.load_rows(db, table)
    findings = []
    for c in ps.build_checks(check):
        findings.extend(c.run(rows))
    # IDOR is a separate tool with its own aggregation, not a registered check,
    # so it rides along only on a full run.
    if check == "all":
        findings.extend(idor_findings(db, table))
    findings.sort(key=lambda f: (f.host, f.check, f.path))
    # Locating runs while the findings still carry their raw evidence, against
    # the unmasked panes; masking is length-preserving, so the offsets survive.
    # It runs after the sort because the locations are aligned by index.
    messages = build_messages(rows, findings, show_secrets=show_secrets)
    findings = ps._present(findings, show_secrets=show_secrets)
    return rows, findings, messages


# --------------------------------------------------------------------------- #
# Messages: the request and response a finding came out of
# --------------------------------------------------------------------------- #

# How much of an observed value the ID listing shows.
_ID_DISPLAY = 80

# Per pane. A report is a triage view, not an archive of the corpus, but the
# cap has to clear a real response body or the evidence falls off the end and
# the finding loses its highlight.
# ponytail: flat cap. Window the pane around the match if a corpus of very
# large bodies makes the report unwieldy.
_PANE_CAP = 200_000


def _request_text(row):
    """Reconstruct the request from the stored fields.

    Not the captured bytes — `requests` keeps the parts, not the raw message —
    but the same fields the checks read, in wire order.
    """
    query = row["query"] or ""
    line = f"{row['method'] or ''} {row['path'] or ''}"
    if query:
        line += "?" + query
    head = [line + " HTTP/1.1"]
    if row["headers"]:
        head.append(row["headers"])
    return "\n".join(head) + "\n\n" + (row["body"] or "")


def _response_text(row):
    status = row["response_status_code"]
    head = [f"HTTP/1.1 {status}" if status is not None else "HTTP/1.1"]
    if row["response_headers"]:
        head.append(row["response_headers"])
    return "\n".join(head) + "\n\n" + (row["response_body"] or "")


def _needle(evidence):
    """The literal text to look for: evidence minus `_snippet`'s cosmetics."""
    return (evidence or "").removesuffix("…").replace("\\n", "\n")


def _utf16_len(text):
    """Length in UTF-16 code units — what JS string offsets count."""
    return len(text.encode("utf-16-le")) // 2


def _mask(secret):
    """`redact`'s shape, at `redact`'s expense, in the same number of units.

    Same-length means every offset computed against the unmasked pane still
    points at the same characters afterwards, so masking a secret cannot move
    another finding's highlight.
    """
    units = _utf16_len(secret)
    if units <= 8:
        return secret[:1] + "•" * (units - 1) if units else ""
    return secret[:4] + "•" * (units - 6) + secret[-2:]


def _hide(text, secrets):
    """Mask every known secret in a piece of text, keeping its length."""
    for raw in secrets:
        text = text.replace(raw, _mask(raw))
    return text


# Which scannable field a parameter-level location belongs to.
_FIELD_FOR_PARAM = {
    "body": "request-body",
    "query": "request-query",
    "cookies": "request-cookies",
}


def _sibling_views(location, available):
    """The decoded views of the field a finding came from.

    A JWT in a cookie matches in the raw request, so nothing ever matched in
    `request-cookies#decoded` and the pane that spells the token out was pruned
    away — from the one finding that most wanted it. This offers the decoded
    view of the field the finding is *about*, which is the rule the fingerprint
    case wanted too: related to this finding, not to its neighbours.
    """
    base = location.split("#", 1)[0]
    if ":" in base:
        base = _FIELD_FOR_PARAM.get(base.split(":", 1)[0], "")
    return [v for v in (f"{base}#decoded", f"{base}#json") if v in available]


def _panes_for(row):
    panes = {
        "request": _request_text(row)[:_PANE_CAP],
        "response": _response_text(row)[:_PANE_CAP],
    }
    # The decoded views are why a base64-wrapped payload can still be pointed
    # at: its evidence lives in `body_decoded`, not in the body on the wire.
    for label, text in ps.iter_fields(row):
        if label.endswith("#decoded") and text:
            panes[label] = text[:_PANE_CAP]
    return panes


def _locate(finding, rows, panes):
    """Which pane holds a finding's evidence, and where in it.

    Returns `(row_index, pane, [start, end])` in UTF-16 units, with a match of
    None when there is nothing to point at — a *missing* header has no text to
    highlight, and the request is still worth showing as context.
    """
    needle = _needle(finding.evidence)
    same_host = [i for i, row in enumerate(rows) if row["host"] == finding.host]
    on_path = [
        i for i in same_host if not finding.path or rows[i]["path"] == finding.path
    ]
    fallback = on_path[0] if on_path else (same_host[0] if same_host else None)
    if not needle:
        return fallback, "request", None
    # Findings dedupe, so a finding's path is one representative row's and a
    # merged one stands for many. Prefer the paths it names, then settle for
    # anywhere on the host.
    # ponytail: linear scan of the corpus per finding. Fine for a report over a
    # browsing session; index by (host, path) if a big corpus makes it drag.
    for i in on_path + [i for i in same_host if i not in on_path]:
        for pane, text in panes[i].items():
            at = text.find(needle)
            if at >= 0:
                start = _utf16_len(text[:at])
                return i, pane, [start, start + _utf16_len(needle)]
    return fallback, "request", None


def build_messages(rows, findings, show_secrets):
    """Panes per row, and where each finding's evidence sits in them.

    Findings must still hold their raw evidence here. Locating happens against
    the unmasked text; the secrets are then masked in place, which a message
    needs or it would leak in full what its own finding hides.
    """
    panes = {i: _panes_for(row) for i, row in enumerate(rows)}
    locations = [_locate(f, rows, panes) for f in findings]

    if not show_secrets:
        secrets = {f.evidence for f in findings if f.check == "secrets" and f.evidence}
        for row_panes in panes.values():
            for name, text in row_panes.items():
                row_panes[name] = _hide(text, secrets)
        # A secret can be quoted by a finding that is not a secrets finding:
        # `_present` only redacts that check, and idor_finder will treat a
        # bearer token in a hinted body parameter as an identifier, putting it
        # in `evidence` and in `ids`. Mask those the same way. Locations were
        # taken before this and the mask keeps its length, so they still hold.
        for f in findings:
            if f.evidence and f.check != "secrets":
                f.evidence = _hide(f.evidence, secrets)
            # A detail can quote claim values now, and a claim can hold a token.
            if f.detail:
                f.detail = _hide(f.detail, secrets)
            if f.ids:
                f.ids = [_hide(i, secrets) for i in f.ids]
    return {"panes": panes, "locations": locations}


def build_report_doc(rows, findings, meta_extra, messages=None, repo_url=REPO_URL):
    """The verbose JSON document — the intermediary the HTML is built from."""
    rule_urls = _rule_urls(repo_url)
    by_check, by_host = {}, {}
    for f in findings:
        by_check[f.check] = by_check.get(f.check, 0) + 1
        by_host[f.host] = by_host.get(f.host, 0) + 1

    meta = {
        "tool": "passive_scan",
        "format_version": TOOL_VERSION,
        # With the zone: a report gets read on another machine, and a bare
        # local timestamp there is a guess.
        "generated": _dt.datetime.now(_dt.UTC)
        .astimezone()
        .strftime("%Y-%m-%d %H:%M:%S %Z (UTC%z)"),
        "rows": len(rows),
        "rows_scanned": len(rows),
        "total_findings": len(findings),
    }
    meta.update(meta_extra or {})

    panes = (messages or {}).get("panes", {})
    locations = (messages or {}).get("locations", [])
    records, used = [], {}
    for i, f in enumerate(findings):
        rec = {"id": i}
        rec.update(asdict(f))
        # An observed value is meant to be an identifier; anything longer is
        # something else that got classified as one, and a full one would make
        # the listing unreadable.
        rec["ids"] = [
            v if len(v) <= _ID_DISPLAY else v[:_ID_DISPLAY] + "…" for v in f.ids
        ]
        row, pane, match = locations[i] if i < len(locations) else (None, None, None)
        rec.update({"row": row, "pane": pane, "match": match})
        rec["rule_url"] = rule_urls.get(f.check)
        if row is not None:
            # Keep the request and response of any row a finding points at, and
            # a decoded pane only when a finding actually landed in one.
            # The store is per row and several findings share it, so name the
            # panes *this* finding should offer: the exchange, whichever pane
            # its evidence was found in, and the decoded views of the field it
            # came from. Not its neighbours' — a fingerprint hit in a response
            # header has no business sprouting a request-body #decoded tab.
            offered = ["request", "response"]
            for extra in [pane, *_sibling_views(f.location, panes.get(row, {}))]:
                if extra not in offered:
                    offered.append(extra)
            rec["panes"] = offered
            used.setdefault(row, set()).update(offered)
        records.append(rec)

    return {
        "meta": meta,
        "summary": {
            "by_check": dict(sorted(by_check.items())),
            "by_host": dict(sorted(by_host.items())),
        },
        "messages": {
            str(row): {k: v for k, v in panes[row].items() if k in keep}
            for row, keep in sorted(used.items())
        },
        "findings": records,
    }


def _safe_json(obj) -> str:
    """json.dumps escaped so it can't break out of a <script> block."""
    s = json.dumps(obj, ensure_ascii=False)
    return (
        s.replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


def render_html(doc) -> str:
    """Render the HTML report from a report document (the JSON intermediary)."""
    return _TEMPLATE.replace("/*__DATA__*/null", _safe_json(doc))


# --------------------------------------------------------------------------- #
# The template: chrome is trusted (innerHTML ok); all finding values are set
# via textContent in JS. Palette is a cool "diagnostic console" scheme.
# --------------------------------------------------------------------------- #

_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Passive Scan — Report</title>
<style>
  :root{
    --ink:#161b22; --ink-soft:#4a5568; --paper:#eef1f5; --surface:#ffffff;
    --line:#dbe0e8; --line-soft:#e8ebf0;
    --accent:#12897a;
    --mono:ui-monospace,"SF Mono",SFMono-Regular,Menlo,Consolas,monospace;
    --sans:system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  }
  *{box-sizing:border-box}
  html,body{margin:0}
  body{background:var(--paper);color:var(--ink);font-family:var(--sans);
    font-size:14px;line-height:1.5;-webkit-font-smoothing:antialiased}
  .wrap{max-width:1080px;margin:0 auto;padding:32px 24px 96px}
  a{color:var(--accent)}

  .eyebrow{font-family:var(--mono);font-size:11px;letter-spacing:.18em;
    text-transform:uppercase;color:var(--ink-soft)}
  h1{font-size:26px;font-weight:680;letter-spacing:-.01em;margin:.3em 0 .1em}
  .meta{font-family:var(--mono);font-size:12px;color:var(--ink-soft);
    display:flex;flex-wrap:wrap;gap:6px 18px;margin-top:6px}
  .meta b{color:var(--ink);font-weight:600}


  /* controls */
  .controls{display:flex;flex-wrap:wrap;gap:10px;align-items:center;
    margin:22px 0 6px}
  .chips{display:flex;flex-wrap:wrap;gap:6px;flex:1 1 100%}
  .chip{font-family:var(--mono);font-size:11px;padding:4px 9px;border-radius:20px;
    border:1px solid var(--line);background:var(--surface);color:var(--ink-soft);
    cursor:pointer;white-space:nowrap}
  .chip[data-off="1"]{opacity:.4}
  .chip.on{border-color:var(--ink);color:var(--ink);background:#fff}
  .chip b{color:var(--ink);font-weight:700}
  .field{display:flex;align-items:center;gap:7px}
  select,input[type=search]{font-family:var(--mono);font-size:12px;
    padding:7px 9px;border:1px solid var(--line);border-radius:6px;
    background:var(--surface);color:var(--ink)}
  input[type=search]{flex:1 1 220px;min-width:180px}
  select:focus,input:focus{outline:2px solid var(--accent);outline-offset:-1px}
  .count{font-family:var(--mono);font-size:12px;color:var(--ink-soft);
    margin:10px 2px}

  /* host groups + findings */
  .host{border:1px solid var(--line);border-radius:8px;background:var(--surface);
    margin:12px 0;overflow:hidden}
  .host-hd{display:flex;align-items:center;gap:12px;padding:12px 14px;
    cursor:pointer;border-bottom:1px solid transparent}
  .host.open .host-hd{border-bottom-color:var(--line-soft)}
  .host-hd .caret{font-family:var(--mono);color:var(--ink-soft);transition:.15s;
    font-size:11px}
  .host.open .host-hd .caret{transform:rotate(90deg)}
  .host-name{font-family:var(--mono);font-weight:600;font-size:13px}
  .tally{margin-left:auto;display:flex;gap:6px;font-family:var(--mono);
    font-size:11px}
  .tally i{font-style:normal;padding:1px 7px;border-radius:4px;
    background:var(--line-soft);color:var(--ink-soft)}
  .rows{display:none} .host.open .rows{display:block}

  .row{border-top:1px solid var(--line-soft)}
  .row:first-child{border-top:0}
  .row-hd{display:grid;grid-template-columns:84px 1fr;gap:12px;
    align-items:center;padding:10px 14px;cursor:pointer}
  .row-hd:hover{background:#f7f9fc}
  .r-check{font-family:var(--mono);font-size:11px;color:var(--ink-soft);
    text-align:left}
  .r-main{min-width:0}
  .r-title{font-family:var(--mono);font-size:12.5px;color:var(--ink);
    white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .r-title .mth{color:var(--accent);font-weight:600}
  .r-ev{font-family:var(--mono);font-size:11.5px;color:var(--ink-soft);
    white-space:nowrap;overflow:hidden;text-overflow:ellipsis;margin-top:2px}
  .detail{display:none;padding:2px 14px 16px 32px}
  .row.open .detail{display:block}
  .detail .note{color:var(--ink);margin:6px 0 10px;max-width:70ch}
  .kv{display:grid;grid-template-columns:92px 1fr;gap:2px 12px;
    font-family:var(--mono);font-size:11.5px}
  .kv dt{color:var(--ink-soft)} .kv dd{margin:0;color:var(--ink);
    word-break:break-all}
  .kv dd a{color:var(--accent);text-decoration:none;
    border-bottom:1px solid rgba(18,137,122,.35)}
  .kv dd a:hover{border-bottom-color:var(--accent)}
  .evidence{font-family:var(--mono);font-size:12px;background:#0f1420;
    color:#e7edf6;padding:10px 12px;border-radius:6px;margin:8px 0 12px;
    white-space:pre-wrap;word-break:break-all;max-height:220px;overflow:auto}
  .msg-tabs{display:flex;gap:6px;flex-wrap:wrap;margin:10px 0 0}
  .msg-tab{font-family:var(--mono);font-size:11px;color:var(--ink-soft);
    background:var(--surface);border:1px solid var(--line);border-radius:5px;
    padding:3px 9px;cursor:pointer}
  .msg-tab:hover{border-color:var(--accent);color:var(--accent)}
  .msg-tab.on{color:#fff;background:var(--accent);border-color:var(--accent)}
  .msg{font-family:var(--mono);font-size:12px;line-height:1.5;background:#0f1420;
    color:#e7edf6;padding:10px 12px;border-radius:6px;margin:8px 0 6px;
    white-space:pre-wrap;word-break:break-all;max-height:340px;overflow:auto}
  .msg mark{background:#ffd54a;color:#14181f;border-radius:2px;padding:0 1px;
    box-shadow:0 0 0 2px #ffd54a}
  .msg-note{font-family:var(--mono);font-size:11px;color:var(--ink-soft);
    margin:0 0 12px}
  .paths{margin:0 0 12px}
  .paths summary{font-family:var(--mono);font-size:11.5px;color:var(--accent);
    cursor:pointer}
  .paths ul{margin:6px 0 0;padding-left:18px;font-family:var(--mono);
    font-size:11.5px;color:var(--ink);max-height:200px;overflow:auto}
  .paths li{margin:1px 0;word-break:break-all}
  .r-title .more{color:var(--ink-soft)}

  .empty{text-align:center;color:var(--ink-soft);font-family:var(--mono);
    padding:60px 20px}
  .foot{margin-top:34px;font-family:var(--mono);font-size:11px;
    color:var(--ink-soft)}
  @media (max-width:560px){
    .row-hd{grid-template-columns:1fr}.r-check{display:none}
  }
  @media (prefers-reduced-motion:reduce){*{transition:none!important}}
</style>
</head>
<body>
<div class="wrap">
  <div class="eyebrow">Passive Scan // Report</div>
  <h1>Findings console</h1>
  <div class="meta" id="meta"></div>

  <div class="controls">
    <div class="chips" id="chips"></div>
    <div class="field">
      <select id="host" aria-label="Filter by host"></select>
    </div>
    <div class="field" style="flex:1 1 220px">
      <input type="search" id="search" placeholder="Filter by path, rule, or evidence…" aria-label="Search findings">
    </div>
  </div>
  <div class="count" id="count"></div>

  <div id="list"></div>
  <div class="foot" id="foot"></div>
</div>

<script id="r-data" type="application/json">/*__DATA__*/null</script>
<script>
(function(){
  "use strict";
  var DATA = JSON.parse(document.getElementById("r-data").textContent);
  var F = DATA.findings || [];
  var META = DATA.meta || {};
  var MSG = DATA.messages || {};
  var state = { checks:{}, host:"all", q:"" };
  // counts
  var checkCount={}, hosts={};
  F.forEach(function(f){
    checkCount[f.check]=(checkCount[f.check]||0)+1;
    hosts[f.host]=(hosts[f.host]||0)+1;
  });
  Object.keys(checkCount).sort().forEach(function(c){state.checks[c]=true;});

  function el(tag,cls,txt){var e=document.createElement(tag);
    if(cls)e.className=cls; if(txt!=null)e.textContent=txt; return e;}

  // The message is attacker-controlled text: every part of it goes in as a text
  // node, and the highlight is a real <mark> element, never spliced-in markup.
  function paint(pre,text,match){
    pre.textContent="";
    if(!match){ pre.appendChild(document.createTextNode(text)); return; }
    pre.appendChild(document.createTextNode(text.slice(0,match[0])));
    var m=document.createElement("mark");
    m.textContent=text.slice(match[0],match[1]);
    pre.appendChild(m);
    pre.appendChild(document.createTextNode(text.slice(match[1])));
    requestAnimationFrame(function(){
      if(m.offsetTop>pre.clientHeight*0.6) pre.scrollTop=m.offsetTop-pre.clientHeight/3;
    });
  }

  // meta line
  (function(){
    var m=document.getElementById("meta");
    function add(label,val){var b=el("b",null,val);
      var s=el("span"); s.appendChild(document.createTextNode(label+" ")); s.appendChild(b); m.appendChild(s);}
    add("db", META.db||"—");
    add("scanned", (META.rows!=null?META.rows:"—")+" requests");
    add("findings", String(F.length));
    add("checks", META.check||"all");
    add("generated", META.generated||"");
  })();

  // check chips
  var chips=document.getElementById("chips");
  var allChip=el("div","chip on","all checks");
  allChip.addEventListener("click",function(){
    var anyOff=Object.keys(state.checks).some(function(c){return !state.checks[c];});
    Object.keys(state.checks).forEach(function(c){state.checks[c]=anyOff;});
    syncChips(); render();
  });
  chips.appendChild(allChip);
  var chipEls={};
  Object.keys(checkCount).sort().forEach(function(c){
    var ch=el("div","chip on"); ch.appendChild(el("span",null,c+" "));
    ch.appendChild(el("b",null,String(checkCount[c])));
    ch.addEventListener("click",function(){state.checks[c]=!state.checks[c];syncChips();render();});
    chips.appendChild(ch); chipEls[c]=ch;
  });
  function syncChips(){
    Object.keys(chipEls).forEach(function(c){
      chipEls[c].className="chip "+(state.checks[c]?"on":"");
      chipEls[c].setAttribute("data-off",state.checks[c]?"0":"1");
    });
    var allOn=Object.keys(state.checks).every(function(c){return state.checks[c];});
    allChip.className="chip "+(allOn?"on":"");
  }

  // host select
  var hostSel=document.getElementById("host");
  hostSel.appendChild(new Option("all hosts ("+Object.keys(hosts).length+")","all"));
  Object.keys(hosts).sort().forEach(function(h){
    hostSel.appendChild(new Option(h+" ("+hosts[h]+")",h));});
  hostSel.addEventListener("change",function(){state.host=hostSel.value;render();});

  var search=document.getElementById("search");
  search.addEventListener("input",function(){state.q=search.value.toLowerCase();render();});

  function visible(f){
    if(!state.checks[f.check]) return false;
    if(state.host!=="all" && f.host!==state.host) return false;
    if(state.q){
      var hay=(f.path+" "+f.signature+" "+f.evidence+" "+f.detail+" "+f.location).toLowerCase();
      if(hay.indexOf(state.q)<0) return false;
    }
    return true;
  }

  var list=document.getElementById("list");
  var countEl=document.getElementById("count");

  function render(){
    list.innerHTML="";
    var shown=F.filter(visible);
    countEl.textContent=shown.length+" of "+F.length+" findings shown";
    if(!shown.length){
      list.appendChild(el("div","empty","No findings match the current filters."));
      return;
    }
    // group by host
    var byHost={};
    shown.forEach(function(f){(byHost[f.host]=byHost[f.host]||[]).push(f);});
    // One host: there is nothing to choose between, so show its findings. More
    // than one: open them all and the list is a wall you have to scroll past to
    // find the host you came for.
    var openByDefault=Object.keys(byHost).length===1;
    Object.keys(byHost).sort().forEach(function(h){
      var items=byHost[h].sort(function(a,b){
        return a.check.localeCompare(b.check)||a.path.localeCompare(b.path);});
      var host=el("div","host"+(openByDefault?" open":""));
      var hd=el("div","host-hd");
      hd.appendChild(el("span","caret","▶"));
      hd.appendChild(el("span","host-name",h||"(host-level)"));
      var tally=el("span","tally");
      tally.appendChild(el("i",null,items.length+(items.length===1?" finding":" findings")));
      hd.appendChild(tally);
      hd.addEventListener("click",function(){host.classList.toggle("open");});
      host.appendChild(hd);
      var rowsWrap=el("div","rows");
      items.forEach(function(f){ rowsWrap.appendChild(rowEl(f)); });
      host.appendChild(rowsWrap);
      list.appendChild(host);
    });
  }

  function rowEl(f){
    var row=el("div","row");
    var hd=el("div","row-hd");
    hd.appendChild(el("div","r-check",f.check));
    var main=el("div","r-main");
    var title=el("div","r-title");
    var loc = f.path ? "" : (" · "+f.location);
    var mth=el("span","mth",f.method||""); title.appendChild(mth);
    title.appendChild(document.createTextNode(" "+(f.path|| "["+f.location+"]")+"  "));
    var np=(f.paths||[]).length;
    if(np>1) title.appendChild(el("span","more","+"+(np-1)+" more paths  "));
    var sig=el("span",null,f.signature); sig.style.color="var(--ink-soft)";
    title.appendChild(sig);
    var ev=el("div","r-ev",f.evidence||"");
    main.appendChild(title); main.appendChild(ev);
    hd.appendChild(main);
    row.appendChild(hd);

    var det=el("div","detail");
    if(f.detail) det.appendChild(el("div","note",f.detail));
    function listing(items,summary){
      var d=el("details","paths");
      d.appendChild(el("summary",null,summary));
      var ul=el("ul");
      items.forEach(function(it){ ul.appendChild(el("li",null,it)); });
      d.appendChild(ul);
      return d;
    }
    if((f.paths||[]).length>1){
      det.appendChild(listing(f.paths,
        "seen on "+f.paths.length+" requests — same finding, deduplicated"));
    }
    if((f.rules||[]).length>1){
      det.appendChild(listing(f.rules,
        f.rules.length+" places this rule matched — one finding, not one each"));
    }
    if((f.ids||[]).length){
      det.appendChild(listing(f.ids,
        f.ids.length+" observed ID"+(f.ids.length===1?"":"s")
        +" — replay these as a second identity"));
    }
    var msg=MSG[String(f.row)];
    if(msg){
      // Only this finding's panes: the store is shared across the row.
      var names=(f.panes||Object.keys(msg)).filter(function(n){
        return msg[n]!==undefined;});
      var first=(f.pane && msg[f.pane]!==undefined)?f.pane:names[0];
      var tabs=el("div","msg-tabs"), pre=el("pre","msg");
      names.forEach(function(nm){
        var b=el("button","msg-tab"+(nm===first?" on":""),nm);
        b.type="button";
        b.addEventListener("click",function(){
          Array.prototype.forEach.call(tabs.children,function(x){
            x.className="msg-tab";});
          b.className="msg-tab on";
          paint(pre,msg[nm],nm===f.pane?f.match:null);
        });
        tabs.appendChild(b);
      });
      det.appendChild(tabs); det.appendChild(pre);
      paint(pre,msg[first],first===f.pane?f.match:null);
      det.appendChild(el("div","msg-note", f.match
        ? "Reconstructed from the stored fields; the match is highlighted."
        : "Reconstructed from the stored fields. Nothing to highlight — this "
          +"finding is about what the response does not contain."));
    } else if(f.evidence){
      det.appendChild(el("div","evidence",f.evidence));
    }
    var kv=el("dl","kv");
    [["rule",f.signature],["check",f.check],["host",f.host||"—"],
     ["method",f.method||"—"],["path",f.path||"—"],
     ["location",f.location||"—"]].forEach(function(p){
      kv.appendChild(el("dt",null,p[0]));
      var dd=el("dd");
      // The rule name links to the check that raised it. href is built from
      // the registry, never from finding text, so nothing attacker-controlled
      // reaches a URL.
      if(p[0]==="rule" && f.rule_url){
        var a=el("a",null,p[1]);
        a.href=f.rule_url; a.target="_blank"; a.rel="noopener noreferrer";
        a.title="source of this check";
        dd.appendChild(a);
      } else {
        dd.textContent=p[1];
      }
      kv.appendChild(dd);});
    det.appendChild(kv);
    row.appendChild(det);
    hd.addEventListener("click",function(){row.classList.toggle("open");});
    return row;
  }

  document.getElementById("foot").textContent=
    "Passive analysis of captured traffic — findings are leads to confirm against systems you are authorised to test because I vibe coded the shit out of this.";
  render();
})();
</script>
</body>
</html>
"""


def _json_path_for(html_path, explicit):
    if explicit:
        return explicit
    if html_path.lower().endswith(".html"):
        return html_path[:-5] + ".json"
    return html_path + ".json"


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Write a verbose JSON report and a self-contained HTML view."
    )
    ap.add_argument(
        "db", nargs="?", help="SQLite DB to scan (omit when using --from-json)"
    )
    ap.add_argument(
        "-o",
        "--out",
        default="report.html",
        help="HTML output path (default: report.html)",
    )
    ap.add_argument(
        "--json", default=None, help="JSON output path (default: alongside the HTML)"
    )
    ap.add_argument(
        "--from-json",
        default=None,
        help="render HTML from an existing report JSON, no rescan",
    )
    ap.add_argument("--table", default="requests")
    ap.add_argument("--check", default="all")
    ap.add_argument("--show-secrets", action="store_true")
    ap.add_argument(
        "--repo-url",
        default=REPO_URL,
        help="base URL each rule links to (default: the upstream repo on main)",
    )
    args = ap.parse_args(argv)

    # Re-render path: JSON is the intermediary, so we can rebuild HTML from it.
    if args.from_json:
        with open(args.from_json, encoding="utf-8") as fh:
            doc = json.load(fh)
        if "findings" not in doc:
            ap.error(f"{args.from_json} is not a report document (no 'findings')")
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(render_html(doc))
        print(
            f"Rendered {args.out} from {args.from_json} "
            f"({len(doc['findings'])} findings)"
        )
        return

    if not args.db:
        ap.error("a db argument is required unless --from-json is given")

    rows, findings, messages = collect(
        args.db, args.table, args.check, args.show_secrets
    )
    doc = build_report_doc(
        rows,
        findings,
        {
            "db": args.db,
            "check": args.check,
            "secrets_redacted": not args.show_secrets,
        },
        messages,
        repo_url=args.repo_url,
    )

    json_path = _json_path_for(args.out, args.json)
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, ensure_ascii=False)
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(render_html(doc))

    print(
        f"Wrote {json_path} and {args.out} — "
        f"{len(findings)} findings from {len(rows)} requests"
    )


if __name__ == "__main__":
    main()
