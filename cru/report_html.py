"""
report_html.py — render passive_scan findings as a self-contained HTML console.

Runs the same Check interface as passive_scan (imports its runner and Finding
type), then writes a verbose JSON report document AND a self-contained .html
rendered from that same document. The JSON is the intermediary: the HTML embeds
exactly the JSON that is written to disk, and `--from-json` re-renders the HTML
from an existing results file without rescanning.

The JSON document has three parts: `meta` (db, timestamp, row count, check
selection), `summary` (counts by check / host), and `findings` (every
finding with full context). Secret redaction is applied before the document is
built, so the JSON respects --show-secrets too.

Security note: findings contain attacker-controlled payloads (XSS, etc.). Every
finding value is rendered client-side via textContent / DOM building, and the
embedded JSON escapes <, >, & — so the report cannot be XSS'd by what it shows.

Usage:
    python -m cru.report_html your.db -o report.html          # writes .html + .json
    python -m cru.report_html your.db -o out.html --json out.json
    python -m cru.report_html --from-json out.json -o out.html # re-render, no rescan
    python -m cru.report_html your.db -o report.html --show-secrets   # careful
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
from dataclasses import asdict

from cru import passive_scan as ps

TOOL_VERSION = "1.0"


def collect(db, table, check, show_secrets):
    rows = ps.load_rows(db, table)
    findings = []
    for c in ps.build_checks(check):
        findings.extend(c.run(rows))
    findings = ps._present(findings, show_secrets=show_secrets)
    findings.sort(key=lambda f: (f.host, f.check, f.path))
    return rows, findings


def build_report_doc(rows, findings, meta_extra):
    """The verbose JSON document — the intermediary the HTML is built from."""
    by_check, by_host = {}, {}
    for f in findings:
        by_check[f.check] = by_check.get(f.check, 0) + 1
        by_host[f.host] = by_host.get(f.host, 0) + 1

    meta = {
        "tool": "passive_scan",
        "format_version": TOOL_VERSION,
        "generated": _dt.datetime.now(_dt.UTC)
        .astimezone()
        .strftime("%Y-%m-%d %H:%M:%S"),
        "rows": len(rows),
        "rows_scanned": len(rows),
        "total_findings": len(findings),
    }
    meta.update(meta_extra or {})

    records = []
    for i, f in enumerate(findings):
        rec = {"id": i}
        rec.update(asdict(f))
        records.append(rec)

    return {
        "meta": meta,
        "summary": {
            "by_check": dict(sorted(by_check.items())),
            "by_host": dict(sorted(by_host.items())),
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
  .evidence{font-family:var(--mono);font-size:12px;background:#0f1420;
    color:#e7edf6;padding:10px 12px;border-radius:6px;margin:8px 0 12px;
    white-space:pre-wrap;word-break:break-all;max-height:220px;overflow:auto}

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
    Object.keys(byHost).sort().forEach(function(h){
      var items=byHost[h].sort(function(a,b){
        return a.check.localeCompare(b.check)||a.path.localeCompare(b.path);});
      var host=el("div","host open");
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
    var sig=el("span",null,f.signature); sig.style.color="var(--ink-soft)";
    title.appendChild(sig);
    var ev=el("div","r-ev",f.evidence||"");
    main.appendChild(title); main.appendChild(ev);
    hd.appendChild(main);
    row.appendChild(hd);

    var det=el("div","detail");
    if(f.detail) det.appendChild(el("div","note",f.detail));
    if(f.evidence){ det.appendChild(el("div","evidence",f.evidence)); }
    var kv=el("dl","kv");
    [["rule",f.signature],["check",f.check],["host",f.host||"—"],
     ["method",f.method||"—"],["path",f.path||"—"],
     ["location",f.location||"—"]].forEach(function(p){
      kv.appendChild(el("dt",null,p[0])); kv.appendChild(el("dd",null,p[1]));});
    det.appendChild(kv);
    row.appendChild(det);
    hd.addEventListener("click",function(){row.classList.toggle("open");});
    return row;
  }

  document.getElementById("foot").textContent=
    "Passive analysis of captured traffic — findings are leads to confirm against systems you are authorised to test.";
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

    rows, findings = collect(args.db, args.table, args.check, args.show_secrets)
    doc = build_report_doc(
        rows,
        findings,
        {
            "db": args.db,
            "check": args.check,
            "secrets_redacted": not args.show_secrets,
        },
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
