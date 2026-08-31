# CHECKS.md

Per-check reference for the checks in `cru/checks/` (one module per check, run by
`cru/passive_scan.py`). What each check catches, the patterns behind it, and where
it stops.

## How to read this

**Everything here is passive.** The scanner reads a SQLite corpus of captured
request/response pairs and sends no traffic of its own. A finding means "this
pattern is present in traffic you already captured", not "this is exploitable".
Every finding is a lead to confirm by hand against a system you are authorised
to test.

**A finding can stand for several requests.** `paths` lists every path an
occurrence was seen on. Most checks dedupe per path, so it holds one entry; the
JWT ones dedupe on decoded content, so a merged finding lists them all. A count
of findings was never a count of requests, and is less so now.

**There is no severity ranking.** `Finding(...)` accepts a severity argument for
readability at the call site and discards it (`cru/checks/base.py`); the stored
`_Finding` has no severity field. Output is grouped by check, never ranked.
Where an entry below says a signal is "strong" or "weaker", that is guidance for
your triage, not something the tool sorts on.

### Where checks read from

| Helper | Yields |
|--------|--------|
| `request_inputs(row)` | `(label, text)` for request cookies, headers, query, body — URL-decoded |
| `iter_fields(row)` | as above plus response headers and body — raw, not URL-decoded |
| `request_param_values(row)` | `(location, value)` per individual query/body parameter, incl. nested JSON leaves |
| `response_text(row)` | response headers and body concatenated |

Checks that hunt for a payload use the request-side helpers; checks that hunt
for a leak or a misconfiguration read the response.

### Encoding coverage

Base64/hex-wrapped payloads are decoded **once, at import time** by
`field_decode.decoded_view()` into the `query_decoded`, `body_decoded`,
`cookies_decoded`, `headers_decoded` and `response_body_decoded` columns. The
field helpers surface those as extra `#decoded` views (`request-body#decoded`,
etc.), so every pattern check gets encoding coverage without decoding anything
itself. A finding whose `location` ends in `#decoded` was found in recovered
plaintext, not in the field as sent.

Two limits worth knowing:

- **One layer only.** `decoded_view` unwraps base64 *or* hex, not
  base64-of-hex-of-payload. A doubly-wrapped payload is invisible.
- **A database without the columns loses it silently.** If the `*_decoded`
  columns are absent, `load_rows` falls back to the base columns and no
  `#decoded` views are produced — no error, just less coverage. Both CRU import
  paths write them, so this only affects a corpus built by another tool.

### Corpus-wide limits

These apply to every check; per-check entries below point back here rather than
repeat them.

- **Duplicate headers collapse.** Response headers are parsed into a dict
  upstream, so repeated header lines (several `Set-Cookie`s, an injected second
  header) do not all survive into the corpus. Response-side confirmation of
  header injection is therefore unreliable — see `crlf` and `cookies`.
- **Fields are truncated** at `_MAX_FIELD` = 400,000 bytes per field.
- **Evidence is truncated** to 60 characters by `_snippet`, with a trailing `…`.
- **Findings dedupe** on `(check, signature, host, path, location, evidence)`.
  The same finding across a thousand rows collapses to one, so a finding count
  is not a request count.
- **Host-level findings** (`headers`, `cookies`, `fingerprint`, `methods`,
  `mixedcontent`) blank the path before dedup, so they report once per host
  rather than once per URL.

---

## `deser` — deserialization / serialized-object payloads

Serialized objects crossing a trust boundary are a direct path to RCE when the
receiving side calls an unsafe `unserialize()` / `readObject()` / `loads()`.
This flags both the serialized form itself and the markers of known gadget
vectors.

- **Reads:** `iter_fields` (request *and* response), URL-decoded.
- **Signatures:** 12 string patterns — PHP serialized object and array,
  `phar://`, node-serialize's `_$$ND_FUNC$$_`, Java XMLDecoder, Jackson/fastjson
  `"@type":` polymorphic hints, YAML object tags, ASP.NET `__VIEWSTATE`, and the
  base64 prefixes of Java (`rO0AB`), .NET BinaryFormatter (`AAEAAAD/////`) and
  Ruby Marshal (`BAh`). Plus 4 magic-byte signatures matched against
  base64-*decoded* blobs (`b64_blobs`): Java `AC ED 00 05`, .NET
  BinaryFormatter, Ruby Marshal `04 08`, gzip `1F 8B`. Python pickle is detected
  by protocol opcode (`\x80\x02`–`\x80\x05`) or a `c__builtin__` /
  `cos\nsystem` / `csubprocess` opcode in the first 64 bytes.
- **Limits:** `php-serialized-array` and `gzip-wrapped-blob` fire on benign
  traffic by design — a serialized array is often just data, and a gzip blob is
  reported so you decompress it yourself. Gzip blobs are **not** decompressed
  and re-scanned. `__VIEWSTATE` presence says nothing about whether MAC
  validation is on; that still needs checking by hand.

## `secrets` — credentials and high-entropy tokens

Two passes: high-precision vendor detectors, then a generic entropy sweep for
tokens no detector knows about.

- **Reads:** `iter_fields`.
- **Signatures:** 20 detectors — AWS access key IDs, GitHub PATs (classic and
  fine-grained), GitLab PATs, Slack tokens and webhooks, Stripe live/test keys,
  Google API keys and OAuth tokens, OpenAI, Anthropic, SendGrid, npm, Twilio,
  Mailgun, PEM private-key blocks, JWTs, `Authorization: Basic`, and a generic
  `password=`/`api_key=`-style assignment. The entropy pass flags base64-ish
  tokens of length ≥ 20 scoring ≥ 4.5 bits, or hex tokens scoring ≥ 3.0.
- **Dedup:** the `jwt` detector groups on decoded token content, exactly as the
  `jwt` check does, so a re-issued session token is one finding listing every
  path. Every other detector dedupes per path as before.
- **Redaction:** secret evidence is redacted for display (`redact` via
  `_present`) as `abcd…yz (44 chars)`. `--show-secrets` prints it in full.
  `--no-entropy` disables the second pass.
- **Limits:** `generic-secret-assignment` is deliberately noisy — it catches
  `password=` in traffic that is merely *about* passwords. The entropy pass
  skips UUID-prefixed values and 24/32/40/64-character hex (almost always hashes
  or IDs, not secrets), which also means a 32-hex API key is missed. The
  24-character case is the Mongo ObjectId: on a Mongo-backed API it was 81% of
  all `high-entropy-string` hits and none of them were secrets. They are still
  worth chasing, just as *enumeration* candidates — `idor_finder` classifies
  them as `mongo-objectid` and scores them for sequencing. Detecting a
  key says nothing about whether it is live; treat every hit as needing
  revocation triage, not as confirmed compromise.

## `sqli` — SQL injection

Correlates three independent signals in the same row.

- **Reads:** `response_text` for errors; `request_inputs` for payloads;
  `request_param_values` for parameter names.
- **Signatures:** (a) DBMS error fingerprints for 6 families — MySQL/MariaDB,
  PostgreSQL, MSSQL, Oracle (`ORA-nnnnn`), SQLite, and generic JDBC/ODBC/DB2.
  A DB error reaching the client means input reached the query engine
  unhandled, which is reported on its own. (b) 7 payload shapes in request
  inputs: tautology, `UNION SELECT`, quote-plus-comment terminator, stacked
  query, time-based (`sleep`/`pg_sleep`/`benchmark`/`waitfor delay`),
  error-based functions (`extractvalue`/`updatexml`), and quoted tautology.
  (c) parameter *names* that hand the caller part of the query, in two tiers
  like the `code` check. `sink` is any name containing `sql` — which covers the
  permutations as they appear in the wild: `sqlQuery`, `sql_query`, `sql-query`,
  `SQLQuery`, `rawSql`, `execSQL`, `sqlStatement`. `clause` is a bare SQL clause
  name — `where`, `whereClause`, `orderBy`, `sortBy`, `groupBy`, `having`,
  `select`, `from`, `table`, `tableName` — meaning the query is composed from
  caller input even when the value itself is not raw SQL.
- **Correlation:** a payload or a query-composition parameter, plus a DB error
  or a 5xx in the same row, is called out as "likely injectable" in the
  finding's note. With a clean 200 it is reported as observed input only.
- **Limits:** only the *first* matching error family is reported per row
  (the loop breaks). There is no timing data in the corpus, so blind and
  time-based SQLi produce no confirmation — a `sleep(5)` payload is flagged as
  a payload, never as a hit. The `clause` tier keys on the name alone, so a REST
  API that legitimately exposes `orderBy` or `sortBy` for pagination will be
  flagged; that is the point — the parameter is a query-composition surface —
  but expect it on healthy endpoints too.

## `ssti` — server-side template injection

Flags request inputs carrying template-expression syntax, tagged by templating
style.

- **Reads:** `request_inputs` only. It never looks at responses.
- **Signatures:** 12 styles — Jinja2/Twig/Angular `{{…}}`, Jinja/Twig
  statements `{%…%}`, Handlebars blocks, EL/FreeMarker/Thymeleaf `${…}`,
  Ruby/JSF `#{…}`, Thymeleaf `*{…}` and `@{…}`, ERB/JSP/EJS/ASP `<%…%>`,
  Velocity directives, FreeMarker directives, Smarty, and the
  `${{<%[%'"}}%` polyglot. A match containing an `_SSTI_DANGEROUS` token
  (`config`, `self`, `request`, `__class__`, `__globals__`, `__subclasses__`,
  `Runtime`, `getRuntime`, `ProcessBuilder`, `T(`, `new X(`, …) is called out as
  a likely payload rather than incidental syntax.
- **Limits:** request-side only, so evaluation is never confirmed — a flagged
  input may be rendered, escaped, or ignored entirely. JavaScript template
  literals, CSS-in-JS, and any data that legitimately contains braces are
  expected false positives at the plain `{{…}}` / `${…}` tiers.

## `code` — code-bearing inputs

A parameter that accepts raw source or a shell command is a parameter that may
reach an `eval()` / `exec()` / command sink.

- **Reads:** `request_inputs` only.
- **Signatures:** two tiers per language. `exec` covers execution and eval
  sinks; `syntax` covers language structure that merely suggests the field takes
  code. Languages: Python, JavaScript/Node, PHP, Ruby, Java/OGNL, PowerShell,
  and shell. Cross-language sinks (`eval` / `exec` / `system` / `passthru` /
  `shell_exec` / `popen` / `proc_open`) are one shared signature so a single
  `eval(` is not reported once per language. JNDI/Log4Shell lookups
  (`${jndi:ldap:` and friends) and nested Log4j lookups (`${lower:`, `${env:`)
  are their own signatures.
- **Limits:** the `syntax` tier fires on ordinary prose and data — a
  code-review comment, a JSON blob with `function`, an English sentence
  containing `import os`. Shell detection keys on command names after a
  separator, which false-positives on natural text. Treat `syntax` hits as "look
  at this parameter", not as findings in themselves.

## `srcleak` — source and config disclosure

Responses returning server-side source or configuration that should never reach
the client.

- **Reads:** `response_text`, plus the request path.
- **Signatures:** four tables. *Server tags* (5): PHP open tags, JSP
  directives/scriptlets, ASP/ASP.NET directives, SSI directives, ERB source —
  all meaning a template was served unexecuted. *Source constructs* (6): Java,
  Python, PHP, C#, Node and Ruby/Rails source markers. *Config files* (5):
  `.env` with credentials, `wp-config.php` defines, `web.config`
  `<connectionStrings>`/`<machineKey>`, Django `settings.py`, PHP config arrays
  with passwords. *VCS* (1): `.git` metadata. Plus an interpreter shebang at the
  start of a line, and a risky-path rule — a backup/dotfile/VCS path
  (`.bak`, `.old`, `~`, `/.git/`, `/.env`, `.php.txt`, …) returning 200 with a
  non-empty body.
- **Limits:** keys on server-side-only markers, so a normal `.js` response is
  never a finding — but that also means client-side source disclosure is out of
  scope by design. The risky-path rule cannot tell a real backup from a route
  that happens to end in `.old`.

## `xss` — cross-site scripting

Two signals: payload syntax in request inputs, and reflection of parameter
values in the response body.

- **Reads:** `request_inputs` for payloads, `request_param_values` plus the raw
  response body for reflection.
- **Signatures:** 8 payload vectors — `<script>`, `javascript:` URI, a tag with
  an event handler, a bare event handler, a JS sink call
  (`alert(`/`document.cookie`/`String.fromCharCode(`), attribute breakout,
  `data:text/html`, and bare `<svg>`/`<math>`.
- **Correlation:** a payload escalates to "likely exploitable" only when the
  matched fragment contains `<` or `>` **and** comes back in the response body
  verbatim. Inert fragments like `alert(` or `onerror=` can reflect even when
  the surrounding tag characters were HTML-encoded, so they never escalate.
  Separately, any parameter value ≥ 4 characters that reflects is reported —
  as a reflected-XSS candidate if it carries `<`, `>` or `"` unencoded, and as
  a context-check note if it is ≥ 8 characters of plain text.
- **Limits:** reflection is a substring match against the raw body. There is no
  parsing of output context, so a value reflected inside a JS string, an
  attribute, or a comment all look identical here. DOM-based XSS is entirely
  invisible — it never appears in the response body.

## `xxe` — XML external entities

- **Reads:** the four request fields in **both** raw and URL-decoded form, so
  percent-encoding cannot hide a declaration; the response body for the
  file-read tell.
- **Signatures:** 6 — external entity (`<!ENTITY x SYSTEM|PUBLIC`), parameter
  entity (`<!ENTITY % x`, the blind/OOB vector), a `file://` URI in a
  SYSTEM/PUBLIC/href/src position, exotic stream wrappers (`php://filter`,
  `php://input`, `expect://`, `jar:`, `netdoc:`, `gopher://`), a DOCTYPE with an
  internal subset, and a bare DOCTYPE. Plus `_XXE_FILE_DISCLOSURE` on the
  response body — `root:x:0:0:`, `[fonts]`, `[extensions]`,
  `; for 16-bit app support` — meaning a local file actually came back.
- **Limits:** a bare `<!DOCTYPE` is normal in plenty of XML and is reported only
  so you can see the XML attack surface. The response-side rule only knows the
  handful of well-known file signatures above; a read of any other file is
  invisible.

## `ssrf` — server-side request forgery

- **Reads:** `request_param_values` — parameter names matter here, so this works
  per-parameter rather than per-field.
- **Signatures:** three tiers. Cloud metadata endpoints (`169.254.169.254`,
  `metadata.google`, `100.100.100.200`, `instance-data`) fire on any parameter,
  because there is no benign reason for them to be there. An internal or
  loopback host (`localhost`, RFC1918 ranges, `::1`, `169.254.*`, `.internal`,
  `.local`, `.consul`) fires when the value looks like a URL *or* the parameter
  name is fetch-shaped. An external URL fires only in a fetch-shaped parameter
  name (`url`, `uri`, `src`, `redirect`, `webhook`, `proxy`, `image`, `feed`,
  `callback`, … — see `_SSRF_PARAM`).
- **Limits:** parameter-name driven, so a server-fetch parameter with an unusual
  name is missed entirely. Whether the server actually dereferences the URL is
  not knowable from the corpus.

## `redirect` — open redirect

- **Reads:** `request_param_values` and the response `Location` header.
- **Signatures:** 26 redirect-shaped parameter names (`next`, `return`,
  `returnUrl`, `redirect_uri`, `dest`, `continue`, `goto`, `callback`,
  `success_url`, …), and an offsite-looking value: `//host`, `http(s)://`, or a
  backslash variant used for parser confusion (`https:\`, `/\`, `\/`).
- **Correlation:** if the response is 3xx and the value appears in `Location`,
  the redirect is confirmed reflected. Otherwise it is a candidate to test.
- **Limits:** only the listed parameter names are considered. Path-based or
  header-based redirect logic is out of scope.

## `traversal` — path traversal / LFI

- **Reads:** `request_inputs`; the response body for the file-read tell.
- **Signatures:** strong absolute-path markers (`/etc/passwd`, `/etc/shadow`,
  `/etc/hosts`, `/proc/self/environ`, `boot.ini`, `win.ini`, `c:\windows`), or
  a traversal sequence — two or more `../`, `%2e%2e` forms, `..%2f`, `..%5c`,
  or double-encoded `%252e%252e`.
- **Correlation:** shares `_XXE_FILE_DISCLOSURE` with the `xxe` check; if file
  contents came back in the same response, the note says so.
- **Limits:** a single `../` is not flagged (too common in legitimate relative
  paths). Traversal that resolves to a file with no recognisable signature
  produces a payload finding but no confirmation.

## `crlf` — CRLF / header injection

**Request-side probe only.**

- **Reads:** the four raw request fields, without URL-decoding — the point is
  the encoded sequence itself.
- **Signatures:** `%0d%0a` and its variants, a literal CRLF, overlong-UTF8
  smuggling (`%e5%98%8a`, `%e5%98%8d`), and U+2028/U+2029.
- **Limits:** duplicate headers collapse in this corpus (see *Corpus-wide
  limits*), so an injected `Set-Cookie` in a response cannot be observed here.
  This check tells you the probe was sent, not that it worked — confirm out of
  band.

## `nosqli` — NoSQL injection

- **Reads:** `request_inputs`.
- **Signatures:** strong tier — a JSON operator key (`"$ne":`, `"$gt":`,
  `"$where":`, `"$regex":`, `"$function":`, …) or a `$where` / `sleep(n)` /
  `this.field ==` / `|| '1'=='1` expression. Weaker tier — the bracketed query
  form `param[$ne]=`, which is how operators are smuggled through form encoding.
- **Limits:** MongoDB-shaped only. Other document stores and their operator
  syntaxes are not covered.

## `upload` — dangerous upload filenames

- **Reads:** the request body, and only when it contains the literal string
  `filename` (case-insensitive).
- **Signatures:** three, in order — a double extension (`photo.jpg.php`), a
  server-executable extension (`.php`, `.phtml`, `.phar`, `.jsp`, `.asp(x)`,
  `.cgi`, `.sh`, `.exe`, `.jar`, `.war`, `.py`, `.rb`, …), and a markup
  extension that yields stored XSS (`.svg`, `.html`, `.xml`).
- **Limits:** multipart `Content-Disposition` only. A raw `PUT` upload, a
  base64-in-JSON upload, or any scheme that does not carry a `filename=`
  parameter is missed. A dangerous filename says nothing about where the file
  landed or whether it is servable.

## `headers` — missing response security headers

Host-level: findings blank the path so each host reports once.

- **Reads:** response headers, on rows with a 2xx/3xx status **and** a non-empty
  body.
- **Signatures:** missing HSTS on any TLS response. Then, on `text/html`
  responses only: missing CSP, or a CSP containing `unsafe-inline`,
  `unsafe-eval` or a bare wildcard; missing clickjacking protection (neither
  `X-Frame-Options` nor `frame-ancestors`); missing `X-Content-Type-Options`,
  `Referrer-Policy`, and `Permissions-Policy`.
- **Limits:** non-HTML responses are only checked for HSTS, so a JSON API is
  effectively exempt from the rest. A single host serving many endpoints reports
  each missing header once, which hides *which* endpoints lack it.

## `cors` — CORS misconfiguration

- **Reads:** response headers, plus the request `Origin` header for the
  reflection case. Rows with no `Access-Control-Allow-Origin` are skipped.
- **Signatures:** `ACAO: *` together with `Access-Control-Allow-Credentials:
  true` (invalid per spec, but frequently mishandled); `ACAO: null` (reachable
  from a sandboxed iframe); `ACAO` reflecting the request `Origin` *with*
  credentials, which is the cross-origin data-theft case; and bare `ACAO: *`,
  which only exposes non-credentialed responses.
- **Limits:** origin reflection can only be spotted when the request carried an
  `Origin` header that survived into the corpus. A server that reflects only
  *some* origins looks identical to one that reflects all of them — that needs
  active probing to distinguish.

## `cookies` — cookie flags

Host-level.

- **Reads:** every `Set-Cookie` line in the response headers.
- **Signatures:** missing `HttpOnly` on a session-like cookie (name matching
  `sess`, `sid`, `token`, `auth`, `jwt`, `login`, `remember`, `csrf`); missing
  `Secure` on any cookie set over TLS; missing `SameSite` on any cookie.
- **Limits:** duplicate headers collapse (see *Corpus-wide limits*), so when a
  response sets several cookies not all of them survive. Absence of a cookie
  from these findings means "not observed", not "correctly flagged".

## `jwt` — JWT weaknesses

- **Reads:** `request_inputs` plus `response_text`; deduped per row so a token
  echoed in both is analysed once.
- **Signatures:** decodes the header and payload segments as base64url JSON and
  reports `alg=none` (signature bypass), an empty third segment (empty
  signature), and a payload with no `exp` claim (token never expires). An HMAC
  `alg` (`HS256` etc.) is noted as worth testing for a weak or guessable signing
  key.
- **Dedup:** by decoded content. A token's identity is its header plus its
  claims minus the volatile ones (`iat`, `exp`, `nbf`, `jti`, `auth_time`,
  `nonce`), so a session refreshed across a browsing run is **one** finding
  carrying every path it appeared on, not one per request. Two tokens differing
  in any other claim stay separate findings.
- **Limits:** no signature verification and no key cracking — this reads claims
  only. A token whose segments do not decode as JSON is skipped silently, and is
  not grouped either — it stands on its own path.

## `infoleak` — stack traces and debug output

- **Reads:** `response_text`.
- **Signatures:** 8 — Python tracebacks and the Werkzeug debugger, Java stack
  traces, .NET error pages, PHP errors with a file path, Ruby/Rails backtraces,
  Node stack traces, directory listings (`Index of /`, `Directory listing for`,
  `[To Parent Directory]`), and GraphQL introspection data.
- **Limits:** matches the shape of an error page, not its contents — it will not
  tell you what was leaked. A custom error page that discloses internals in an
  unfamiliar format is missed.

## `fingerprint` — technology and version disclosure

Host-level.

- **Reads:** response headers.
- **Signatures:** banner headers — `Server`, `X-Powered-By`,
  `X-AspNet-Version`, `X-AspNetMvc-Version`, `X-Generator`, `X-Runtime`,
  `X-Drupal-Cache`, `X-Varnish` — with values carrying a version number
  (`\d+\.\d+`) called out separately from bare ones. Plus framework session
  cookie names (`PHPSESSID`, `JSESSIONID`, `ASP.NET_SessionId`,
  `laravel_session`, `connect.sid`, `csrftoken`, …).
- **Limits:** disclosure only. Whether the disclosed version is actually
  vulnerable is not checked, and banners are trivially spoofed.

## `methods` — dangerous HTTP methods observed

Host-level.

- **Reads:** the request method and response status.
- **Signatures:** `PUT`, `DELETE`, `TRACE`, `CONNECT`, `PATCH`, `TRACK`.
  `TRACE`/`TRACK` are noted as a Cross-Site Tracing risk; any of them answered
  with a status below 405 is noted as "method allowed".
- **Limits:** this reports methods that appear *in the corpus*, i.e. methods
  something already sent. It does not enumerate what a server would accept —
  that needs an active `OPTIONS` probe. A status under 405 is not proof the
  operation succeeded.

## `mixedcontent` — HTTP resources on an HTTPS page

Host-level.

- **Reads:** the response body of TLS rows whose `Content-Type` is `text/html`.
- **Signatures:** `src=`, `href=` or `action=` pointing at an `http://` URL.
- **Limits:** first match per response only. Resources loaded by JavaScript at
  runtime are not visible, and `href="http://..."` in ordinary link text is a
  routine false positive.

## `cleartext` — sensitive data over plaintext HTTP

- **Reads:** non-TLS rows only (`is_tls` falsy).
- **Signatures:** a request cookie present, an `Authorization` header present,
  or a credential-shaped parameter in the query or body (`password`, `token`,
  `secret`, `api_key`, `otp`, `pin`, `ssn`, `card`, `cvv`, …). All matching
  reasons are listed in one finding per request.
- **Limits:** depends on `is_tls` being recorded correctly by the importer. A
  plaintext request that redirects straight to HTTPS still counts — the
  credentials were already on the wire, which is the point.

## `csrf` — missing anti-CSRF token (heuristic)

- **Reads:** method, request cookies, and the query/body/headers as one blob.
- **Signatures:** fires when the method is state-changing
  (`POST`/`PUT`/`DELETE`/`PATCH`), the request carried a cookie, and nothing
  CSRF-token-shaped appears anywhere in it (`csrf`, `xsrf`,
  `authenticity_token`, `__RequestVerification`, `_token`, `anti-forgery`,
  `request_token`).
- **Limits:** the weakest heuristic here. `SameSite` cookies, an `Origin` /
  `Referer` check, a custom header requirement, or a token under a name not in
  the list are all invisible — any of them means the endpoint is protected while
  this still reports. Read it as "verify anti-CSRF protection", never as
  "vulnerable to CSRF".
