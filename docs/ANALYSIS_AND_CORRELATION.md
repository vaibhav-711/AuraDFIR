# Analysis & Correlation Methodology

How Aura DFIR turns indexed web server logs into findings and attack timelines, and how to get
the most out of the ES backend.

---

## 1. Indexing design (make correlation possible at write time)

Good correlation starts with the mapping, not the query:

- **ECS-style field names** (`source.ip`, `url.original`, `http.response.status_code`,
  `user_agent.original`) so Kibana, Elastic detection rules and third-party content work
  unchanged.
- `source.ip` mapped as ES `ip` type → enables CIDR queries (`source.ip: "203.0.113.0/24"`),
  which matter because attackers rotate within a subnet or cloud provider range.
- `url.original` and `user_agent.original` as `keyword` (with `text` subfield) → exact
  aggregations *and* regex/signature search.
- **One index per case** (`auradfir-case<N>-logs`) → evidence isolation, painless deletion,
  per-case lifecycle.
- Findings are documents too (`auradfir-case<N>-findings`) → findings themselves can be
  aggregated, timelined, and joined back to raw events.

## 2. Three detection layers

### Layer 1 — Signature rules (known-bad)

Case-insensitive regexes run server-side as ES `regexp` queries against `url.original`,
aggregated per source IP with first-seen / last-seen and a sample hit:

| Rule | Looks for | Severity |
|---|---|---|
| `sqli` | `union select`, `information_schema`, `sleep(`, quote probes | high |
| `xss` | `<script`, `javascript:`, `onerror=` (incl. URL-encoded) | medium |
| `lfi_traversal` | `../`, `etc/passwd`, `%2e%2e%2f` | high |
| `rfi` | `=http(s)://` in parameters | high |
| `webshell` | `c99`, `r57`, `wso.php`, `eval-stdin.php`, POSTs to upload dirs | critical |
| `log4shell` | `${jndi:` | critical |
| `cve_probe` | `/vendor/phpunit`, `/.env`, `/.git/`, `xmlrpc.php`, `wp-login` | medium |
| `scanner_ua` | sqlmap, nikto, nuclei, gobuster, wpscan, zgrab, masscan UAs | medium |

The table above is a summary — the shipping ruleset in `app/analysis/rules.py` has **25
signature categories**, adding NoSQL / OS-command / template / LDAP / XPath injection, SSRF,
XXE, insecure deserialization, Spring4Shell, Struts2 OGNL, CRLF/response-splitting, open
redirect, access-control bypass, sensitive-file & backup access, null-byte/encoding evasion and
IIS/ASP.NET probes, plus a behavioural *dangerous HTTP method* (PUT/DELETE/WebDAV/DEBUG) check.

Signatures are deliberately ES-safe regex (no `\d`, no lookarounds) so the *same* pattern list
drives both the ES queries and the Python event-tagger used by the timeline builder — one
source of truth in `app/analysis/rules.py`. Because Lucene `regexp` (flags=ALL) treats
`< > # & @ ~ " { }` as operators, any literal occurrence must be backslash-escaped; the
**dialect contract** is enforced automatically by `tests/test_rules.py` (which also checks every
pattern compiles and fires on a representative payload while staying quiet on clean URLs). The
engine raises `max_determinized_states` to 200 000 so the large alternations never trip Lucene's
automaton limit.

### Layer 2 — Behavioural aggregations (known-bad *behaviour*, unknown payloads)

Pure ES aggregations — no documents leave the cluster:

- **Brute force**: `status ∈ {401,403}` → `terms(source.ip)` → 5-minute `date_histogram` →
  flag any IP whose worst 5-min window ≥ 20 failures.
- **Enumeration / forced browsing**: per-IP 404 count ≥ 50, or 404-ratio > 0.7 with ≥ 30
  requests. Catches dirbusting even with a spoofed browser UA.
- **Exfil candidates**: `sum(http.response.body.bytes)` per IP; flag outliers
  (> mean + 3σ *and* > 10 MB). A single IP pulling 100× the median bytes is your
  data-theft lead.
- **Rare user-agents**: least-common UA terms (doc_count ≤ 5). Custom tooling, raw
  `python-requests`, or typo'd spoofed UAs surface here.

### Layer 3 — Statistical anomaly detection

- **Traffic spikes**: 1-hour `date_histogram` over the whole case → z-score per bucket in
  Python → z > 3 flagged. Spikes anchor the timeline ("what happened at 02:00?").
- Extensible: request-interval regularity per IP (low variance ⇒ beaconing/cron'd webshell),
  Shannon entropy of URL parameters (encrypted/encoded payloads), hour-of-day profiling
  (legit users have diurnal patterns; webshells don't).

### Descriptive statistics module (`app/analysis/statistics.py`)

Separate from the detection layers, the statistics module answers *"what does this traffic
look like?"* — the questions every triage starts with:

- **Top-N rankings** (analyst-selectable N = 10/20/50/100/200) of source IPs, user-agents,
  URLs/endpoints, domains (vhost, falling back to referrer host), referrers, HTTP methods and
  status codes — each as a horizontal CSS bar with count and % share.
- **Top IPs by bytes transferred** — the exfil lens, ranked independently of request count.
- **Cardinalities & totals**: unique IPs / UAs / URLs / domains, total events, total bytes,
  and the observed time window.
- **Traffic over time**: an `auto_date_histogram` rendered as an **inline SVG** line/area chart
  with the peak bucket annotated — no CDN or JS charting library, so it renders offline and
  inside the packaged `.exe`.
- **Status-class distribution** (2xx/3xx/4xx/5xx) — a fast read on scanning (4xx-heavy) vs.
  successful exploitation (a burst of 2xx to previously-404 paths).

All of it is available at `/cases/<id>/statistics` (interactive) and
`/cases/<id>/statistics.json?top_n=<N>` (for scripting/reporting).

## 3. Timeline correlation method

The correlation script (`app/correlation/timeline.py`) does what an analyst does manually:

1. **Pull events** for the case (optionally filtered to one IP / time range), sorted by
   `@timestamp` using `search_after` paging — works on multi-million-event cases.
2. **Tag** every event with matching signature rules (Python regex, same rule list).
3. **Sessionize**: group by `(source.ip, user_agent)`, split when the gap between consecutive
   requests exceeds 30 minutes. A "session" ≈ one attacker sitting, one tool run.
4. **Classify each session into phases** from its tags and shape:
   - `recon` — high 404 ratio, scanner UA, many distinct paths, no signature hits
   - `exploitation` — SQLi/LFI/RFI/log4shell tags present
   - `post-exploitation` — webshell tag, POSTs to previously-404'd paths, new files accessed
   - `exfiltration` — large cumulative response bytes late in the chain
5. **Emit** an ordered chain: `sessions[] → {ip, ua, start, end, phase, tags, event_count,
   bytes_out, sample_events[]}` as JSON/CSV.

The killer pivot: when session A (scanner UA, 4 000 requests) and session B (browser UA,
12 surgical requests to exactly the paths A found) come from the same IP or /24 — that phase
transition **is** the compromise narrative for your report.

### Correlation pivots to use in Kibana / the API

- **IP → everything**: all cases, all sessions, all findings for one IP (plus its /24).
- **UA string** — attackers reuse the same weird UA across IPs from a proxy pool.
- **URL path** — who else touched `/uploads/x.php` before/after the webshell finding?
- **Time-window join** — everything from anyone ±5 min around a critical finding.
- **Referrer** — webshell panels often send tell-tale or empty referrers on POSTs.

## 4. Enrichment & intelligence correlation

### AbuseIPDB (implemented)

Every unique `source.ip` in a case is bulk-checked (see `app/intel/abuseipdb.py`):
multi-key pool → picks the key with most remaining daily quota → 429 marks the key exhausted
for the day and rotates → results cached locally 24 h. Score ≥ 80 = confirmed-bad, 25–79 =
suspicious, plus country / ISP / usage-type / Tor flag for the report.

Use it to *prioritise*, not to convict: a 0-score IP can still be the attacker (fresh VPS),
and a 100-score IP hitting `/favicon.ico` once is internet background noise.

### Recommended next integrations (all API-based, no scraping needed)

| Source | What it answers | Free tier |
|---|---|---|
| **GreyNoise** | "Is this IP scanning *everyone* or just me?" — the single best triage signal | community API |
| **AlienVault OTX** | Is this IP/URL in published threat pulses? Which campaign? | yes |
| **CISA KEV + ExploitDB/nuclei-templates** | Map probed paths to actual CVEs → "they tried CVE-2017-9841" | yes (offline lists) |
| **Tor exit list / cloud IP ranges** | Anonymised vs datacenter vs residential attacker | yes (offline) |
| **URLhaus / ThreatFox (abuse.ch)** | RFI payload URLs and C2s seen in your logs | yes |
| **Shodan/Censys** | What is the attacking host? (open ports ⇒ compromised box vs VPS) | limited |
| **MaxMind GeoLite2** | Geo/ASN at ingest time (offline, unlimited) | yes |

### On "web scraping for similar incidents"

Scraping Google/forums for incident write-ups is fragile and often against ToS. Better ways to
answer *"has anyone else seen this attack?"*:

1. **GreyNoise** literally answers it, per IP, via API.
2. **ISC SANS diaries and abuse.ch feeds** have RSS/APIs — pull, don't scrape.
3. **GitHub code search API** on a distinctive URI/payload string finds nuclei templates and
   PoCs → identifies the exact tool/CVE being thrown at you.
4. An optional **LLM enrichment step** (paste the finding summary, ask for CVE candidates and
   references) gets you the same result with citations and no scraping infrastructure.

## 5. Example ES queries (paste into Kibana Dev Tools)

Worst 5-minute brute-force window per IP:

```json
GET auradfir-case1-logs/_search
{ "size": 0,
  "query": { "terms": { "http.response.status_code": [401, 403] } },
  "aggs": { "per_ip": { "terms": { "field": "source.ip", "size": 50 },
    "aggs": { "win": { "date_histogram": { "field": "@timestamp", "fixed_interval": "5m" } },
              "worst": { "max_bucket": { "buckets_path": "win>_count" } } } } } }
```

Who touched a path before it started returning 200:

```json
GET auradfir-case1-logs/_search
{ "query": { "term": { "url.original": "/uploads/x.php" } },
  "sort": [{ "@timestamp": "asc" }],
  "_source": ["@timestamp","source.ip","http.request.method","http.response.status_code"] }
```
