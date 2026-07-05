# Parameter (field) analysis

*"Is this log even usable as evidence, and what is it missing?"* — the question to ask **before**
you start hunting. Aura DFIR's parameter-analysis module answers it for a declared server type.

Open **Parameters** in the top nav (or the 🔧 Parameters button on a case). Pick the server
type, then paste lines, upload a file, or sample a case's indexed events. You get:

1. a **comparative table** of every expected parameter for that server type — marked
   *present* / *missing*, tagged **core / recommended / optional**, with a sample value, the
   populated-ratio, and the ECS field it maps to on ingest; and
2. a ranked list of **discrepancies**.

## Supported log sources

| Type | Family | Notes |
|---|---|---|
| **Apache httpd** | web server | CLF & combined; vhost, XFF, response-time detected |
| **Nginx** | web server | combined + `$request_time` / `$upstream_*` (optional) |
| **Microsoft IIS** | web server | W3C — presence read authoritatively from the `#Fields:` header |
| **AWS ALB/ELB** | load balancer | positional, quote-aware; records the **real** client IP |
| **HAProxy** | load balancer | HTTP log format (accept-date, client, timers, request) |
| **Squid** | proxy | native format (`epoch elapsed client code/status bytes method url …`) |
| **Generic** | fallback | any CLF-like line |

Load balancers and proxies are first-class here precisely because their access logs share the
same **core quintet** every web log has — client IP, timestamp, request line, status, byte
count — plus their own extras (backend/target, timers). See "Can it handle LB/proxy logs?" below.

## Discrepancy checks

| Check | Severity | What it means |
|---|---|---|
| `missing_timezone` | high/med | Apache/Nginx timestamps without a `+HHMM` offset — times are ambiguous across zones; a problem for correlation and court. |
| `inconsistent_datetime` | high | Some timestamps don't parse under the declared format — mixed formats or **merged logs**. |
| `non_chronological` | medium | Time steps backwards >1 h — concatenated-out-of-order or tampered logs. |
| `private_client_ip` | high/med | Client IPs are RFC1918/loopback. You're logging the **proxy/LB**, not the real client. High when no XFF is present. |
| `query_string_empty` (IIS) | medium | `cs-uri-query` is logged but always `-`; injection payloads in the query are invisible. |
| `empty_core_field` | high | A core field (status, bytes, …) is present but always `-`. |
| `low_parse_rate` | high | <80 % of lines matched — wrong server type declared, or heavily customised format. |
| `mixed_ip_versions` / `timezone_is_utc` | info | Context, not problems. |

## Why this matters for an investigation

- A **private client IP with no X-Forwarded-For** is the single most common reason a web-log
  investigation dead-ends: every request looks like it came from `10.0.0.5` (your load
  balancer). The module tells you immediately, so you go get the XFF/real-IP logging fixed or
  find the upstream logs — before you waste hours.
- **Missing timezone** turns a clean timeline into an argument. Catch it on day one.
- **Missing User-Agent/Referer** (common vs combined format) tells you how much behavioural
  correlation is even possible with this dataset.

For developers, it's a **pre-flight check**: point it at your access log and confirm you're
capturing everything you'd want if you ever had to investigate an incident.

## Can it handle load balancer / proxy logs?

**Yes.** Web-server, load-balancer and proxy access logs are structurally the same event —
"who requested what, when, and what did we answer" — so the whole pipeline works on them:

- **Parameter analysis**: native ALB / HAProxy / Squid support (table above).
- **Ingest / analysis / timeline / statistics / AbuseIPDB**: the ingest parsers target the
  Apache/Nginx **combined** and IIS **W3C** formats. ALB, HAProxy and most reverse-proxy logs
  are combined-compatible or can be emitted in combined format, so they flow straight through.
  A dedicated ALB/HAProxy ingest parser is a small, well-scoped addition on the roadmap.

The one genuinely important difference is **whose IP is the client**: on a load balancer the
logged client IP *is* the real client (good), whereas a web server *behind* an LB logs the LB's
IP unless X-Forwarded-For is enabled — which is exactly what the `private_client_ip` /
`x_forwarded_for` checks surface.
