"""Parameter (field) analysis for web server / proxy / load-balancer access logs.

Given a declared server type and a sample of raw log lines, this module reports:

  * a comparative table of EXPECTED parameters vs. what is actually PRESENT
    (core / recommended / optional), with a sample value and presence ratio, and
  * DISCREPANCIES — missing timezone, inconsistent/unparseable timestamps,
    private/loopback IPs captured as the client (i.e. you are seeing the
    proxy/LB, not the real client), empty core fields, out-of-range statuses,
    low parse rate (wrong server type declared), mixed IP versions, etc.

It is deliberately format-aware but resilient: web servers (Apache, Nginx, IIS)
are first-class; load balancers / proxies (AWS ALB, HAProxy, Squid) are
supported because their access logs are structurally very close — same core
quintet of client IP, timestamp, request line, status and byte count.

All functions here are pure (no ES / no network) and unit-tested offline.
"""
import ipaddress
import re
from collections import defaultdict
from datetime import datetime

MAX_SAMPLE = 5000

SERVER_TYPES = [
    ("apache", "Apache httpd"),
    ("nginx", "Nginx"),
    ("iis", "Microsoft IIS (W3C)"),
    ("aws_alb", "AWS Application/Elastic Load Balancer"),
    ("haproxy", "HAProxy"),
    ("squid", "Squid proxy"),
    ("generic", "Generic / other (CLF-like)"),
]
_SERVER_LABELS = dict(SERVER_TYPES)

# --------------------------------------------------------------------------- #
# Expected-parameter catalogs.  category: core | recommended | optional        #
# --------------------------------------------------------------------------- #
_COMBINED_CATALOG = [
    ("remote_ip", "Client IP (%a/%h)", "core", "Source IP of the request", "source.ip"),
    ("ident", "Identd (%l)", "optional", "RFC 1413 identity — almost always '-'", "—"),
    ("remote_user", "Auth user (%u)", "optional", "HTTP-authenticated username", "user.name"),
    ("timestamp", "Timestamp (%t)", "core", "Request time; should carry a timezone offset", "@timestamp"),
    ("method", "HTTP method", "core", "Method from the request line", "http.request.method"),
    ("uri", "URL / URI", "core", "Requested path (+ query string)", "url.original"),
    ("protocol", "Protocol/version", "recommended", "e.g. HTTP/1.1 — from the request line", "http.version"),
    ("status", "Status code (%>s)", "core", "HTTP response status", "http.response.status_code"),
    ("bytes", "Response bytes (%b/%O)", "core", "Response size in bytes", "http.response.body.bytes"),
    ("referer", "Referer", "recommended", "Referring URL (combined format only)", "http.request.referrer"),
    ("user_agent", "User-Agent", "recommended", "Client user agent (combined format only)", "user_agent.original"),
    ("vhost", "Virtual host (%v)", "optional", "Server name — essential on multi-site hosts", "url.domain"),
    ("x_forwarded_for", "X-Forwarded-For", "recommended", "Real client IP when behind a proxy/LB", "—"),
    ("response_time", "Response time (%D/%T)", "optional", "Request duration — perf & anomaly signal", "—"),
]
_NGINX_EXTRA = [
    ("request_time", "$request_time", "optional", "Total request time (nginx)", "—"),
    ("upstream_addr", "$upstream_addr", "optional", "Backend the request was proxied to", "—"),
    ("upstream_time", "$upstream_response_time", "optional", "Backend response time", "—"),
]
_IIS_CATALOG = [
    ("date", "date", "core", "UTC date (W3C has no timezone field — always UTC)", "@timestamp"),
    ("time", "time", "core", "UTC time of day", "@timestamp"),
    ("c-ip", "c-ip", "core", "Client IP", "source.ip"),
    ("cs-method", "cs-method", "core", "HTTP method", "http.request.method"),
    ("cs-uri-stem", "cs-uri-stem", "core", "Requested path (without query)", "url.original"),
    ("cs-uri-query", "cs-uri-query", "recommended", "Query string — often disabled; needed for injection forensics", "url.query"),
    ("sc-status", "sc-status", "core", "HTTP status code", "http.response.status_code"),
    ("sc-substatus", "sc-substatus", "optional", "IIS sub-status", "—"),
    ("sc-win32-status", "sc-win32-status", "optional", "Win32 status code", "—"),
    ("sc-bytes", "sc-bytes", "recommended", "Bytes sent to client", "http.response.body.bytes"),
    ("cs-bytes", "cs-bytes", "optional", "Bytes received from client", "—"),
    ("time-taken", "time-taken", "recommended", "Request duration (ms)", "—"),
    ("cs(User-Agent)", "cs(User-Agent)", "recommended", "Client user agent", "user_agent.original"),
    ("cs(Referer)", "cs(Referer)", "recommended", "Referring URL", "http.request.referrer"),
    ("cs-username", "cs-username", "optional", "Authenticated user", "user.name"),
    ("cs-host", "cs-host", "optional", "Host header / vhost", "url.domain"),
    ("s-ip", "s-ip", "optional", "Server IP", "—"),
    ("s-port", "s-port", "optional", "Server port", "—"),
]
_ALB_CATALOG = [
    ("type", "type", "optional", "Listener type (http/https/h2/...)", "—"),
    ("timestamp", "time", "core", "ISO-8601 UTC request time (carries 'Z')", "@timestamp"),
    ("elb", "elb", "optional", "Load balancer resource id", "—"),
    ("client_ip", "client:port", "core", "Real client IP:port (the LB records the true client)", "source.ip"),
    ("target_ip", "target:port", "recommended", "Backend the request was routed to", "—"),
    ("request_time", "request_processing_time", "optional", "LB request processing time", "—"),
    ("target_time", "target_processing_time", "recommended", "Backend processing time", "—"),
    ("elb_status", "elb_status_code", "core", "Status returned to the client", "http.response.status_code"),
    ("target_status", "target_status_code", "recommended", "Status from the backend", "—"),
    ("received_bytes", "received_bytes", "optional", "Bytes received from client", "—"),
    ("sent_bytes", "sent_bytes", "recommended", "Bytes sent to client", "http.response.body.bytes"),
    ("request", "request", "core", "Method + URL + protocol (quoted)", "url.original"),
    ("user_agent", "user_agent", "recommended", "Client user agent (quoted)", "user_agent.original"),
    ("ssl_cipher", "ssl_cipher", "optional", "Negotiated TLS cipher", "—"),
    ("ssl_protocol", "ssl_protocol", "optional", "Negotiated TLS version", "—"),
]
_HAPROXY_CATALOG = [
    ("client_ip", "client_ip", "core", "Real client IP (HAProxy records the true client)", "source.ip"),
    ("accept_date", "accept_date", "core", "Request accept time [dd/Mon/yyyy:HH:MM:SS.mmm]", "@timestamp"),
    ("frontend", "frontend_name", "optional", "Frontend that accepted the connection", "—"),
    ("backend", "backend/server", "recommended", "Backend & server the request was sent to", "—"),
    ("timers", "Tq/Tw/Tc/Tr/Tt", "recommended", "Connection/response timers (ms)", "—"),
    ("status", "status_code", "core", "HTTP status returned to client", "http.response.status_code"),
    ("bytes", "bytes_read", "core", "Bytes sent to client", "http.response.body.bytes"),
    ("request", "http_request", "core", "Quoted request line (method+url+proto)", "url.original"),
]
_SQUID_CATALOG = [
    ("epoch", "time", "core", "Unix epoch seconds.millis (UTC)", "@timestamp"),
    ("elapsed", "elapsed", "recommended", "Request duration (ms)", "—"),
    ("client_ip", "remotehost", "core", "Client IP", "source.ip"),
    ("status", "code/status", "core", "Squid result code + HTTP status (e.g. TCP_MISS/200)", "http.response.status_code"),
    ("bytes", "bytes", "core", "Reply size in bytes", "http.response.body.bytes"),
    ("method", "method", "core", "HTTP method", "http.request.method"),
    ("uri", "URL", "core", "Requested URL", "url.original"),
    ("user", "rfc931", "recommended", "Authenticated user ('-' if none)", "user.name"),
    ("hierarchy", "peerstatus/peerhost", "optional", "Cache hierarchy / upstream peer", "—"),
    ("content_type", "type", "optional", "Response content type", "—"),
]


def _catalog(server_type):
    if server_type == "nginx":
        return _COMBINED_CATALOG + _NGINX_EXTRA
    return {
        "apache": _COMBINED_CATALOG, "generic": _COMBINED_CATALOG,
        "iis": _IIS_CATALOG, "aws_alb": _ALB_CATALOG,
        "haproxy": _HAPROXY_CATALOG, "squid": _SQUID_CATALOG,
    }.get(server_type, _COMBINED_CATALOG)


# Which tokenized key holds the client IP / timestamp, and how to read the time.
_CLIENT_KEY = {"apache": "remote_ip", "nginx": "remote_ip", "generic": "remote_ip",
               "aws_alb": "client_ip", "haproxy": "client_ip", "squid": "client_ip"}
_TS_KEY = {"apache": "timestamp", "nginx": "timestamp", "generic": "timestamp",
           "aws_alb": "timestamp", "haproxy": "accept_date", "squid": "epoch"}
_TS_KIND = {"apache": "clf", "nginx": "clf", "generic": "clf",
            "aws_alb": "iso", "haproxy": "clf_ms", "squid": "epoch"}

# --------------------------------------------------------------------------- #
# Tokenizers                                                                    #
# --------------------------------------------------------------------------- #
_CLF = re.compile(
    r'^(?:(?P<vhost>[A-Za-z0-9._\-]+\.[A-Za-z0-9._\-]+(?::\d+)?)\s+)?'
    r'(?P<remote_ip>\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f:]+)\s+'
    r'(?P<ident>\S+)\s+(?P<remote_user>\S+)\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+'
    r'(?P<status>\d{3}|-)\s+(?P<bytes>\d+|-)'
    r'(?P<rest>.*)$'
)


def _tokenize_combined(line):
    m = _CLF.match(line.rstrip("\r\n"))
    if not m:
        return None
    g = m.groupdict()
    d = {"remote_ip": g["remote_ip"], "ident": g["ident"],
         "remote_user": g["remote_user"], "timestamp": g["timestamp"],
         "status": g["status"], "bytes": g["bytes"]}
    if g.get("vhost"):
        d["vhost"] = g["vhost"]
    req = (g["request"] or "").split(" ")
    d["method"] = req[0] if req and req[0] else "-"
    if len(req) > 1:
        d["uri"] = req[1]
    if len(req) > 2:
        d["protocol"] = req[2]
    rest = g["rest"] or ""
    quoted = re.findall(r'"([^"]*)"', rest)
    if len(quoted) >= 1:
        d["referer"] = quoted[0]
    if len(quoted) >= 2:
        d["user_agent"] = quoted[1]
    # X-Forwarded-For: a comma-separated IP list beyond the remote IP.
    xff = re.search(r'(\d{1,3}(?:\.\d{1,3}){3}(?:\s*,\s*\d{1,3}(?:\.\d{1,3}){3})+)', rest)
    if xff:
        d["x_forwarded_for"] = xff.group(1)
    # Response time: a 3+ digit number trailing after the quoted section (µs) or a float.
    tail = rest[rest.rfind('"') + 1:] if '"' in rest else rest
    rt = re.search(r'(?<![\w.])(\d{3,}|\d+\.\d+)(?![\w.])', tail)
    if rt:
        d["response_time"] = rt.group(1)
    return d


def _split_quoted(line):
    """Split on spaces but keep "quoted" and [bracketed] groups intact (ALB/HAProxy)."""
    return re.findall(r'"[^"]*"|\[[^\]]*\]|\S+', line.rstrip("\r\n"))


def _tokenize_alb(line):
    p = _split_quoted(line)
    if len(p) < 13:
        return None
    d = {"type": p[0], "timestamp": p[1], "elb": p[2],
         "client_ip": p[3].rsplit(":", 1)[0], "target_ip": p[4],
         "request_time": p[5], "target_time": p[6],
         "elb_status": p[8], "target_status": p[9],
         "received_bytes": p[10], "sent_bytes": p[11],
         "request": p[12].strip('"')}
    if len(p) > 13:
        d["user_agent"] = p[13].strip('"')
    if len(p) > 15:
        d["ssl_cipher"], d["ssl_protocol"] = p[14], p[15]
    return d


_HAPROXY = re.compile(
    r'(?P<client_ip>\d{1,3}(?:\.\d{1,3}){3}):\d+\s+'
    r'\[(?P<accept_date>\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}\.\d+)\]\s+'
    r'(?P<frontend>\S+)\s+(?P<backend>\S+)\s+(?P<timers>[\d\-/]+)\s+'
    r'(?P<status>\d{3})\s+(?P<bytes>\d+)\s'
)


def _tokenize_haproxy(line):
    m = _HAPROXY.search(line)
    if not m:
        return None
    d = m.groupdict()
    q = re.search(r'"([^"]*)"', line)
    if q:
        d["request"] = q.group(1)
    return d


def _tokenize_squid(line):
    p = line.split()
    if len(p) < 7:
        return None
    d = {"epoch": p[0], "elapsed": p[1], "client_ip": p[2], "status": p[3],
         "bytes": p[4], "method": p[5], "uri": p[6]}
    if len(p) > 7:
        d["user"] = p[7]
    if len(p) > 8:
        d["hierarchy"] = p[8]
    if len(p) > 9:
        d["content_type"] = p[9]
    return d


_TOKENIZERS = {"apache": _tokenize_combined, "nginx": _tokenize_combined,
               "generic": _tokenize_combined, "aws_alb": _tokenize_alb,
               "haproxy": _tokenize_haproxy, "squid": _tokenize_squid}


# --------------------------------------------------------------------------- #
# Helpers                                                                       #
# --------------------------------------------------------------------------- #
def _populated(v):
    return v not in (None, "", "-")


def _is_private(ip):
    try:
        obj = ipaddress.ip_address(ip.strip())
    except ValueError:
        return None
    return not obj.is_global


def _has_offset(raw):
    return bool(re.search(r'[+\-]\d{4}\b', raw or "")) or (raw or "").endswith("Z")


def _parse_ts(kind, raw):
    try:
        if kind in ("clf", "clf_ms"):
            base = raw.split()[0]
            return datetime.strptime(base.split(".")[0], "%d/%b/%Y:%H:%M:%S")
        if kind == "iso":
            return datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if kind == "epoch":
            return datetime.utcfromtimestamp(float(raw))
        if kind == "iis":
            return datetime.strptime(raw, "%Y-%m-%d %H:%M:%S")
    except (ValueError, OverflowError, OSError):
        return None
    return None


def _discrepancies(server_type, parsed, client_ips, raw_ts, ts_kind, xff_present):
    out = []
    n = max(parsed, 1)

    # --- timezone ---
    if ts_kind in ("clf", "clf_ms"):
        missing = sum(1 for t in raw_ts if not _has_offset(t))
        if raw_ts and missing:
            out.append({"check": "missing_timezone",
                        "severity": "high" if missing == len(raw_ts) else "medium",
                        "message": f"{missing}/{len(raw_ts)} sampled timestamps have no timezone "
                                   f"offset (e.g. +0000). Times are ambiguous across zones — "
                                   f"correlation and legal timelines require an explicit offset.",
                        "examples": [t for t in raw_ts if not _has_offset(t)][:3]})
    elif ts_kind == "iso":
        missing = sum(1 for t in raw_ts if not _has_offset(t))
        if missing:
            out.append({"check": "missing_timezone", "severity": "medium",
                        "message": f"{missing} timestamps lack the expected UTC 'Z'/offset.",
                        "examples": raw_ts[:3]})
    elif server_type == "iis":
        out.append({"check": "timezone_is_utc", "severity": "info",
                    "message": "IIS W3C logs have no timezone field — times are UTC by "
                               "specification. Confirm the collector didn't localise them."})

    # --- datetime consistency ---
    parsed_ts = [(_parse_ts(ts_kind, t), t) for t in raw_ts]
    unparsable = [t for dt, t in parsed_ts if dt is None]
    if raw_ts and unparsable:
        out.append({"check": "inconsistent_datetime", "severity": "high",
                    "message": f"{len(unparsable)}/{len(raw_ts)} timestamps did not parse under the "
                               f"expected {server_type} format — mixed formats or merged logs.",
                    "examples": unparsable[:3]})
    ordered = [dt for dt, _ in parsed_ts if dt]
    backward = sum(1 for a, b in zip(ordered, ordered[1:]) if (a - b).total_seconds() > 3600)
    if backward:
        out.append({"check": "non_chronological", "severity": "medium",
                    "message": f"Timestamps step backwards by >1h {backward} time(s) in the sample "
                               f"— logs may be concatenated out of order or tampered with."})

    # --- private / loopback client IPs ---
    priv = [ip for ip in client_ips if _is_private(ip) is True]
    if priv:
        ratio = len(priv) / max(len(client_ips), 1)
        sev = "high" if (ratio > 0.5 and not xff_present) else "medium"
        msg = (f"{len(priv)}/{len(client_ips)} client IPs are private/loopback/reserved "
               f"({ratio:.0%}). ")
        if not xff_present:
            msg += ("No X-Forwarded-For was detected — you are almost certainly logging the "
                    "proxy/load-balancer address, not the real client. Enable XFF / real-IP.")
        else:
            msg += "An X-Forwarded-For field is present — use it as the true client IP."
        out.append({"check": "private_client_ip", "severity": sev, "message": msg,
                    "examples": priv[:5]})

    # --- mixed IP versions ---
    v4 = any(":" not in ip and _is_private(ip) is not None for ip in client_ips)
    v6 = any(":" in ip for ip in client_ips)
    if v4 and v6:
        out.append({"check": "mixed_ip_versions", "severity": "info",
                    "message": "Both IPv4 and IPv6 client addresses are present."})
    return out


def _finalize(server_type, catalog, structural, populated, samples, parsed,
              sampled, extra_discrepancies):
    params, present_core_missing, missing = [], [], []
    for key, label, category, desc, ecs in catalog:
        s = structural.get(key, 0)
        p = structural_present = populated.get(key, 0)
        present = s > 0
        row = {
            "key": key, "label": label, "category": category, "description": desc,
            "ecs": ecs, "present": present,
            "presence_ratio": round(s / max(parsed, 1), 2),
            "populated_ratio": round(p / max(parsed, 1), 2),
            "sample": samples.get(key, ""),
            "note": "",
        }
        if present and p == 0:
            row["note"] = "present but always empty ('-')"
        elif present and 0 < row["presence_ratio"] < 0.9:
            row["note"] = "inconsistent — only in some lines"
        if not present:
            missing.append(key)
            if category == "core":
                present_core_missing.append(label)
        params.append(row)

    discrepancies = list(extra_discrepancies)
    # empty core field
    for r in params:
        if r["category"] == "core" and r["present"] and r["populated_ratio"] == 0:
            discrepancies.append({"check": "empty_core_field", "severity": "high",
                                  "message": f"Core field '{r['label']}' is present but always "
                                             f"empty ('-').", "examples": []})
    # low parse rate → wrong type declared
    parse_rate = parsed / max(sampled, 1)
    if sampled and parse_rate < 0.8:
        discrepancies.insert(0, {
            "check": "low_parse_rate", "severity": "high",
            "message": f"Only {parse_rate:.0%} of sampled lines matched the "
                       f"'{_SERVER_LABELS.get(server_type, server_type)}' format. Wrong server "
                       f"type selected, or the format is heavily customised.", "examples": []})

    core = [r for r in params if r["category"] == "core"]
    reco = [r for r in params if r["category"] == "recommended"]
    sev_rank = {"high": 0, "medium": 1, "info": 2}
    discrepancies.sort(key=lambda d: sev_rank.get(d["severity"], 3))
    return {
        "server_type": server_type,
        "server_label": _SERVER_LABELS.get(server_type, server_type),
        "sampled": sampled, "parsed": parsed, "parse_rate": round(parse_rate, 3),
        "parameters": params,
        "present_count": sum(1 for r in params if r["present"]),
        "missing_count": sum(1 for r in params if not r["present"]),
        "core_present": sum(1 for r in core if r["present"]), "core_total": len(core),
        "recommended_present": sum(1 for r in reco if r["present"]), "recommended_total": len(reco),
        "core_missing": present_core_missing,
        "discrepancies": discrepancies,
    }


def _analyze_tokenized(server_type, lines):
    tok = _TOKENIZERS.get(server_type, _tokenize_combined)
    catalog = _catalog(server_type)
    structural, populated, samples = defaultdict(int), defaultdict(int), {}
    client_ips, raw_ts = [], []
    xff_present = False
    parsed = 0
    ck, tk = _CLIENT_KEY.get(server_type), _TS_KEY.get(server_type)
    for line in lines:
        d = tok(line)
        if not d:
            continue
        parsed += 1
        for k, v in d.items():
            structural[k] += 1
            if _populated(v):
                populated[k] += 1
                samples.setdefault(k, v)
        if ck and _populated(d.get(ck)):
            client_ips.append(d[ck])
        if tk and _populated(d.get(tk)):
            raw_ts.append(d[tk])
        if _populated(d.get("x_forwarded_for")):
            xff_present = True
    disc = _discrepancies(server_type, parsed, client_ips, raw_ts,
                          _TS_KIND.get(server_type, "clf"), xff_present)
    return _finalize(server_type, catalog, structural, populated, samples,
                     parsed, len(lines), disc)


def _analyze_iis(lines):
    catalog = _IIS_CATALOG
    fields = []
    structural, populated, samples = defaultdict(int), defaultdict(int), {}
    client_ips, raw_ts = [], []
    parsed = 0
    for raw in lines:
        line = raw.rstrip("\r\n")
        if line.startswith("#Fields:"):
            fields = line.split(":", 1)[1].split()
            continue
        if line.startswith("#") or not line.strip() or not fields:
            continue
        vals = line.split(" ")
        row = dict(zip(fields, vals))
        parsed += 1
        for k in fields:
            structural[k] += 1
            v = row.get(k, "-")
            if _populated(v):
                populated[k] += 1
                samples.setdefault(k, v)
        if _populated(row.get("c-ip")):
            client_ips.append(row["c-ip"])
        if _populated(row.get("date")) and _populated(row.get("time")):
            raw_ts.append(f"{row['date']} {row['time']}")
    disc = _discrepancies("iis", parsed, client_ips, raw_ts, "iis", False)
    # IIS-specific: query string logging disabled?
    q = next((r for r in [{"k": "cs-uri-query"}] if structural.get("cs-uri-query")), None)
    if q and populated.get("cs-uri-query", 0) == 0 and structural.get("cs-uri-query"):
        disc.append({"check": "query_string_empty", "severity": "medium",
                     "message": "cs-uri-query is logged but always '-'. Query strings are not "
                                "captured — SQLi/XSS/traversal payloads in the query will be "
                                "invisible. Enable query-string logging.", "examples": []})
    return _finalize("iis", catalog, structural, populated, samples,
                     parsed, parsed, disc)


def analyze_parameters(server_type, lines):
    """Analyze an iterable of raw log lines for the declared server type."""
    sample = [ln for ln in lines if ln and ln.strip()][:MAX_SAMPLE]
    if server_type == "iis":
        return _analyze_iis(sample)
    return _analyze_tokenized(server_type, sample)
