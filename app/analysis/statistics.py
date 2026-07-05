"""Descriptive statistics for a case's indexed logs.

Pulls top-N rankings (IPs, user-agents, URLs, domains, referrers, methods,
status codes) plus totals, cardinalities and a traffic-over-time series from
Elasticsearch, and renders an offline inline-SVG line chart (no CDN / JS libs,
so it works air-gapped and inside the packaged .exe).

The formatting helpers (`_with_pct`, `classify_status`, `build_timechart`) are
pure functions and unit-tested without a live cluster.
"""
from html import escape

from app import config
from app.es import get_es

TOP_N_OPTIONS = [10, 20, 50, 100, 200]

STATUS_CLASSES = [
    ("2xx Success", "success", 200, 299),
    ("3xx Redirect", "redirect", 300, 399),
    ("4xx Client error", "client_error", 400, 499),
    ("5xx Server error", "server_error", 500, 599),
]


def clamp_top_n(n: int) -> int:
    try:
        n = int(n)
    except (TypeError, ValueError):
        return 20
    return max(1, min(n, 1000))


def _with_pct(items: list[dict]) -> list[dict]:
    """Add `pct` (bar width vs. the largest bar) and `share` (% of total)."""
    total = sum(i["count"] for i in items) or 1
    mx = max((i["count"] for i in items), default=1) or 1
    for i in items:
        i["pct"] = round(100 * i["count"] / mx, 1)
        i["share"] = round(100 * i["count"] / total, 1)
    return items


def classify_status(status_buckets: list[dict]) -> list[dict]:
    """Fold individual status codes into 2xx/3xx/4xx/5xx classes."""
    out = []
    total = sum(b["count"] for b in status_buckets) or 1
    for label, cls, lo, hi in STATUS_CLASSES:
        count = sum(b["count"] for b in status_buckets
                    if isinstance(b["label"], int) and lo <= b["label"] <= hi)
        out.append({"label": label, "cls": cls, "count": count,
                    "share": round(100 * count / total, 1)})
    return out


def build_timechart(series: list[dict], width: int = 780, height: int = 220) -> dict:
    """Return an inline-SVG line/area chart for a [{t, count}] time series."""
    if not series:
        return {"svg": "", "peak": None, "buckets": 0}
    n = len(series)
    maxc = max(s["count"] for s in series) or 1
    pad_l, pad_r, pad_t, pad_b = 46, 12, 12, 30
    plot_w = width - pad_l - pad_r
    plot_h = height - pad_t - pad_b

    pts = []
    for i, s in enumerate(series):
        x = pad_l + (i / (n - 1) * plot_w if n > 1 else plot_w / 2)
        y = pad_t + plot_h - (s["count"] / maxc) * plot_h
        pts.append((x, y))
    poly = " ".join(f"{x:.1f},{y:.1f}" for x, y in pts)
    baseline = pad_t + plot_h
    area = f"{pad_l:.1f},{baseline:.1f} {poly} {pad_l + plot_w:.1f},{baseline:.1f}"

    peak = max(series, key=lambda s: s["count"])
    grid = "".join(
        f'<line x1="{pad_l}" y1="{pad_t + plot_h * f:.1f}" x2="{pad_l + plot_w}" '
        f'y2="{pad_t + plot_h * f:.1f}" stroke="var(--border)" stroke-width="1"/>'
        for f in (0, 0.5, 1.0)
    )
    dots = "".join(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="2" fill="var(--accent)"/>'
                   for x, y in pts) if n <= 60 else ""
    x_labels = (
        f'<text x="{pad_l}" y="{height - 8}" fill="var(--muted)" font-size="11">'
        f'{escape(series[0]["t"])}</text>'
        f'<text x="{pad_l + plot_w}" y="{height - 8}" fill="var(--muted)" '
        f'font-size="11" text-anchor="end">{escape(series[-1]["t"])}</text>'
    )
    y_labels = (
        f'<text x="{pad_l - 6}" y="{pad_t + 4}" fill="var(--muted)" font-size="11" '
        f'text-anchor="end">{maxc}</text>'
        f'<text x="{pad_l - 6}" y="{baseline:.1f}" fill="var(--muted)" font-size="11" '
        f'text-anchor="end">0</text>'
    )
    svg = (
        f'<svg viewBox="0 0 {width} {height}" width="100%" '
        f'preserveAspectRatio="xMidYMid meet" xmlns="http://www.w3.org/2000/svg">'
        f'{grid}'
        f'<polygon points="{area}" fill="var(--accent)" opacity="0.12"/>'
        f'<polyline points="{poly}" fill="none" stroke="var(--accent)" '
        f'stroke-width="2" stroke-linejoin="round"/>'
        f'{dots}{x_labels}{y_labels}</svg>'
    )
    return {"svg": svg, "peak": {"t": peak["t"], "count": peak["count"]}, "buckets": n}


# --------------------------------------------------------------------------- ES
def _terms(es, index, field, size, drop=("", "-")) -> list[dict]:
    resp = es.search(index=index, size=0,
                     aggs={"a": {"terms": {"field": field, "size": size}}})
    return [{"label": b["key"], "count": b["doc_count"]}
            for b in resp["aggregations"]["a"]["buckets"] if b["key"] not in drop]


def compute_statistics(case_id: int, top_n: int = 20) -> dict | None:
    es = get_es()
    index = config.case_log_index(case_id)
    if not es.indices.exists(index=index):
        return None
    top_n = clamp_top_n(top_n)

    total = es.count(index=index)["count"]
    summary = es.search(index=index, size=0, aggs={
        "ips": {"cardinality": {"field": "source.ip"}},
        "uas": {"cardinality": {"field": "user_agent.original"}},
        "urls": {"cardinality": {"field": "url.original"}},
        "domains": {"cardinality": {"field": "url.domain"}},
        "first": {"min": {"field": "@timestamp"}},
        "last": {"max": {"field": "@timestamp"}},
        "bytes": {"sum": {"field": "http.response.body.bytes"}},
    })["aggregations"]

    # top IPs by transferred bytes (exfil lens)
    resp = es.search(index=index, size=0, aggs={
        "per_ip": {"terms": {"field": "source.ip", "size": top_n,
                             "order": {"b": "desc"}},
                   "aggs": {"b": {"sum": {"field": "http.response.body.bytes"}}}}})
    top_ip_bytes = [{"label": b["key"], "count": int(b["b"]["value"])}
                    for b in resp["aggregations"]["per_ip"]["buckets"]]

    # traffic over time (auto-bucketed)
    resp = es.search(index=index, size=0, aggs={
        "t": {"auto_date_histogram": {"field": "@timestamp", "buckets": 60}}})
    series = [{"t": b["key_as_string"][:16].replace("T", " "), "count": b["doc_count"]}
              for b in resp["aggregations"]["t"]["buckets"]]

    status_terms = _terms(es, index, "http.response.status_code", 50, drop=())

    return {
        "case_id": case_id,
        "top_n": top_n,
        "summary": {
            "total_events": total,
            "unique_ips": summary["ips"]["value"],
            "unique_user_agents": summary["uas"]["value"],
            "unique_urls": summary["urls"]["value"],
            "unique_domains": summary["domains"]["value"],
            "total_bytes": int(summary["bytes"]["value"] or 0),
            "first_seen": summary["first"].get("value_as_string"),
            "last_seen": summary["last"].get("value_as_string"),
        },
        "top_ips": _with_pct(_terms(es, index, "source.ip", top_n)),
        "top_user_agents": _with_pct(_terms(es, index, "user_agent.original", top_n)),
        "top_urls": _with_pct(_terms(es, index, "url.original", top_n)),
        "top_domains": _with_pct(_terms(es, index, "url.domain", top_n)),
        "top_referrers": _with_pct(_terms(es, index, "http.request.referrer", top_n)),
        "top_methods": _with_pct(_terms(es, index, "http.request.method", top_n)),
        "top_status": _with_pct(sorted(status_terms, key=lambda s: s["count"],
                                       reverse=True)[:top_n]),
        "status_classes": classify_status(status_terms),
        "top_ip_bytes": _with_pct(top_ip_bytes),
        "timechart": build_timechart(series),
        "timeseries": series,   # raw [{t, count}] for Excel/Word exports
    }
