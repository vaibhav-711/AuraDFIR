"""Timeline correlation — sessionize events and classify attack phases."""
from datetime import datetime, timedelta
from html import escape

from app import config
from app.analysis import rules
from app.es import get_es

SESSION_GAP = timedelta(minutes=30)
PAGE = 5000

PHASE_ORDER = ["benign", "recon", "exploitation", "post-exploitation", "exfiltration"]

PHASE_COLORS = {
    "recon": "#4fc3f7", "exploitation": "#ffa726",
    "post-exploitation": "#ef5350", "exfiltration": "#b71c1c", "benign": "#607d8b",
}


def _fetch_events(index: str, ip: str | None, start: str | None, end: str | None):
    es = get_es()
    must = []
    if ip:
        must.append({"term": {"source.ip": ip}})
    if start or end:
        rng = {}
        if start:
            rng["gte"] = start
        if end:
            rng["lte"] = end
        must.append({"range": {"@timestamp": rng}})
    query = {"bool": {"must": must}} if must else {"match_all": {}}

    search_after = None
    while True:
        body = {"size": PAGE, "query": query,
                "sort": [{"@timestamp": "asc"}, {"_doc": "asc"}]}
        if search_after:
            body["search_after"] = search_after
        resp = es.search(index=index, **body)
        hits = resp["hits"]["hits"]
        if not hits:
            return
        for h in hits:
            yield h["_source"]
        search_after = hits[-1]["sort"]


def _classify(session: dict) -> str:
    tags = session["tags"]
    if tags & rules.POSTEXPLOIT_TAGS:
        return "post-exploitation"
    if session["bytes_out"] >= rules.EXFIL_MIN_BYTES:
        return "exfiltration"
    if tags & rules.EXPLOIT_TAGS:
        return "exploitation"
    total = session["event_count"]
    if session["scanner_ua"] or (total >= 20 and session["n404"] / total > 0.5) \
            or (tags & rules.RECON_TAGS):
        return "recon"
    return "benign"


def build_timeline(case_id: int, ip: str | None = None,
                   start: str | None = None, end: str | None = None,
                   include_benign: bool = False) -> dict:
    index = config.case_log_index(case_id)
    sessions = []
    open_sessions: dict[tuple, dict] = {}   # (ip, ua) -> session

    def close(key):
        s = open_sessions.pop(key)
        s["tags"] = sorted(s["tags"])
        s["phase"] = s.pop("_phase")
        s["sample_events"] = s["sample_events"][:10]
        sessions.append(s)

    for ev in _fetch_events(index, ip, start, end):
        src_ip = ev.get("source", {}).get("ip", "")
        ua = ev.get("user_agent", {}).get("original", "")
        ts = datetime.fromisoformat(ev["@timestamp"])
        url = ev.get("url", {}).get("original", "")
        status = ev.get("http", {}).get("response", {}).get("status_code", 0)
        nbytes = ev.get("http", {}).get("response", {}).get("body", {}).get("bytes", 0)
        key = (src_ip, ua)

        s = open_sessions.get(key)
        if s and ts - s["_last_ts"] > SESSION_GAP:
            close(key)
            s = None
        if not s:
            s = {"ip": src_ip, "ua": ua[:200], "start": ev["@timestamp"], "end": None,
                 "event_count": 0, "n404": 0, "bytes_out": 0, "tags": set(),
                 "scanner_ua": rules.is_scanner_ua(ua), "sample_events": [],
                 "_last_ts": ts, "_phase": "benign"}
            open_sessions[key] = s

        tags = rules.tag_url(url)
        s["tags"].update(tags)
        s["event_count"] += 1
        s["n404"] += 1 if status == 404 else 0
        s["bytes_out"] += nbytes or 0
        s["end"] = ev["@timestamp"]
        s["_last_ts"] = ts
        if tags or len(s["sample_events"]) < 3:
            s["sample_events"].append({
                "ts": ev["@timestamp"], "method": ev.get("http", {}).get("request", {}).get("method", ""),
                "url": url[:300], "status": status, "tags": tags})
        s["_phase"] = _classify(s)

    for key in list(open_sessions):
        close(key)

    sessions.sort(key=lambda s: s["start"])
    if not include_benign:
        interesting = [s for s in sessions if s["phase"] != "benign"]
    else:
        interesting = sessions

    # attack chain: highest phase reached per IP, in order of first appearance
    chain = {}
    for s in interesting:
        cur = chain.setdefault(s["ip"], {"ip": s["ip"], "first_seen": s["start"],
                                         "phases": [], "sessions": 0})
        cur["sessions"] += 1
        if s["phase"] not in cur["phases"]:
            cur["phases"].append(s["phase"])

    return {
        "case_id": case_id,
        "filter": {"ip": ip, "start": start, "end": end},
        "total_sessions": len(sessions),
        "suspicious_sessions": len([s for s in sessions if s["phase"] != "benign"]),
        "sessions": interesting,
        "attack_chains": sorted(chain.values(),
                                key=lambda c: max(PHASE_ORDER.index(p) for p in c["phases"]),
                                reverse=True),
    }


def _parse_iso(s):
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00")).replace(tzinfo=None)
    except (ValueError, TypeError):
        return None


def render_timeline_svg(tl: dict, width: int = 940) -> str:
    """Render the sessionized attack timeline as an offline swimlane SVG:
    one lane per attacker IP, one bar per session, coloured by attack phase."""
    sessions = [s for s in (tl or {}).get("sessions", [])
                if _parse_iso(s.get("start")) and _parse_iso(s.get("end"))]
    if not sessions:
        return ""

    # Lane order: most-severe attack chains first, then first-appearance.
    chain_order = [c["ip"] for c in tl.get("attack_chains", [])]
    ips = []
    for s in sessions:
        if s["ip"] not in ips:
            ips.append(s["ip"])
    ips.sort(key=lambda ip: chain_order.index(ip) if ip in chain_order else len(chain_order))
    row_of = {ip: i for i, ip in enumerate(ips)}

    tmin = min(_parse_iso(s["start"]) for s in sessions)
    tmax = max(_parse_iso(s["end"]) for s in sessions)
    span = (tmax - tmin).total_seconds() or 1.0

    left, right, top, rowh, barh = 150, 20, 58, 30, 16
    plot_w = width - left - right
    height = top + len(ips) * rowh + 34

    def xp(dt):
        return left + (dt - tmin).total_seconds() / span * plot_w

    parts = []

    # legend
    lx = left
    present_phases = [p for p in PHASE_ORDER if any(s["phase"] == p for s in sessions)]
    for phase in present_phases:
        parts.append(f'<rect x="{lx}" y="16" width="12" height="12" rx="2" '
                     f'fill="{PHASE_COLORS[phase]}"/>')
        parts.append(f'<text x="{lx + 17}" y="26" fill="#9fb0bf" font-size="12">{phase}</text>')
        lx += 34 + 7 * len(phase)

    # vertical grid + time axis
    bottom = top + len(ips) * rowh
    for f in (0, 0.25, 0.5, 0.75, 1.0):
        gx = left + f * plot_w
        parts.append(f'<line x1="{gx:.1f}" y1="{top}" x2="{gx:.1f}" y2="{bottom}" '
                     f'stroke="#2c3844" stroke-width="1"/>')
        tick = tmin + timedelta(seconds=span * f)
        label = tick.strftime("%m-%d %H:%M") if span > 86400 else tick.strftime("%H:%M:%S")
        anchor = "start" if f == 0 else ("end" if f == 1.0 else "middle")
        parts.append(f'<text x="{gx:.1f}" y="{bottom + 16}" fill="#9fb0bf" '
                     f'font-size="11" text-anchor="{anchor}">{label}</text>')

    # IP lane labels + baselines
    for ip in ips:
        y = top + row_of[ip] * rowh
        parts.append(f'<text x="{left - 8}" y="{y + barh - 2}" fill="#d7dde3" font-size="12" '
                     f'text-anchor="end" font-family="Consolas,monospace">{escape(ip)}</text>')
        parts.append(f'<line x1="{left}" y1="{y + barh + 4:.1f}" x2="{left + plot_w}" '
                     f'y2="{y + barh + 4:.1f}" stroke="#222c36" stroke-width="1"/>')

    # session bars
    for s in sessions:
        st, en = _parse_iso(s["start"]), _parse_iso(s["end"])
        x = xp(st)
        w = max(xp(en) - x, 4)
        y = top + row_of[s["ip"]] * rowh
        color = PHASE_COLORS.get(s["phase"], "#607d8b")
        tags = ", ".join(s.get("tags", [])) or "-"
        tip = (f'{s["ip"]}  [{s["phase"]}]  {s["start"]} -> {s["end"]}  '
               f'{s.get("event_count", 0)} events  tags: {tags}')
        parts.append(f'<rect x="{x:.1f}" y="{y + 4}" width="{w:.1f}" height="{barh}" rx="3" '
                     f'fill="{color}" opacity="0.92"><title>{escape(tip)}</title></rect>')

    return (f'<svg viewBox="0 0 {width} {height}" width="100%" '
            f'preserveAspectRatio="xMidYMid meet" xmlns="http://www.w3.org/2000/svg" '
            f'font-family="Segoe UI, system-ui, sans-serif">{"".join(parts)}</svg>')
