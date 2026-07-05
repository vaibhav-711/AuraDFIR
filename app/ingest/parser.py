"""Parsers for Apache/Nginx combined (+vhost) and IIS W3C logs → ECS-style dicts."""
import re
from datetime import datetime

COMBINED = re.compile(
    r'^(?:(?P<vhost>[^ ]+?:\d+|\S+\.\S+) )?'          # optional leading vhost
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+) '
    r'\S+ (?P<user>\S+) '
    r'\[(?P<time>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<url>[^" ]+)(?: (?P<proto>[^"]*))?" '
    r'(?P<status>\d{3}) (?P<bytes>\d+|-)'
    r'(?: "(?P<referrer>[^"]*)" "(?P<ua>[^"]*)")?'
)

APACHE_TS = "%d/%b/%Y:%H:%M:%S %z"


def parse_combined(line: str):
    m = COMBINED.match(line)
    if not m:
        return None
    g = m.groupdict()
    try:
        ts = datetime.strptime(g["time"], APACHE_TS)
    except ValueError:
        return None
    vhost = g.get("vhost") or ""
    domain = vhost.split(":")[0] if vhost else _referrer_host(g.get("referrer") or "")
    return _doc(ts, g["ip"], g["method"], g["url"], int(g["status"]),
                0 if g["bytes"] in (None, "-") else int(g["bytes"]),
                g.get("referrer") or "", g.get("ua") or "", line, domain)


def _referrer_host(referrer: str) -> str:
    """Fallback 'domain hit' from the referrer host when no vhost is logged."""
    m = re.match(r"[a-z]+://([^/:]+)", referrer, re.IGNORECASE)
    return m.group(1) if m else ""


class IISParser:
    """Stateful parser for IIS W3C logs (#Fields: directive defines columns)."""

    def __init__(self):
        self.fields: list[str] = []

    def parse(self, line: str):
        line = line.rstrip("\r\n")
        if line.startswith("#Fields:"):
            self.fields = line.split(":", 1)[1].split()
            return None
        if line.startswith("#") or not line.strip() or not self.fields:
            return None
        vals = dict(zip(self.fields, line.split(" ")))
        try:
            ts = datetime.strptime(f"{vals.get('date','')} {vals.get('time','')}",
                                   "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return None
        url = vals.get("cs-uri-stem", "-")
        query = vals.get("cs-uri-query", "-")
        if query and query != "-":
            url = f"{url}?{query}"
        ua = (vals.get("cs(User-Agent)", "") or "").replace("+", " ")
        referrer = (vals.get("cs(Referer)", "") or "").replace("+", " ")
        domain = vals.get("cs-host", "") or _referrer_host(referrer)
        try:
            status = int(vals.get("sc-status", "0"))
        except ValueError:
            status = 0
        try:
            nbytes = int(vals.get("sc-bytes", "0"))
        except ValueError:
            nbytes = 0
        return _doc(ts, vals.get("c-ip", ""), vals.get("cs-method", ""),
                    url, status, nbytes, referrer, ua, line, domain)


def _doc(ts, ip, method, url, status, nbytes, referrer, ua, original, domain=""):
    return {
        "@timestamp": ts.isoformat(),
        "source": {"ip": ip},
        "http": {
            "request": {"method": method, "referrer": referrer},
            "response": {"status_code": status, "body": {"bytes": nbytes}},
        },
        "url": {"original": url[:4096], "domain": (domain or "")[:255]},
        "user_agent": {"original": ua[:1024]},
        "event": {"original": original[:8192]},
    }


def iter_events(path: str, fmt: str = "auto"):
    """Yield parsed docs from a log file; auto-detects IIS by the #Software/#Fields header."""
    iis = IISParser()
    detected = fmt
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if detected == "auto":
                detected = "iis" if line.startswith("#") else "combined"
            doc = iis.parse(line) if detected == "iis" else parse_combined(line)
            if doc:
                yield doc
