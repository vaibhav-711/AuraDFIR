"""Tests for the parameter/field analysis module (offline, no ES)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.analysis import parameters as pa  # noqa: E402


def _checks(report):
    return {d["check"] for d in report["discrepancies"]}


def _param(report, key):
    return next(r for r in report["parameters"] if r["key"] == key)


def test_apache_combined_clean():
    lines = [
        '203.0.113.7 - - [10/Jul/2026:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 4523 '
        '"https://example.com/" "Mozilla/5.0"',
        '198.51.100.9 - alice [10/Jul/2026:13:56:01 +0000] "POST /login HTTP/1.1" 302 12 '
        '"https://example.com/login" "Mozilla/5.0"',
    ]
    r = pa.analyze_parameters("apache", lines)
    assert r["parse_rate"] == 1.0
    assert _param(r, "remote_ip")["present"] and _param(r, "user_agent")["present"]
    assert _param(r, "referer")["present"] and _param(r, "remote_user")["present"]
    assert r["core_present"] == r["core_total"]
    assert "missing_timezone" not in _checks(r)


def test_apache_missing_timezone():
    lines = ['203.0.113.7 - - [10/Jul/2026:13:55:36] "GET / HTTP/1.1" 200 10 "-" "curl/8.0"']
    r = pa.analyze_parameters("apache", lines)
    assert "missing_timezone" in _checks(r)


def test_common_format_missing_ua_referer():
    # Common Log Format: no referer / user-agent slots at all.
    lines = ['203.0.113.7 - - [10/Jul/2026:13:55:36 +0000] "GET / HTTP/1.1" 200 100']
    r = pa.analyze_parameters("apache", lines)
    assert not _param(r, "user_agent")["present"]
    assert not _param(r, "referer")["present"]
    assert "User-Agent" in " ".join(r["core_missing"]) or _param(r, "user_agent")["category"] == "recommended"


def test_nginx_behind_proxy_private_ip_with_xff():
    lines = [
        '10.0.0.5 - - [10/Jul/2026:13:55:36 +0000] "GET /api HTTP/1.1" 200 512 "-" '
        '"okhttp/4.9" "203.0.113.9, 10.0.0.5"',
        '10.0.0.5 - - [10/Jul/2026:13:55:37 +0000] "GET /api HTTP/1.1" 200 512 "-" '
        '"okhttp/4.9" "198.51.100.4, 10.0.0.5"',
    ]
    r = pa.analyze_parameters("nginx", lines)
    assert _param(r, "x_forwarded_for")["present"]
    assert "private_client_ip" in _checks(r)
    priv = next(d for d in r["discrepancies"] if d["check"] == "private_client_ip")
    assert priv["severity"] == "medium"  # XFF present → downgraded


def test_private_ip_without_xff_is_high():
    lines = ['10.0.0.5 - - [10/Jul/2026:13:55:36 +0000] "GET / HTTP/1.1" 200 5 "-" "UA"']
    r = pa.analyze_parameters("nginx", lines)
    priv = next(d for d in r["discrepancies"] if d["check"] == "private_client_ip")
    assert priv["severity"] == "high"


def test_iis_query_string_disabled():
    lines = [
        "#Software: Microsoft Internet Information Services 10.0",
        "#Fields: date time c-ip cs-method cs-uri-stem cs-uri-query sc-status sc-bytes cs(User-Agent)",
        "2026-07-10 13:55:36 203.0.113.7 GET /index.html - 200 4523 Mozilla/5.0",
        "2026-07-10 13:55:40 203.0.113.7 GET /about - 200 900 Mozilla/5.0",
    ]
    r = pa.analyze_parameters("iis", lines)
    assert _param(r, "cs-uri-query")["present"]
    assert "query_string_empty" in _checks(r)
    assert "timezone_is_utc" in _checks(r)
    assert not _param(r, "time-taken")["present"]  # not in #Fields


def test_aws_alb():
    line = ('https 2026-07-10T13:55:36.123456Z app/my-lb/abc123 203.0.113.7:54321 '
            '10.0.1.20:80 0.001 0.002 0.000 200 200 512 4523 '
            '"GET https://example.com:443/ HTTP/1.1" "Mozilla/5.0" ECDHE-RSA-AES128-GCM-SHA256 '
            'TLSv1.2 arn:aws:tg "Root=1-abc" "example.com" "arn:cert" 0 '
            '2026-07-10T13:55:36.000000Z "forward" "-" "-" "10.0.1.20:80" "200" "-" "-"')
    r = pa.analyze_parameters("aws_alb", [line])
    assert r["parse_rate"] == 1.0
    assert _param(r, "client_ip")["present"] and _param(r, "client_ip")["sample"] == "203.0.113.7"
    assert _param(r, "elb_status")["sample"] == "200"
    assert "missing_timezone" not in _checks(r)


def test_squid():
    line = ("1720619736.123 250 203.0.113.7 TCP_MISS/200 4523 GET http://example.com/ - "
            "HIER_DIRECT/93.184.216.34 text/html")
    r = pa.analyze_parameters("squid", [line])
    assert _param(r, "client_ip")["sample"] == "203.0.113.7"
    assert _param(r, "epoch")["present"] and _param(r, "status")["sample"] == "TCP_MISS/200"


def test_wrong_type_low_parse_rate():
    lines = ["this is not a log line", "neither=is=this", "garbage garbage garbage"]
    r = pa.analyze_parameters("apache", lines)
    assert "low_parse_rate" in _checks(r)


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"PASS {fn.__name__}")
    print(f"\nAll {len(fns)} parameter-analysis tests passed.")
