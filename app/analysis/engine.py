"""Analysis engine — runs the three detection layers as ES queries/aggregations
and writes findings to auradfir-case<N>-findings."""
import statistics
from datetime import datetime

from elasticsearch import helpers

from app import config
from app.analysis import rules
from app.es import get_es


def _finding(case_id, rule, severity, description, source_ip=None, count=0,
             sample=None, first_seen=None, last_seen=None):
    return {
        "case_id": case_id, "rule": rule, "severity": severity,
        "description": description, "source_ip": source_ip, "count": count,
        "sample": (sample or "")[:2048], "first_seen": first_seen,
        "last_seen": last_seen, "created_at": datetime.utcnow().isoformat(),
    }


def _per_ip_agg():
    return {
        "per_ip": {"terms": {"field": "source.ip", "size": 200}, "aggs": {
            "first": {"min": {"field": "@timestamp"}},
            "last": {"max": {"field": "@timestamp"}},
            "sample": {"top_hits": {"size": 1, "_source": ["url.original", "user_agent.original"]}},
        }}
    }


def _ip_findings(resp, make):
    out = []
    for b in resp["aggregations"]["per_ip"]["buckets"]:
        src = b["sample"]["hits"]["hits"][0]["_source"]
        sample = src.get("url", {}).get("original") or src.get("user_agent", {}).get("original", "")
        out.append(make(b["key"], b["doc_count"], sample,
                        b["first"]["value_as_string"], b["last"]["value_as_string"]))
    return out


def run_analysis(case_id: int) -> dict:
    es = get_es()
    index = config.case_log_index(case_id)
    findings = []

    # ---- Layer 1: signatures on url.original ----
    for name, sev, pattern, desc in rules.SIGNATURES:
        resp = es.search(index=index, size=0,
                         query={"regexp": {"url.original": {
                             "value": f".*({pattern}).*", "case_insensitive": True,
                             "flags": "ALL", "max_determinized_states": 200000}}},
                         aggs=_per_ip_agg())
        findings += _ip_findings(resp, lambda ip, n, s, f, l, name=name, sev=sev, desc=desc:
                                 _finding(case_id, name, sev, desc, ip, n, s, f, l))

    # scanner user-agents
    should = [{"wildcard": {"user_agent.original": {"value": f"*{s}*",
                                                    "case_insensitive": True}}}
              for s in rules.SCANNER_UAS]
    resp = es.search(index=index, size=0,
                     query={"bool": {"should": should, "minimum_should_match": 1}},
                     aggs=_per_ip_agg())
    findings += _ip_findings(resp, lambda ip, n, s, f, l:
                             _finding(case_id, "scanner_ua", "medium",
                                      "Known scanner user-agent", ip, n, s, f, l))

    # dangerous HTTP methods (WebDAV / upload / debug verbs)
    resp = es.search(index=index, size=0,
                     query={"terms": {"http.request.method": rules.DANGEROUS_METHODS}},
                     aggs=_per_ip_agg())
    findings += _ip_findings(resp, lambda ip, n, s, f, l:
                             _finding(case_id, "dangerous_method", "medium",
                                      "Uncommon/dangerous HTTP method (PUT/DELETE/WebDAV/DEBUG)",
                                      ip, n, s, f, l))

    # ---- Layer 2: behavioural aggregations ----
    # brute force: worst 5-min window of 401/403 per IP
    resp = es.search(index=index, size=0,
                     query={"terms": {"http.response.status_code": [401, 403]}},
                     aggs={"per_ip": {"terms": {"field": "source.ip", "size": 200}, "aggs": {
                         "win": {"date_histogram": {"field": "@timestamp",
                                                    "fixed_interval": rules.BRUTE_FORCE_WINDOW}},
                         "worst": {"max_bucket": {"buckets_path": "win>_count"}},
                     }}})
    for b in resp["aggregations"]["per_ip"]["buckets"]:
        worst = b["worst"]["value"] or 0
        if worst >= rules.BRUTE_FORCE_THRESHOLD:
            findings.append(_finding(
                case_id, "brute_force", "high",
                f"{int(worst)} auth failures (401/403) in a single "
                f"{rules.BRUTE_FORCE_WINDOW} window", b["key"], b["doc_count"]))

    # enumeration: heavy 404 producers
    resp = es.search(index=index, size=0,
                     query={"term": {"http.response.status_code": 404}},
                     aggs=_per_ip_agg())
    for b in resp["aggregations"]["per_ip"]["buckets"]:
        if b["doc_count"] >= rules.ENUM_404_THRESHOLD:
            findings.append(_finding(
                case_id, "enumeration_404", "medium",
                f"{b['doc_count']} 404 responses — directory/file enumeration",
                b["key"], b["doc_count"],
                first_seen=b["first"]["value_as_string"],
                last_seen=b["last"]["value_as_string"]))

    # exfil candidates: per-IP total response bytes outliers
    resp = es.search(index=index, size=0, aggs={
        "per_ip": {"terms": {"field": "source.ip", "size": 500}, "aggs": {
            "bytes": {"sum": {"field": "http.response.body.bytes"}}}}})
    buckets = resp["aggregations"]["per_ip"]["buckets"]
    totals = [b["bytes"]["value"] for b in buckets]
    if len(totals) >= 5:
        mean, stdev = statistics.mean(totals), statistics.pstdev(totals)
        for b in buckets:
            v = b["bytes"]["value"]
            if v > rules.EXFIL_MIN_BYTES and stdev and v > mean + 3 * stdev:
                findings.append(_finding(
                    case_id, "exfil_bytes", "high",
                    f"{v / 1048576:.1f} MB served to one IP "
                    f"(fleet mean {mean / 1048576:.1f} MB) — possible data exfiltration",
                    b["key"], b["doc_count"]))

    # rare user-agents
    resp = es.search(index=index, size=0, aggs={
        "ua": {"terms": {"field": "user_agent.original", "size": 25,
                         "order": {"_count": "asc"}}}})
    for b in resp["aggregations"]["ua"]["buckets"]:
        if b["doc_count"] <= rules.RARE_UA_MAX_COUNT and b["key"] not in ("", "-"):
            findings.append(_finding(
                case_id, "rare_user_agent", "low",
                "User-agent seen only a handful of times", None,
                b["doc_count"], sample=b["key"]))

    # ---- Layer 3: hourly traffic spikes (z-score) ----
    resp = es.search(index=index, size=0, aggs={
        "hourly": {"date_histogram": {"field": "@timestamp", "fixed_interval": "1h"}}})
    counts = [b["doc_count"] for b in resp["aggregations"]["hourly"]["buckets"]]
    if len(counts) >= 6:
        mean, stdev = statistics.mean(counts), statistics.pstdev(counts)
        if stdev:
            for b in resp["aggregations"]["hourly"]["buckets"]:
                z = (b["doc_count"] - mean) / stdev
                if z > rules.SPIKE_ZSCORE:
                    findings.append(_finding(
                        case_id, "traffic_spike", "medium",
                        f"{b['doc_count']} requests in 1h (z={z:.1f}) at {b['key_as_string']}",
                        None, b["doc_count"], first_seen=b["key_as_string"]))

    # ---- persist findings ----
    findex = config.case_findings_index(case_id)
    if es.indices.exists(index=findex):
        es.delete_by_query(index=findex, query={"match_all": {}}, refresh=True)
    if findings:
        helpers.bulk(es, ({"_index": findex, "_source": f} for f in findings))
        es.indices.refresh(index=findex)

    by_sev = {}
    for f in findings:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
    return {"case_id": case_id, "findings": len(findings), "by_severity": by_sev}
