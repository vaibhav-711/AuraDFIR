"""AbuseIPDB v2 integration with multi-key pooling, quota tracking and local caching.

Design:
- Multiple API keys live in the DB (admin dashboard manages them).
- Every call picks the active key with the most remaining daily quota.
- Per-key/per-day usage is persisted in `abuseipdb_key_usage`; a 429 marks the key
  exhausted for the day and the checker rotates to the next key transparently.
- Results are cached in `ip_reputation` for ABUSEIPDB_CACHE_TTL_HOURS so repeated
  bulk checks (or overlapping cases) never re-spend quota on the same IP.
"""
import ipaddress
import json
from datetime import date, datetime, timedelta

import httpx
from sqlalchemy.orm import Session

from app import config
from app.models import AbuseIPDBKey, IPReputation, KeyUsage

API_URL = "https://api.abuseipdb.com/api/v2/check"


class NoKeyAvailable(Exception):
    """All keys are missing, disabled, or out of quota for today."""


def _usage_row(db: Session, key_id: int, day: date) -> KeyUsage:
    row = db.query(KeyUsage).filter(KeyUsage.key_id == key_id, KeyUsage.usage_date == day).first()
    if not row:
        row = KeyUsage(key_id=key_id, usage_date=day, count=0)
        db.add(row)
        db.commit()
    return row


def _pick_key(db: Session):
    """Return (key, usage) with the most remaining quota today, or raise NoKeyAvailable."""
    today = date.today()
    best, best_remaining = None, 0
    for key in db.query(AbuseIPDBKey).filter(AbuseIPDBKey.active == True).all():  # noqa: E712
        usage = _usage_row(db, key.id, today)
        if usage.exhausted:
            continue
        remaining = key.daily_limit - usage.count
        if remaining > best_remaining:
            best, best_remaining = (key, usage), remaining
    if not best:
        raise NoKeyAvailable("No AbuseIPDB key with remaining quota — add a key or wait for reset (00:00 UTC).")
    return best


def _rep_to_dict(rep: IPReputation, cached: bool) -> dict:
    return {
        "ip": rep.ip,
        "abuse_score": rep.abuse_score,
        "total_reports": rep.total_reports,
        "country": rep.country,
        "isp": rep.isp,
        "usage_type": rep.usage_type,
        "domain": rep.domain,
        "is_tor": rep.is_tor,
        "last_reported_at": rep.last_reported_at,
        "checked_at": rep.checked_at.isoformat() if rep.checked_at else None,
        "cached": cached,
    }


def check_ip(db: Session, ip: str, max_age_days: int = 365, force: bool = False) -> dict:
    """Check one IP, serving from cache when fresh. Raises NoKeyAvailable when out of quota."""
    rep = db.query(IPReputation).filter(IPReputation.ip == ip).first()
    if rep and not force:
        fresh_after = datetime.utcnow() - timedelta(hours=config.ABUSEIPDB_CACHE_TTL_HOURS)
        if rep.checked_at and rep.checked_at > fresh_after:
            return _rep_to_dict(rep, cached=True)

    attempts = 0
    while True:
        key, usage = _pick_key(db)
        resp = httpx.get(
            API_URL,
            params={"ipAddress": ip, "maxAgeInDays": max_age_days},
            headers={"Key": key.api_key, "Accept": "application/json"},
            timeout=20,
        )
        usage.count += 1
        if resp.status_code == 429:
            usage.exhausted = True
            db.commit()
            attempts += 1
            if attempts >= 10:
                raise NoKeyAvailable("All keys rate-limited.")
            continue
        db.commit()
        resp.raise_for_status()
        break

    data = resp.json()["data"]
    if not rep:
        rep = IPReputation(ip=ip)
        db.add(rep)
    rep.abuse_score = data.get("abuseConfidenceScore", 0)
    rep.total_reports = data.get("totalReports", 0)
    rep.country = data.get("countryCode") or ""
    rep.isp = data.get("isp") or ""
    rep.usage_type = data.get("usageType") or ""
    rep.domain = data.get("domain") or ""
    rep.is_tor = bool(data.get("isTor"))
    rep.last_reported_at = data.get("lastReportedAt") or ""
    rep.raw = json.dumps(data)
    rep.checked_at = datetime.utcnow()
    db.commit()
    return _rep_to_dict(rep, cached=False)


def bulk_check(db: Session, ips: list[str], max_age_days: int = 365) -> dict:
    """Deduplicate, skip private/invalid IPs, check the rest until quota runs out."""
    seen, queue, skipped = set(), [], []
    for raw in ips:
        ip = raw.strip()
        if not ip or ip in seen:
            continue
        seen.add(ip)
        try:
            if not ipaddress.ip_address(ip).is_global:
                skipped.append({"ip": ip, "reason": "private/reserved"})
                continue
        except ValueError:
            skipped.append({"ip": ip, "reason": "invalid"})
            continue
        queue.append(ip)

    results, unchecked = [], []
    api_calls = cache_hits = 0
    for i, ip in enumerate(queue):
        try:
            r = check_ip(db, ip, max_age_days=max_age_days)
        except NoKeyAvailable:
            unchecked = queue[i:]
            break
        except httpx.HTTPError as exc:
            skipped.append({"ip": ip, "reason": f"api error: {exc}"})
            continue
        cache_hits += 1 if r["cached"] else 0
        api_calls += 0 if r["cached"] else 1
        results.append(r)

    results.sort(key=lambda r: r["abuse_score"], reverse=True)
    return {
        "results": results,
        "checked": len(results),
        "api_calls": api_calls,
        "cache_hits": cache_hits,
        "skipped": skipped,
        "quota_exhausted": bool(unchecked),
        "unchecked": unchecked,
    }


def usage_stats(db: Session, days: int = 30) -> list[dict]:
    """Per-key usage summary for the admin dashboard."""
    today = date.today()
    since = today - timedelta(days=days)
    out = []
    for key in db.query(AbuseIPDBKey).order_by(AbuseIPDBKey.id).all():
        rows = (db.query(KeyUsage)
                .filter(KeyUsage.key_id == key.id, KeyUsage.usage_date >= since)
                .order_by(KeyUsage.usage_date).all())
        today_row = next((r for r in rows if r.usage_date == today), None)
        used_today = today_row.count if today_row else 0
        out.append({
            "id": key.id,
            "label": key.label,
            "key_masked": key.api_key[:6] + "…" + key.api_key[-4:] if len(key.api_key) > 12 else "…",
            "daily_limit": key.daily_limit,
            "active": key.active,
            "used_today": used_today,
            "remaining_today": max(key.daily_limit - used_today, 0),
            "exhausted_today": bool(today_row and today_row.exhausted),
            "total_period": sum(r.count for r in rows),
            "history": [{"date": r.usage_date.isoformat(), "count": r.count} for r in rows],
        })
    return out
