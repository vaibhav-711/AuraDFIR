from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app import config
from app.auth.deps import current_user
from app.database import get_db
from app.es import get_es
from app.intel import abuseipdb
from app.models import User

router = APIRouter(prefix="/intel", tags=["intel"])


class BulkCheckRequest(BaseModel):
    ips: list[str] | None = None
    case_id: int | None = None
    max_age_days: int = 365


def case_source_ips(case_id: int, size: int = 10000) -> list[str]:
    es = get_es()
    index = config.case_log_index(case_id)
    if not es.indices.exists(index=index):
        raise HTTPException(404, f"No log index for case {case_id} — ingest logs first.")
    resp = es.search(index=index, size=0, aggs={
        "ips": {"terms": {"field": "source.ip", "size": size}}
    })
    return [b["key"] for b in resp["aggregations"]["ips"]["buckets"]]


@router.post("/bulk-check")
def bulk_check(req: BulkCheckRequest, db: Session = Depends(get_db),
               user: User = Depends(current_user)):
    ips = req.ips or []
    if req.case_id is not None:
        ips = ips + case_source_ips(req.case_id)
    if not ips:
        raise HTTPException(400, "Provide 'ips' or 'case_id'.")
    return abuseipdb.bulk_check(db, ips, max_age_days=req.max_age_days)


@router.get("/case/{case_id}/ips")
def list_case_ips(case_id: int, user: User = Depends(current_user)):
    ips = case_source_ips(case_id)
    return {"case_id": case_id, "unique_ips": len(ips), "ips": ips}
