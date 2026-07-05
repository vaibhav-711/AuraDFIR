import os
import shutil
import tempfile

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import RedirectResponse, Response
from sqlalchemy.orm import Session

from app import config
from app.analysis.engine import run_analysis
from app.analysis.export import statistics_to_xlsx
from app.analysis.statistics import TOP_N_OPTIONS, compute_statistics
from app.auth.deps import current_user
from app.correlation.timeline import build_timeline, render_timeline_svg
from app.database import get_db
from app.es import get_es
from app.ingest.indexer import index_events
from app.ingest.parser import iter_events
from app.models import Case, CaseNote, User
from app.templating import templates

router = APIRouter(prefix="/cases", tags=["cases"])


def _es_counts(case_id: int) -> dict:
    es = get_es()
    out = {"logs": 0, "findings": 0}
    for name, idx in (("logs", config.case_log_index(case_id)),
                      ("findings", config.case_findings_index(case_id))):
        try:
            if es.indices.exists(index=idx):
                out[name] = es.count(index=idx)["count"]
        except Exception:
            pass
    return out


@router.get("")
def list_cases(request: Request, db: Session = Depends(get_db),
               user: User = Depends(current_user)):
    cases = db.query(Case).order_by(Case.created_at.desc()).all()
    return templates.TemplateResponse(request, "cases.html", {
        "user": user, "cases": cases,
    })


@router.post("")
def create_case(name: str = Form(...), description: str = Form(""),
                severity: str = Form("medium"),
                db: Session = Depends(get_db), user: User = Depends(current_user)):
    case = Case(name=name.strip(), description=description.strip(),
                severity=severity, created_by=user.username)
    db.add(case)
    db.commit()
    return RedirectResponse(f"/cases/{case.id}", status_code=303)


@router.get("/{case_id}")
def case_detail(request: Request, case_id: int, db: Session = Depends(get_db),
                user: User = Depends(current_user)):
    case = db.query(Case).get(case_id)
    if not case:
        raise HTTPException(404)
    notes = (db.query(CaseNote).filter(CaseNote.case_id == case_id)
             .order_by(CaseNote.created_at.desc()).all())
    counts = _es_counts(case_id)

    findings = []
    es = get_es()
    findex = config.case_findings_index(case_id)
    try:
        if es.indices.exists(index=findex):
            resp = es.search(index=findex, size=100, sort=[{"created_at": "desc"}])
            findings = [h["_source"] for h in resp["hits"]["hits"]]
            sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
            findings.sort(key=lambda f: (sev_rank.get(f["severity"], 9), -(f["count"] or 0)))
    except Exception:
        pass

    return templates.TemplateResponse(request, "case_detail.html", {
        "user": user, "case": case, "notes": notes,
        "counts": counts, "findings": findings,
    })


@router.post("/{case_id}/notes")
def add_note(case_id: int, body: str = Form(...),
             db: Session = Depends(get_db), user: User = Depends(current_user)):
    db.add(CaseNote(case_id=case_id, author=user.username, body=body.strip()))
    db.commit()
    return RedirectResponse(f"/cases/{case_id}", status_code=303)


@router.post("/{case_id}/status")
def set_status(case_id: int, status: str = Form(...),
               db: Session = Depends(get_db), user: User = Depends(current_user)):
    case = db.query(Case).get(case_id)
    if case and status in ("open", "closed"):
        case.status = status
        db.commit()
    return RedirectResponse(f"/cases/{case_id}", status_code=303)


@router.post("/{case_id}/ingest")
async def ingest_upload(case_id: int, file: UploadFile = File(...),
                        log_format: str = Form("auto"),
                        db: Session = Depends(get_db), user: User = Depends(current_user)):
    case = db.query(Case).get(case_id)
    if not case:
        raise HTTPException(404)
    if not file or not file.filename:
        return RedirectResponse(f"/cases/{case_id}?ingest_error=No+file+selected",
                                status_code=303)
    fmt = log_format if log_format in ("auto", "combined", "iis") else "auto"

    # Stream the upload to a temp file so multi-GB logs never load into memory;
    # iter_events() then reads it line by line into the bulk indexer.
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".log") as tmp:
            shutil.copyfileobj(file.file, tmp)
            tmp_path = tmp.name
        ok, failed = index_events(case_id, iter_events(tmp_path, fmt))
    except Exception as exc:  # noqa: BLE001 — surface any parse/index error in the UI
        return RedirectResponse(
            f"/cases/{case_id}?ingest_error=Ingest+failed:+{type(exc).__name__}",
            status_code=303)
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.remove(tmp_path)

    return RedirectResponse(
        f"/cases/{case_id}?ingested={ok}&failed={failed}&fname={file.filename}",
        status_code=303)


@router.post("/{case_id}/analyze")
def analyze(case_id: int, db: Session = Depends(get_db),
            user: User = Depends(current_user)):
    es = get_es()
    if not es.indices.exists(index=config.case_log_index(case_id)):
        raise HTTPException(400, "No logs indexed for this case yet.")
    run_analysis(case_id)
    return RedirectResponse(f"/cases/{case_id}", status_code=303)


@router.get("/{case_id}/timeline.json")
def timeline_json(case_id: int, ip: str | None = None, start: str | None = None,
                  end: str | None = None, include_benign: bool = False,
                  user: User = Depends(current_user)):
    es = get_es()
    if not es.indices.exists(index=config.case_log_index(case_id)):
        raise HTTPException(404, "No logs indexed for this case.")
    return build_timeline(case_id, ip=ip, start=start, end=end,
                          include_benign=include_benign)


@router.get("/{case_id}/timeline")
def timeline_page(request: Request, case_id: int, ip: str | None = None,
                  include_benign: bool = False, db: Session = Depends(get_db),
                  user: User = Depends(current_user)):
    case = db.query(Case).get(case_id)
    if not case:
        raise HTTPException(404)
    es = get_es()
    has_logs = es.indices.exists(index=config.case_log_index(case_id))
    tl = build_timeline(case_id, ip=ip or None,
                        include_benign=include_benign) if has_logs else None
    return templates.TemplateResponse(request, "timeline.html", {
        "user": user, "case": case, "tl": tl, "has_logs": has_logs,
        "svg": render_timeline_svg(tl) if tl else "",
        "filter_ip": ip or "", "include_benign": include_benign,
    })


@router.get("/{case_id}/statistics")
def statistics_page(request: Request, case_id: int, top_n: int = 20,
                    db: Session = Depends(get_db), user: User = Depends(current_user)):
    case = db.query(Case).get(case_id)
    if not case:
        raise HTTPException(404)
    stats = compute_statistics(case_id, top_n)
    return templates.TemplateResponse(request, "statistics.html", {
        "user": user, "case": case, "stats": stats,
        "top_n": stats["top_n"] if stats else top_n, "top_options": TOP_N_OPTIONS,
    })


@router.get("/{case_id}/statistics.json")
def statistics_json(case_id: int, top_n: int = 20,
                    user: User = Depends(current_user)):
    stats = compute_statistics(case_id, top_n)
    if stats is None:
        raise HTTPException(404, "No logs indexed for this case.")
    return stats


@router.get("/{case_id}/statistics.xlsx")
def statistics_xlsx(case_id: int, top_n: int = 20,
                    user: User = Depends(current_user)):
    stats = compute_statistics(case_id, top_n)
    if stats is None:
        raise HTTPException(404, "No logs indexed for this case.")
    data = statistics_to_xlsx(stats)
    filename = f"aura-dfir-case{case_id}-statistics.xlsx"
    return Response(
        content=data,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
