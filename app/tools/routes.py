from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from sqlalchemy.orm import Session

from app import config
from app.analysis.parameters import SERVER_TYPES, analyze_parameters
from app.auth.deps import current_user
from app.database import get_db
from app.es import get_es
from app.models import Case, User
from app.templating import templates

router = APIRouter(prefix="/tools", tags=["tools"])


def _sample_case_lines(case_id: int, limit: int = 1000) -> list[str]:
    """Pull raw log lines from a case's indexed events (we keep event.original)."""
    es = get_es()
    index = config.case_log_index(case_id)
    if not es.indices.exists(index=index):
        return []
    resp = es.search(index=index, size=limit, _source=["event.original"],
                     query={"match_all": {}})
    out = []
    for h in resp["hits"]["hits"]:
        original = h["_source"].get("event", {}).get("original")
        if original:
            out.append(original)
    return out


@router.get("/parameters")
def parameters_page(request: Request, case_id: int | None = None,
                    db: Session = Depends(get_db), user: User = Depends(current_user)):
    case = db.query(Case).get(case_id) if case_id else None
    return templates.TemplateResponse(request, "parameters.html", {
        "user": user, "server_types": SERVER_TYPES, "report": None,
        "case": case, "log_text": "", "selected_type": "apache",
    })


@router.post("/parameters")
async def parameters_run(request: Request, server_type: str = Form(...),
                         source: str = Form("paste"), log_text: str = Form(""),
                         case_id: int | None = Form(None),
                         file: UploadFile | None = File(None),
                         db: Session = Depends(get_db), user: User = Depends(current_user)):
    lines: list[str] = []
    note = ""
    if source == "upload" and file is not None:
        raw = (await file.read()).decode("utf-8", errors="replace")
        lines = raw.splitlines()
        note = f"Uploaded file: {file.filename} ({len(lines)} lines)"
    elif source == "case" and case_id:
        lines = _sample_case_lines(case_id)
        note = (f"Sampled {len(lines)} raw events from case #{case_id}"
                if lines else f"No indexed logs found for case #{case_id}.")
    else:
        lines = log_text.splitlines()
        note = f"Pasted input ({len(lines)} lines)"

    report = analyze_parameters(server_type, lines) if lines else None
    case = db.query(Case).get(case_id) if case_id else None
    return templates.TemplateResponse(request, "parameters.html", {
        "user": user, "server_types": SERVER_TYPES, "report": report,
        "case": case, "log_text": log_text if source == "paste" else "",
        "selected_type": server_type, "note": note,
    })
