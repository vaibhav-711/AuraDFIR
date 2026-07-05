from fastapi import Depends, FastAPI, Request
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session

from app import config
from app.admin.routes import router as admin_router
from app.auth.deps import current_user
from app.auth.routes import router as auth_router
from app.cases.routes import router as cases_router
from app.database import Base, engine, get_db
from app.es import get_es
from app.intel.routes import router as intel_router
from app.models import AbuseIPDBKey, Case, User
from app.templating import templates
from app.tools.routes import router as tools_router

app = FastAPI(title=config.APP_NAME)
app.mount("/static", StaticFiles(directory=str(config.BASE_DIR / "app" / "static")),
          name="static")

app.include_router(auth_router)
app.include_router(cases_router)
app.include_router(admin_router)
app.include_router(intel_router)
app.include_router(tools_router)


@app.on_event("startup")
def startup():
    Base.metadata.create_all(bind=engine)


@app.get("/")
def dashboard(request: Request, db: Session = Depends(get_db),
              user: User = Depends(current_user)):
    stats = {
        "open_cases": db.query(Case).filter(Case.status == "open").count(),
        "total_cases": db.query(Case).count(),
        "users": db.query(User).filter(User.active == True).count(),  # noqa: E712
        "api_keys": db.query(AbuseIPDBKey).filter(AbuseIPDBKey.active == True).count(),  # noqa: E712
        "es_status": "unreachable",
    }
    try:
        stats["es_status"] = get_es().cluster.health()["status"]
    except Exception:
        pass
    return templates.TemplateResponse(request, "dashboard.html", {
        "user": user, "stats": stats,
    })
