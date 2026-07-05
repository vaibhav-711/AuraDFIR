from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app import config
from app.auth import security, totp
from app.auth.deps import COOKIE_NAME, pending_2fa_session
from app.database import get_db
from app.models import User, UserSession
from app.templating import templates

router = APIRouter()


def _new_session(db: Session, user: User, request: Request, stage: str) -> str:
    token = security.new_session_token()
    db.add(UserSession(
        token=token,
        user_id=user.id,
        stage=stage,
        client_ip=request.client.host if request.client else "",
        expires_at=datetime.utcnow() + timedelta(hours=config.SESSION_TTL_HOURS),
    ))
    db.commit()
    return token


@router.get("/login")
def login_page(request: Request, error: str = ""):
    return templates.TemplateResponse(request, "login.html", {"error": error})


@router.post("/auth/login")
def login(request: Request, username: str = Form(...), password: str = Form(...),
          db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username, User.active == True).first()  # noqa: E712
    if not user or not security.verify_password(password, user.password_hash):
        return RedirectResponse("/login?error=Invalid+credentials", status_code=303)

    stage = "password" if user.mfa_enabled else "full"
    token = _new_session(db, user, request, stage)
    dest = "/2fa" if stage == "password" else "/"
    if stage == "full":
        user.last_login = datetime.utcnow()
        db.commit()
    resp = RedirectResponse(dest, status_code=303)
    resp.set_cookie(COOKIE_NAME, token, httponly=True, samesite="lax")
    return resp


@router.get("/2fa")
def twofa_page(request: Request, error: str = "",
               sess: UserSession = Depends(pending_2fa_session)):
    return templates.TemplateResponse(request, "twofa.html", {"error": error})


@router.post("/auth/2fa")
def twofa_verify(request: Request, code: str = Form(...),
                 sess: UserSession = Depends(pending_2fa_session),
                 db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == sess.user_id).first()
    if not user or not totp.verify_code(user.totp_secret, code):
        return RedirectResponse("/2fa?error=Invalid+code", status_code=303)
    sess.stage = "full"
    user.last_login = datetime.utcnow()
    db.commit()
    return RedirectResponse("/", status_code=303)


@router.post("/auth/logout")
def logout(request: Request, db: Session = Depends(get_db)):
    token = request.cookies.get(COOKIE_NAME)
    if token:
        db.query(UserSession).filter(UserSession.token == token).delete()
        db.commit()
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie(COOKIE_NAME)
    return resp
