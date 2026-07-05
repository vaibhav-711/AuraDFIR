from datetime import datetime

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User, UserSession

COOKIE_NAME = "aura_session"


def _redirect_to_login():
    return HTTPException(status_code=303, headers={"Location": "/login"})


def _session_for(request: Request, db: Session, stage: str):
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return None
    sess = db.query(UserSession).filter(UserSession.token == token).first()
    if not sess or sess.expires_at < datetime.utcnow():
        return None
    if stage == "full" and sess.stage != "full":
        return None
    return sess


def current_user(request: Request, db: Session = Depends(get_db)) -> User:
    sess = _session_for(request, db, stage="full")
    if not sess:
        raise _redirect_to_login()
    user = db.query(User).filter(User.id == sess.user_id, User.active == True).first()  # noqa: E712
    if not user:
        raise _redirect_to_login()
    return user


def current_admin(user: User = Depends(current_user)) -> User:
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


def pending_2fa_session(request: Request, db: Session = Depends(get_db)) -> UserSession:
    sess = _session_for(request, db, stage="password")
    if not sess:
        raise _redirect_to_login()
    return sess
