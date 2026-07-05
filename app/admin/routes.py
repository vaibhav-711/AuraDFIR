from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app import config
from app.auth import security, totp
from app.auth.deps import current_admin
from app.database import get_db
from app.intel import abuseipdb
from app.models import AbuseIPDBKey, KeyUsage, User, UserSession
from app.templating import templates

router = APIRouter(prefix="/admin", tags=["admin"])


# ---------- AbuseIPDB key management ----------

@router.get("/keys")
def keys_page(request: Request, db: Session = Depends(get_db),
              admin: User = Depends(current_admin)):
    return templates.TemplateResponse(request, "admin_keys.html", {
        "user": admin, "stats": abuseipdb.usage_stats(db),
    })


@router.post("/keys")
def add_key(label: str = Form(...), api_key: str = Form(...),
            daily_limit: int = Form(config.ABUSEIPDB_DEFAULT_DAILY_LIMIT),
            db: Session = Depends(get_db), admin: User = Depends(current_admin)):
    db.add(AbuseIPDBKey(label=label.strip(), api_key=api_key.strip(),
                        daily_limit=max(daily_limit, 1)))
    db.commit()
    return RedirectResponse("/admin/keys", status_code=303)


@router.post("/keys/{key_id}/toggle")
def toggle_key(key_id: int, db: Session = Depends(get_db),
               admin: User = Depends(current_admin)):
    key = db.query(AbuseIPDBKey).get(key_id)
    if key:
        key.active = not key.active
        db.commit()
    return RedirectResponse("/admin/keys", status_code=303)


@router.post("/keys/{key_id}/delete")
def delete_key(key_id: int, db: Session = Depends(get_db),
               admin: User = Depends(current_admin)):
    db.query(KeyUsage).filter(KeyUsage.key_id == key_id).delete()
    db.query(AbuseIPDBKey).filter(AbuseIPDBKey.id == key_id).delete()
    db.commit()
    return RedirectResponse("/admin/keys", status_code=303)


@router.get("/keys/stats.json")
def keys_stats(db: Session = Depends(get_db), admin: User = Depends(current_admin)):
    return abuseipdb.usage_stats(db)


# ---------- User management ----------

@router.get("/users")
def users_page(request: Request, db: Session = Depends(get_db),
               admin: User = Depends(current_admin)):
    users = db.query(User).order_by(User.id).all()
    return templates.TemplateResponse(request, "admin_users.html", {
        "user": admin, "users": users,
    })


@router.post("/users")
def create_user(request: Request, username: str = Form(...), password: str = Form(...),
                is_admin: bool = Form(False),
                db: Session = Depends(get_db), admin: User = Depends(current_admin)):
    if db.query(User).filter(User.username == username).first():
        return RedirectResponse("/admin/users", status_code=303)
    secret = totp.new_secret()
    new = User(username=username.strip(), password_hash=security.hash_password(password),
               totp_secret=secret, is_admin=bool(is_admin))
    db.add(new)
    db.commit()
    uri = totp.provisioning_uri(new.username, secret)
    return templates.TemplateResponse(request, "user_setup.html", {
        "user": admin, "target": new,
        "qr": totp.qr_data_uri(uri), "secret": secret,
    })


@router.post("/users/{user_id}/reset-mfa")
def reset_mfa(request: Request, user_id: int, db: Session = Depends(get_db),
              admin: User = Depends(current_admin)):
    target = db.query(User).get(user_id)
    if not target:
        return RedirectResponse("/admin/users", status_code=303)
    target.totp_secret = totp.new_secret()
    db.query(UserSession).filter(UserSession.user_id == target.id).delete()
    db.commit()
    uri = totp.provisioning_uri(target.username, target.totp_secret)
    return templates.TemplateResponse(request, "user_setup.html", {
        "user": admin, "target": target,
        "qr": totp.qr_data_uri(uri), "secret": target.totp_secret,
    })


@router.post("/users/{user_id}/toggle")
def toggle_user(user_id: int, db: Session = Depends(get_db),
                admin: User = Depends(current_admin)):
    target = db.query(User).get(user_id)
    if target and target.id != admin.id:
        target.active = not target.active
        db.query(UserSession).filter(UserSession.user_id == target.id).delete()
        db.commit()
    return RedirectResponse("/admin/users", status_code=303)
