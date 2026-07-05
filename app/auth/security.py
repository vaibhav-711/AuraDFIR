import base64
import hashlib
import os
import secrets

_ITERATIONS = 200_000


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _ITERATIONS)
    return base64.b64encode(salt + dk).decode()


def verify_password(password: str, stored: str) -> bool:
    try:
        raw = base64.b64decode(stored.encode())
    except Exception:
        return False
    salt, dk = raw[:16], raw[16:]
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _ITERATIONS)
    return secrets.compare_digest(candidate, dk)


def new_session_token() -> str:
    return secrets.token_urlsafe(32)
