import base64
import io

import pyotp
import segno

from app import config


def new_secret() -> str:
    return pyotp.random_base32()


def provisioning_uri(username: str, secret: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=config.APP_NAME)


def qr_data_uri(uri: str) -> str:
    """Offline QR code as a data: URI — no external chart API involved."""
    buf = io.BytesIO()
    segno.make(uri).save(buf, kind="png", scale=5)
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()


def verify_code(secret: str, code: str) -> bool:
    return pyotp.TOTP(secret).verify(code.strip().replace(" ", ""), valid_window=1)
