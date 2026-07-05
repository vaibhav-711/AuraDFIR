"""Bootstrap the first admin user. Prints the TOTP secret and saves a QR PNG."""
import argparse
import getpass
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.auth import security, totp          # noqa: E402
from app.database import Base, SessionLocal, engine  # noqa: E402
from app.models import User                  # noqa: E402


def main():
    ap = argparse.ArgumentParser(description="Create a Aura DFIR admin user")
    ap.add_argument("--username", required=True)
    args = ap.parse_args()

    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        if db.query(User).filter(User.username == args.username).first():
            sys.exit(f"User '{args.username}' already exists.")
        password = getpass.getpass("Password: ")
        if password != getpass.getpass("Confirm:  "):
            sys.exit("Passwords do not match.")

        secret = totp.new_secret()
        db.add(User(username=args.username,
                    password_hash=security.hash_password(password),
                    totp_secret=secret, is_admin=True))
        db.commit()

        uri = totp.provisioning_uri(args.username, secret)
        qr_path = Path("admin_totp_qr.png")
        import segno
        segno.make(uri).save(str(qr_path), scale=6)
        print(f"\nAdmin '{args.username}' created.")
        print(f"TOTP secret (manual entry): {secret}")
        print(f"QR code saved to: {qr_path.resolve()}  (scan it, then DELETE the file)")
    finally:
        db.close()


if __name__ == "__main__":
    main()
