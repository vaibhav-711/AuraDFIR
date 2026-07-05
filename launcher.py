"""Entry point for the packaged Aura DFIR executable.

On launch it provisions Elasticsearch (prompting once, then remembering the
choice — see app/es_manager.py), picks a free local port, starts the FastAPI
app with uvicorn, and opens the browser. When frozen by PyInstaller,
templates/static come from sys._MEIPASS and the SQLite DB + es_config.json are
written next to the .exe (see app/config.py)."""
import atexit
import os
import socket
import sys
import threading
import webbrowser


def create_admin(username: str):
    """Bootstrap the first admin from the packaged exe:  AuraDFIR.exe --create-admin admin"""
    import getpass

    from app.auth import security, totp
    from app.config import DATA_DIR
    from app.database import Base, SessionLocal, engine
    from app.models import User

    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        if db.query(User).filter(User.username == username).first():
            sys.exit(f"User '{username}' already exists.")
        password = getpass.getpass("Password: ")
        if password != getpass.getpass("Confirm:  "):
            sys.exit("Passwords do not match.")
        secret = totp.new_secret()
        db.add(User(username=username, password_hash=security.hash_password(password),
                    totp_secret=secret, is_admin=True))
        db.commit()
        qr_path = DATA_DIR / "admin_totp_qr.png"
        import segno
        segno.make(totp.provisioning_uri(username, secret)).save(str(qr_path), scale=6)
        print(f"\nAdmin '{username}' created.")
        print(f"TOTP secret (manual entry): {secret}")
        print(f"QR saved to: {qr_path}  (scan it in your authenticator, then delete the file)")
    finally:
        db.close()


def ingest(case_id: str, path: str):
    """Ingest a log file from the packaged exe:  AuraDFIR.exe --ingest 1 access.log"""
    from app import es_manager

    if not os.path.isfile(path):
        sys.exit(f"File not found: {path}")
    # Use the ES already configured/running; start it from saved config if needed,
    # but never prompt or download here.
    proc, url = es_manager.ensure(prompt=None, allow_download=False)
    if not url:
        sys.exit("Elasticsearch is not configured/running. Launch AuraDFIR.exe once "
                 "to set it up, then re-run --ingest.")
    try:
        from app.ingest.indexer import index_events
        from app.ingest.parser import iter_events
        ok, failed = index_events(int(case_id), iter_events(path))
        print(f"Indexed {ok} events into case {case_id} ({failed} bulk failures).")
    finally:
        es_manager.stop(proc)   # no-op if ES was already running (proc is None)


def reset_es():
    """Forget the saved Elasticsearch choice so the next launch prompts again."""
    from app.config import DATA_DIR
    cfg = DATA_DIR / "es_config.json"
    if cfg.exists():
        cfg.unlink()
        print(f"Removed {cfg}. Next launch will prompt for Elasticsearch again.")
    else:
        print("No saved Elasticsearch configuration to reset.")


def _usage():
    print("Aura DFIR - usage:\n"
          "  AuraDFIR.exe                         start the web server (provisions Elasticsearch)\n"
          "  AuraDFIR.exe --create-admin <user>   create the first admin user\n"
          "  AuraDFIR.exe --ingest <case_id> <file>   index a log file into a case\n"
          "  AuraDFIR.exe --reset-es              forget the saved Elasticsearch choice\n"
          "\nElasticsearch: on first run you are asked for an existing install folder, a URL,\n"
          "or press Enter to auto-download. The choice is remembered in es_config.json and\n"
          "Elasticsearch is started automatically on every later launch.")


def _free_port(preferred: int = 8000) -> int:
    for port in (preferred, 8001, 8080, 8888, 0):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(("127.0.0.1", port))
            chosen = s.getsockname()[1]
            s.close()
            return chosen
        except OSError:
            continue
    return preferred


def main():
    from app import es_manager

    # Provision Elasticsearch (prompt on first run, auto-start thereafter).
    es_proc, es_url = es_manager.ensure()
    atexit.register(es_manager.stop, es_proc)
    if not es_url:
        print("  WARNING: Elasticsearch is not available. The server will still start,\n"
              "  but cases/analysis need ES. Parameter Analysis (paste/upload) works without it.")

    import uvicorn
    from app.main import app  # imported after ES so config.ES_URL is set

    port = int(os.getenv("AURADFIR_PORT", _free_port()))
    web = f"http://127.0.0.1:{port}"
    print("=" * 60)
    print(f"  Aura DFIR is running - open {web}")
    if es_url:
        print(f"  Elasticsearch: {es_url}")
    print("  Close this window to stop the server (and Elasticsearch).")
    print("=" * 60)
    threading.Timer(2.0, lambda: webbrowser.open(web)).start()
    try:
        uvicorn.run(app, host="127.0.0.1", port=port, log_level="info")
    finally:
        es_manager.stop(es_proc)


if __name__ == "__main__":
    try:
        args = sys.argv[1:]
        if args and args[0] == "--create-admin" and len(args) >= 2:
            create_admin(args[1])
        elif args and args[0] == "--ingest" and len(args) >= 3:
            ingest(args[1], args[2])
        elif args and args[0] == "--reset-es":
            reset_es()
        elif args and args[0] in ("-h", "--help"):
            _usage()
        else:
            main()
    except KeyboardInterrupt:
        sys.exit(0)
