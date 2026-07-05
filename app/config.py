import os
import sys
from pathlib import Path

from dotenv import load_dotenv


def _bundle_dir() -> Path:
    """Where read-only assets (templates, static) live.
    When frozen by PyInstaller they are unpacked under sys._MEIPASS."""
    if getattr(sys, "frozen", False):
        return Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))
    return Path(__file__).resolve().parent.parent


def _data_dir() -> Path:
    """Where writable data (SQLite DB, .env) lives.
    Next to the .exe when frozen; the project root in dev.
    Override with AURADFIR_DATA (e.g. %LOCALAPPDATA%\\Aura DFIR)."""
    override = os.getenv("AURADFIR_DATA")
    if override:
        p = Path(override)
        p.mkdir(parents=True, exist_ok=True)
        return p
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).resolve().parent.parent


BUNDLE_DIR = _bundle_dir()
DATA_DIR = _data_dir()

# Load .env from the data dir first (next to the exe), then any CWD .env.
load_dotenv(DATA_DIR / ".env")
load_dotenv()

APP_NAME = os.getenv("APP_NAME", "Aura DFIR")
SECRET_KEY = os.getenv("SECRET_KEY", "dev-insecure-change-me")

# Templates/static are resolved from BUNDLE_DIR; keep BASE_DIR pointing there.
BASE_DIR = BUNDLE_DIR

DB_URL = os.getenv("AURADFIR_DB", f"sqlite:///{(DATA_DIR / 'auradfir.db').as_posix()}")

ES_URL = os.getenv("ES_URL", "http://localhost:9200")
ES_USER = os.getenv("ES_USER", "")
ES_PASSWORD = os.getenv("ES_PASSWORD", "")

SESSION_TTL_HOURS = int(os.getenv("SESSION_TTL_HOURS", "8"))

ABUSEIPDB_CACHE_TTL_HOURS = int(os.getenv("ABUSEIPDB_CACHE_TTL_HOURS", "24"))
ABUSEIPDB_DEFAULT_DAILY_LIMIT = int(os.getenv("ABUSEIPDB_DEFAULT_DAILY_LIMIT", "1000"))


def case_log_index(case_id: int) -> str:
    return f"auradfir-case{case_id}-logs"


def case_findings_index(case_id: int) -> str:
    return f"auradfir-case{case_id}-findings"
