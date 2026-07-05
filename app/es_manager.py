"""Runtime Elasticsearch provisioning for the packaged Aura DFIR executable.

Goal (no Docker, download-once):
  * FIRST launch  -> prompt the user once:
        - point at an existing ES install folder (contains bin\\elasticsearch.bat), or
        - point at an ES already running elsewhere (a URL), or
        - press Enter to download & set it up automatically.
    The choice is persisted to  es_config.json  next to the exe.
  * EVERY later launch -> read es_config.json and start ES automatically
    (no prompt, no re-download). If ES is already reachable, just use it.

The web server (launcher.main) calls ensure() before starting uvicorn, and stop()
on shutdown for any ES instance it started. Pure mechanics live here so they can
be unit-tested with the network/subprocess calls stubbed out.
"""
import json
import os
import subprocess
import time
import zipfile
from pathlib import Path

import httpx

from app import config

ES_VERSION = os.getenv("AURADFIR_ES_VERSION", "8.13.4")
ES_HEAP = os.getenv("AURADFIR_ES_HEAP", "512m")
LOCAL_URL = "http://localhost:9200"
DOWNLOAD_URL = ("https://artifacts.elastic.co/downloads/elasticsearch/"
                f"elasticsearch-{ES_VERSION}-windows-x86_64.zip")

_MENU = (
    "\n" + "=" * 60 + "\n"
    "  Aura DFIR - first-time Elasticsearch setup\n"
    + "=" * 60 + "\n"
    "  Aura DFIR needs Elasticsearch (it is NOT bundled). Pick one:\n"
    "    * Already installed?  enter the folder that contains\n"
    "        bin\\elasticsearch.bat   (e.g. C:\\elasticsearch-8.13.4)\n"
    "    * Running elsewhere?  enter its URL  (e.g. http://localhost:9200)\n"
    "    * Neither?            just press Enter to download & set it up\n"
    + "-" * 60
)


# --------------------------------------------------------------------------- #
# Persisted config                                                             #
# --------------------------------------------------------------------------- #
def _config_path() -> Path:
    return config.DATA_DIR / "es_config.json"


def load_config() -> dict:
    try:
        return json.loads(_config_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save_config(patch: dict) -> dict:
    cur = load_config()
    cur.update(patch)
    try:
        _config_path().write_text(json.dumps(cur, indent=2), encoding="utf-8")
    except OSError:
        pass
    return cur


def _default_install_dir() -> Path:
    return config.DATA_DIR / ".elasticsearch"


# --------------------------------------------------------------------------- #
# Filesystem / process mechanics                                               #
# --------------------------------------------------------------------------- #
def looks_like_es_home(p: Path) -> bool:
    return (p / "bin" / "elasticsearch.bat").exists() or (p / "bin" / "elasticsearch").exists()


def resolve_home(raw: str):
    """Accept an ES home, or a parent dir containing an elasticsearch-* folder."""
    p = Path(raw)
    if looks_like_es_home(p):
        return p
    if p.is_dir():
        for child in sorted(p.glob("elasticsearch-*")):
            if looks_like_es_home(child):
                return child
    return None


def is_reachable(url: str) -> bool:
    if not url:
        return False
    try:
        return httpx.get(url, timeout=3).status_code == 200
    except httpx.HTTPError:
        return False


def configure_yml(home: Path):
    """Write a single-node, security-off dev config; back up any existing one once."""
    cfg = home / "config" / "elasticsearch.yml"
    try:
        if cfg.exists():
            bak = home / "config" / "elasticsearch.yml.auradfir-bak"
            if not bak.exists():
                bak.write_bytes(cfg.read_bytes())
        cfg.write_text(
            "# Written by Aura DFIR (local dev, no Docker)\n"
            "cluster.name: aura-dfir\n"
            "discovery.type: single-node\n"
            "xpack.security.enabled: false\n"
            "xpack.security.enrollment.enabled: false\n",
            encoding="utf-8")
    except OSError as exc:
        print(f"  (could not write elasticsearch.yml: {exc})")


def _download(url: str, dest: Path):
    with httpx.stream("GET", url, follow_redirects=True, timeout=None) as r:
        r.raise_for_status()
        total = int(r.headers.get("Content-Length", "0") or 0)
        done, last = 0, -1
        with open(dest, "wb") as f:
            for chunk in r.iter_bytes(262144):
                f.write(chunk)
                done += len(chunk)
                if total:
                    pct = done * 100 // total
                    if pct != last and pct % 5 == 0:
                        print(f"\r  {pct:3d}%  ({done // 1048576}/{total // 1048576} MB)",
                              end="", flush=True)
                        last = pct
        print()


def download_and_extract(install_dir: Path) -> Path:
    install_dir.mkdir(parents=True, exist_ok=True)
    home = install_dir / f"elasticsearch-{ES_VERSION}"
    if looks_like_es_home(home):
        print(f"  Elasticsearch already present at {home} (skipping download).")
        return home
    zip_path = install_dir / f"elasticsearch-{ES_VERSION}.zip"
    if not zip_path.exists():
        print(f"  Downloading Elasticsearch {ES_VERSION} (~600 MB, one-time)...")
        _download(DOWNLOAD_URL, zip_path)
    print("  Extracting...")
    with zipfile.ZipFile(zip_path) as z:
        z.extractall(install_dir)
    try:
        zip_path.unlink()
    except OSError:
        pass
    return home


def start_process(home: Path) -> subprocess.Popen:
    log = open(config.DATA_DIR / "elasticsearch.log", "ab")
    env = {**os.environ, "ES_JAVA_OPTS": f"-Xms{ES_HEAP} -Xmx{ES_HEAP}"}
    if os.name == "nt":
        cmd = ["cmd", "/c", str(home / "bin" / "elasticsearch.bat")]
        flags = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        cmd = [str(home / "bin" / "elasticsearch")]
        flags = 0
    return subprocess.Popen(cmd, cwd=str(home), env=env, stdout=log,
                            stderr=subprocess.STDOUT, creationflags=flags)


def wait_until_up(url: str, proc, timeout: int = 180) -> bool:
    print("  Waiting for Elasticsearch to come up", end="", flush=True)
    deadline = time.time() + timeout
    while time.time() < deadline:
        if is_reachable(url):
            print(" OK")
            return True
        if proc is not None and proc.poll() is not None:
            print(" FAILED (process exited early - see elasticsearch.log)")
            return False
        print(".", end="", flush=True)
        time.sleep(2)
    print(" TIMEOUT")
    return False


def stop(proc):
    if not proc:
        return
    try:
        if proc.poll() is None:
            if os.name == "nt":
                subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                               capture_output=True)
            else:
                proc.terminate()
    except (OSError, subprocess.SubprocessError):
        pass


def _start_managed(home: Path, url: str):
    configure_yml(home)
    print(f"  Starting Elasticsearch from {home}")
    proc = start_process(home)
    if wait_until_up(url, proc):
        return proc
    stop(proc)
    return None


def _finish(proc, url):
    if url:
        config.ES_URL = url          # app.es.get_es() reads this lazily
        os.environ["ES_URL"] = url
    return proc, url


# --------------------------------------------------------------------------- #
# Orchestrator                                                                 #
# --------------------------------------------------------------------------- #
def ensure(prompt=input, allow_download: bool = True):
    """Return (process_or_None, es_url_or_None).

    process is the ES instance we started (caller must stop() it on exit); it is
    None when ES was already running or is external. url is None only when ES
    could not be provisioned non-interactively.
    """
    cfg = load_config()

    # 1) Already reachable (env URL, saved URL, or default)?
    url = os.getenv("ES_URL") or cfg.get("es_url") or LOCAL_URL
    if is_reachable(url):
        print(f"  Using Elasticsearch already running at {url}")
        return _finish(None, url)

    # 2) A previously-saved managed install -> start it automatically (no prompt).
    saved_home = os.getenv("AURADFIR_ES_HOME") or (cfg.get("es_home") if cfg.get("managed") else None)
    if saved_home and looks_like_es_home(Path(saved_home)):
        target = cfg.get("es_url", LOCAL_URL)
        proc = _start_managed(Path(saved_home), target)
        if proc:
            save_config({"managed": True, "es_home": str(saved_home),
                         "es_url": target, "version": ES_VERSION})
            return _finish(proc, target)
        print("  Saved Elasticsearch did not start; let's reconfigure.")

    # 3) Non-interactive callers (e.g. --ingest) stop here.
    if prompt is None:
        if allow_download and os.getenv("AURADFIR_NONINTERACTIVE"):
            home = download_and_extract(_default_install_dir())
            proc = _start_managed(home, LOCAL_URL)
            if proc:
                save_config({"managed": True, "es_home": str(home),
                             "es_url": LOCAL_URL, "version": ES_VERSION})
                return _finish(proc, LOCAL_URL)
        return _finish(None, None)

    # 4) First-run interactive setup.
    return _interactive(prompt)


def _interactive(prompt):
    print(_MENU)
    for _ in range(3):
        raw = (prompt("  Your choice (folder path / URL / Enter to auto-download): ") or "").strip().strip('"')

        if raw == "":
            home = download_and_extract(_default_install_dir())
            proc = _start_managed(home, LOCAL_URL)
            if proc:
                save_config({"managed": True, "es_home": str(home),
                             "es_url": LOCAL_URL, "version": ES_VERSION})
                return _finish(proc, LOCAL_URL)
            print("  Could not start the downloaded Elasticsearch (see elasticsearch.log).")
            continue

        if raw.lower().startswith(("http://", "https://")):
            if is_reachable(raw):
                save_config({"managed": False, "es_url": raw})
                print(f"  Using existing Elasticsearch at {raw}")
                return _finish(None, raw)
            print(f"  Not reachable at {raw}.")
            continue

        home = resolve_home(raw)
        if home:
            proc = _start_managed(home, LOCAL_URL)
            if proc:
                save_config({"managed": True, "es_home": str(home),
                             "es_url": LOCAL_URL, "version": ES_VERSION})
                return _finish(proc, LOCAL_URL)
            print("  Found Elasticsearch there but it did not come up "
                  "(security enabled? wrong version?). See elasticsearch.log.")
            continue

        print("  No bin\\elasticsearch(.bat) under that folder. Try again.")

    print("  Falling back to automatic download.")
    home = download_and_extract(_default_install_dir())
    proc = _start_managed(home, LOCAL_URL)
    if proc:
        save_config({"managed": True, "es_home": str(home),
                     "es_url": LOCAL_URL, "version": ES_VERSION})
        return _finish(proc, LOCAL_URL)
    return _finish(None, None)
