"""Tests for the runtime Elasticsearch manager (network/subprocess stubbed).

Runs against a throwaway DATA_DIR so es_config.json doesn't touch the real one.
"""
import os
import sys
import tempfile
from pathlib import Path

# Point DATA_DIR at a temp dir BEFORE importing app.config / es_manager.
_TMP = Path(tempfile.mkdtemp(prefix="aura_esmgr_"))
os.environ["AURADFIR_DATA"] = str(_TMP)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import es_manager as em  # noqa: E402


class DummyProc:
    def __init__(self):
        self._alive = True

    def poll(self):
        return None if self._alive else 0


def _fake_home(root: Path) -> Path:
    home = root / "elasticsearch-8.13.4"
    (home / "bin").mkdir(parents=True, exist_ok=True)
    (home / "config").mkdir(parents=True, exist_ok=True)
    (home / "bin" / "elasticsearch.bat").write_text("echo es", encoding="utf-8")
    return home


def _reset(monkey_reachable=False):
    cfg = em._config_path()
    if cfg.exists():
        cfg.unlink()
    em.is_reachable = lambda url: monkey_reachable
    em.config.ES_URL = "http://localhost:9200"


def test_looks_like_and_resolve(tmp=_TMP):
    home = _fake_home(tmp / "a")
    assert em.looks_like_es_home(home)
    # parent dir containing an elasticsearch-* child resolves to the child
    assert em.resolve_home(str(tmp / "a")) == home
    assert em.resolve_home(str(tmp / "does-not-exist")) is None


def test_config_roundtrip():
    _reset()
    em.save_config({"managed": True, "es_home": r"C:\es", "es_url": em.LOCAL_URL})
    assert em.load_config()["es_home"] == r"C:\es"


def test_already_running_short_circuits():
    _reset(monkey_reachable=True)
    called = {"prompt": False}
    proc, url = em.ensure(prompt=lambda *_: called.__setitem__("prompt", True) or "")
    assert proc is None and url == "http://localhost:9200"
    assert called["prompt"] is False   # must NOT prompt when ES already up


def test_first_run_autodownload_then_persists(monkeypatch):
    _reset(monkey_reachable=False)
    home = _fake_home(_TMP / "auto")
    monkeypatch.setattr(em, "download_and_extract", lambda d: home)
    monkeypatch.setattr(em, "start_process", lambda h: DummyProc())
    monkeypatch.setattr(em, "wait_until_up", lambda url, proc, timeout=180: True)

    proc, url = em.ensure(prompt=lambda *_: "")   # Enter -> auto-download
    assert isinstance(proc, DummyProc) and url == em.LOCAL_URL
    cfg = em.load_config()
    assert cfg["managed"] is True and cfg["es_home"] == str(home)


def test_second_run_autostarts_without_prompt(monkeypatch):
    _reset(monkey_reachable=False)
    home = _fake_home(_TMP / "saved")
    em.save_config({"managed": True, "es_home": str(home), "es_url": em.LOCAL_URL})
    monkeypatch.setattr(em, "start_process", lambda h: DummyProc())
    monkeypatch.setattr(em, "wait_until_up", lambda url, proc, timeout=180: True)

    def _no_prompt(*_):
        raise AssertionError("must not prompt on a subsequent run")

    proc, url = em.ensure(prompt=_no_prompt)
    assert isinstance(proc, DummyProc) and url == em.LOCAL_URL


def test_existing_url_choice(monkeypatch):
    _reset(monkey_reachable=False)
    # is_reachable: false for default, true for the URL the user types
    def reachable(url):
        return url == "http://192.168.1.9:9200"
    monkeypatch.setattr(em, "is_reachable", reachable)

    proc, url = em.ensure(prompt=lambda *_: "http://192.168.1.9:9200")
    assert proc is None and url == "http://192.168.1.9:9200"
    assert em.load_config()["managed"] is False


def test_existing_folder_choice(monkeypatch):
    _reset(monkey_reachable=False)
    home = _fake_home(_TMP / "existing")
    monkeypatch.setattr(em, "start_process", lambda h: DummyProc())
    monkeypatch.setattr(em, "wait_until_up", lambda url, proc, timeout=180: True)

    proc, url = em.ensure(prompt=lambda *_: str(home))
    assert isinstance(proc, DummyProc) and url == em.LOCAL_URL
    assert em.load_config()["es_home"] == str(home)


def test_noninteractive_ingest_returns_none_when_unconfigured():
    _reset(monkey_reachable=False)   # nothing running, no saved config
    proc, url = em.ensure(prompt=None, allow_download=False)
    assert proc is None and url is None


if __name__ == "__main__":
    # Minimal pytest-monkeypatch shim so this runs with plain `python`.
    class _MP:
        def __init__(self):
            self._undo = []

        def setattr(self, obj, name, val):
            self._undo.append((obj, name, getattr(obj, name)))
            setattr(obj, name, val)

        def undo(self):
            for obj, name, val in reversed(self._undo):
                setattr(obj, name, val)
            self._undo.clear()

    fns = [(k, v) for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    for name, fn in fns:
        mp = _MP()
        try:
            import inspect
            if "monkeypatch" in inspect.signature(fn).parameters:
                fn(mp)
            else:
                fn()
            print(f"PASS {name}")
            passed += 1
        finally:
            mp.undo()
    print(f"\nAll {passed}/{len(fns)} es_manager tests passed.")
