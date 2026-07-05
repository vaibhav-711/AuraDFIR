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


class _FakeStream:
    """Mimics the httpx.stream(...) context manager for one simulated response."""

    def __init__(self, status_code, headers, chunks, raise_mid_iter=None):
        self.status_code = status_code
        self.headers = headers
        self._chunks = chunks
        self._raise_mid_iter = raise_mid_iter  # index after which to raise

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def raise_for_status(self):
        if self.status_code >= 400:
            raise em.httpx.HTTPStatusError("bad status", request=None, response=None)

    def iter_bytes(self, chunk_size):
        for i, c in enumerate(self._chunks):
            yield c
            if self._raise_mid_iter is not None and i == self._raise_mid_iter:
                raise em.httpx.RemoteProtocolError("peer closed connection early")


def test_download_retries_transient_failure_and_resumes(monkeypatch):
    dest = _TMP / "retry_test.zip"
    dest.unlink(missing_ok=True)
    monkeypatch.setattr(em.time, "sleep", lambda s: None)
    calls = []

    def fake_stream(method, url, follow_redirects=True, headers=None, timeout=None):
        calls.append(dict(headers or {}))
        if len(calls) == 1:
            # dies right after the first chunk, like the reported RemoteProtocolError
            return _FakeStream(200, {"Content-Length": "20"},
                               [b"A" * 10, b"B" * 10], raise_mid_iter=0)
        # second attempt: server honors the Range header, sends only the rest
        return _FakeStream(206, {"Content-Length": "10"}, [b"B" * 10])

    monkeypatch.setattr(em.httpx, "stream", fake_stream)
    em._download("http://fake/file.zip", dest)
    assert dest.read_bytes() == b"A" * 10 + b"B" * 10, "resumed download should append, not restart"
    assert len(calls) == 2
    assert calls[1].get("Range") == "bytes=10-", "second attempt must ask to resume from byte 10"
    dest.unlink(missing_ok=True)


def test_download_exhausts_retries_and_leaves_no_corrupt_file(monkeypatch):
    dest = _TMP / "fail_test.zip"
    dest.unlink(missing_ok=True)
    monkeypatch.setattr(em.time, "sleep", lambda s: None)

    def always_dies(method, url, follow_redirects=True, headers=None, timeout=None):
        return _FakeStream(200, {"Content-Length": "20"}, [b"A" * 5], raise_mid_iter=0)

    monkeypatch.setattr(em.httpx, "stream", always_dies)
    try:
        em._download("http://fake/file.zip", dest)
        raise AssertionError("expected RuntimeError after exhausting retries")
    except RuntimeError as exc:
        assert "Could not download" in str(exc)
    assert not dest.exists(), "a failed download must never leave a corrupt partial file behind"


def test_download_and_extract_cleans_up_a_corrupt_zip(monkeypatch):
    install_dir = _TMP / "corrupt_install"
    install_dir.mkdir(parents=True, exist_ok=True)
    zip_path = install_dir / f"elasticsearch-{em.ES_VERSION}.zip"
    zip_path.write_bytes(b"not a real zip file")  # simulates a corrupt leftover

    def must_not_be_called(url, dest):
        raise AssertionError("should not re-download when a zip file already exists")
    monkeypatch.setattr(em, "_download", must_not_be_called)

    try:
        em.download_and_extract(install_dir)
        raise AssertionError("expected RuntimeError for a corrupt zip")
    except RuntimeError as exc:
        assert "corrupt" in str(exc).lower()
    assert not zip_path.exists(), "corrupt zip must be removed so the next run can retry cleanly"


def test_interactive_enter_recovers_after_a_failed_download(monkeypatch):
    _reset(monkey_reachable=False)
    home = _fake_home(_TMP / "recovered")
    attempts = {"n": 0}

    def flaky_download(install_dir):
        attempts["n"] += 1
        if attempts["n"] == 1:
            raise RuntimeError("simulated network failure")
        return home

    monkeypatch.setattr(em, "download_and_extract", flaky_download)
    monkeypatch.setattr(em, "start_process", lambda h: DummyProc())
    monkeypatch.setattr(em, "wait_until_up", lambda url, proc, timeout=180: True)

    prompts = iter(["", ""])  # first Enter fails, second Enter (retry) succeeds
    proc, url = em.ensure(prompt=lambda *_: next(prompts))
    assert isinstance(proc, DummyProc) and url == em.LOCAL_URL
    assert attempts["n"] == 2, "the menu must survive a failed download and let the user retry"


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
