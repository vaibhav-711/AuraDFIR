"""Unit tests for the pure statistics helpers (no live Elasticsearch needed)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.analysis import statistics as st  # noqa: E402


def test_clamp_top_n():
    assert st.clamp_top_n(20) == 20
    assert st.clamp_top_n(0) == 1
    assert st.clamp_top_n(99999) == 1000
    assert st.clamp_top_n("bad") == 20


def test_with_pct():
    items = st._with_pct([{"label": "a", "count": 80}, {"label": "b", "count": 20}])
    assert items[0]["pct"] == 100.0 and items[0]["share"] == 80.0
    assert items[1]["pct"] == 25.0 and items[1]["share"] == 20.0


def test_with_pct_empty():
    assert st._with_pct([]) == []


def test_classify_status():
    buckets = [{"label": 200, "count": 70}, {"label": 301, "count": 10},
               {"label": 404, "count": 15}, {"label": 500, "count": 5}]
    classes = {c["cls"]: c for c in st.classify_status(buckets)}
    assert classes["success"]["count"] == 70 and classes["success"]["share"] == 70.0
    assert classes["client_error"]["count"] == 15
    assert classes["server_error"]["count"] == 5


def test_build_timechart():
    series = [{"t": "2026-07-04 10:00", "count": 5},
              {"t": "2026-07-04 11:00", "count": 40},
              {"t": "2026-07-04 12:00", "count": 12}]
    chart = st.build_timechart(series)
    assert chart["buckets"] == 3
    assert chart["peak"]["count"] == 40
    assert chart["svg"].startswith("<svg") and "polyline" in chart["svg"]


def test_build_timechart_empty():
    chart = st.build_timechart([])
    assert chart["svg"] == "" and chart["peak"] is None


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"PASS {fn.__name__}")
    print(f"\nAll {len(fns)} statistics tests passed.")
