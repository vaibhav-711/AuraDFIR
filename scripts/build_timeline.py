"""Build a correlated attack timeline for a case; export JSON or CSV."""
import argparse
import csv
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.correlation.timeline import build_timeline  # noqa: E402


def main():
    ap = argparse.ArgumentParser(description="Build Aura DFIR attack timeline")
    ap.add_argument("--case", type=int, required=True)
    ap.add_argument("--ip", help="Restrict to one source IP")
    ap.add_argument("--start", help="ISO start time (e.g. 2026-07-01T00:00:00)")
    ap.add_argument("--end", help="ISO end time")
    ap.add_argument("--include-benign", action="store_true")
    ap.add_argument("--out", default="timeline.json", help=".json or .csv output path")
    args = ap.parse_args()

    tl = build_timeline(args.case, ip=args.ip, start=args.start, end=args.end,
                        include_benign=args.include_benign)

    out = Path(args.out)
    if out.suffix.lower() == ".csv":
        with out.open("w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["start", "end", "ip", "phase", "events", "404s",
                        "bytes_out", "tags", "user_agent"])
            for s in tl["sessions"]:
                w.writerow([s["start"], s["end"], s["ip"], s["phase"],
                            s["event_count"], s["n404"], s["bytes_out"],
                            "|".join(s["tags"]), s["ua"]])
    else:
        out.write_text(json.dumps(tl, indent=2), encoding="utf-8")

    print(f"{tl['suspicious_sessions']}/{tl['total_sessions']} suspicious sessions "
          f"→ {out.resolve()}")
    for c in tl["attack_chains"][:10]:
        print(f"  {c['ip']:>15}  phases: {' → '.join(c['phases'])}  "
              f"({c['sessions']} sessions, first seen {c['first_seen']})")


if __name__ == "__main__":
    main()
