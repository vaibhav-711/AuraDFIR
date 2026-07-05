"""Ingest a web server log file into a case's Elasticsearch index."""
import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.ingest.indexer import index_events  # noqa: E402
from app.ingest.parser import iter_events    # noqa: E402


def main():
    ap = argparse.ArgumentParser(description="Index web server logs into Aura DFIR")
    ap.add_argument("--case", type=int, required=True, help="Case ID")
    ap.add_argument("--file", required=True, help="Path to the log file")
    ap.add_argument("--format", choices=["auto", "combined", "iis"], default="auto")
    args = ap.parse_args()

    if not Path(args.file).is_file():
        sys.exit(f"File not found: {args.file}")

    t0 = time.time()
    ok, failed = index_events(args.case, iter_events(args.file, args.format))
    print(f"Indexed {ok} events into case {args.case} "
          f"({failed} bulk failures) in {time.time() - t0:.1f}s")


if __name__ == "__main__":
    main()
