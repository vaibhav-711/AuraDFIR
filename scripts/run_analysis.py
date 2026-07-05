"""Run the analysis engine over a case's indexed logs."""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.analysis.engine import run_analysis  # noqa: E402


def main():
    ap = argparse.ArgumentParser(description="Run Aura DFIR analysis engine")
    ap.add_argument("--case", type=int, required=True, help="Case ID")
    args = ap.parse_args()
    print(json.dumps(run_analysis(args.case), indent=2))


if __name__ == "__main__":
    main()
