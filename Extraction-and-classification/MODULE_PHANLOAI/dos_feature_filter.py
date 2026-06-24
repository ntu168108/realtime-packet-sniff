#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
dos_feature_filter.py — Filter + classify DoS attacks.

Wrapper that loads signatures/dos.json and applies rule-based scoring
via baseline_filter.run().

Usage:
    python dos_feature_filter.py <input.csv>
    python dos_feature_filter.py <input_dir>
    python dos_feature_filter.py <input> -o <output.csv|dir>
"""
import argparse
import logging
import sys
from pathlib import Path

from baseline_filter import run

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

CLASS_NAME = "DoS"

# Portable default output dir (replaces hardcoded Windows path).
# .../Extraction-and-classification/CSV/Filter_DoS_feature
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT_DIR = str(_PROJECT_ROOT / "CSV" / "Filter_DoS_feature")


def filter_dos_features(input_csv: str, output_csv: str) -> None:
    """Public API used by dos_classifier.py: filter DoS features and write to output_csv."""
    run(CLASS_NAME, input_csv, output_csv)


def main():
    parser = argparse.ArgumentParser(
        description=f"Filter + classify {CLASS_NAME} attacks using baseline signature rules."
    )
    parser.add_argument(
        "input",
        nargs="?",
        default=DEFAULT_OUTPUT_DIR,
        help="Input CSV file or directory of CSVs.",
    )
    parser.add_argument(
        "-o", "--output",
        default=None,
        help="Output CSV file (if input is file) or directory (if input is dir).",
    )
    args = parser.parse_args()

    in_path = Path(args.input)
    out_path = Path(args.output) if args.output else None

    if in_path.is_dir():
        out_dir = out_path if out_path and out_path.is_dir() else (out_path or in_path)
        out_dir.mkdir(parents=True, exist_ok=True)
        csv_files = sorted(in_path.glob("*.csv"))
        if not csv_files:
            logger.warning(f"No CSV files found in: {in_path}")
            sys.exit(0)
        logger.info(f"Found {len(csv_files)} CSV file(s) in {in_path}")
        for csv in csv_files:
            _process_one(csv, out_dir)
    elif in_path.is_file():
        _process_one(in_path, out_path)
    else:
        logger.error(f"Path not found: {in_path}")
        sys.exit(1)


def _process_one(in_csv: Path, out_target):
    """Process one CSV. Skip if already filtered."""
    name = in_csv.stem
    if name.endswith(f"_{CLASS_NAME.lower()}_features"):
        logger.debug(f"Skipping already-filtered file: {in_csv.name}")
        return

    base = name[:-4] if name.endswith("_raw") else name

    if out_target is None:
        out_csv = None
    elif out_target.is_dir() or str(out_target).endswith(("/", "\\")):
        out_csv = out_target / f"{base}_{CLASS_NAME.lower()}_features.csv"
    else:
        out_csv = out_target

    logger.info(f"Processing: {in_csv.name}")
    run(CLASS_NAME, str(in_csv), str(out_csv) if out_csv else None)


if __name__ == "__main__":
    main()
