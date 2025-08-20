#!/usr/bin/env python3
"""
Normalize arbitrary phishing datasets to match the canonical schema of back-end/phishing.csv.

Features:
- Reads the canonical column order from ../back-end/phishing.csv (or a provided --schema).
- Detects the label column even if named differently (e.g., label, target, is_phishing, status, etc.).
- Maps label values to {-1, 1} with sensible defaults and customizable via --mapping JSON.
- Reorders, adds missing columns (filled with 0 except Index), drops extras, and writes a clean CSV.

Usage examples:
  python dataset_tools/normalize_dataset.py -i data.csv -o data.normalized.csv
  python dataset_tools/normalize_dataset.py -i raw_folder -o out_folder
  python dataset_tools/normalize_dataset.py -i data.csv -o data.normalized.csv -m dataset_tools/config/column_mapping.example.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Dict, List, Optional, Tuple

import pandas as pd

# Support running as a script or as a module
try:
    from .schema_utils import (
        get_canonical_schema,
        get_default_schema_path,
        get_label_column_name,
    )
except Exception:
    try:
        from dataset_tools.schema_utils import (
            get_canonical_schema,
            get_default_schema_path,
            get_label_column_name,
        )
    except Exception:
        # Fallback: add current folder to sys.path and import
        current_dir = os.path.dirname(os.path.abspath(__file__))
        if current_dir not in sys.path:
            sys.path.append(current_dir)
        from schema_utils import (
            get_canonical_schema,
            get_default_schema_path,
            get_label_column_name,
        )


KNOWN_LABEL_NAMES = [
    "class",
    "label",
    "labels",
    "target",
    "y",
    "is_phishing",
    "phishing",
    "status",
    "result",
]

DEFAULT_STRING_LABEL_MAP = {
    # negative / phishing side maps to -1
    "phishing": -1,
    "malicious": -1,
    "bad": -1,
    "fraud": -1,
    "spam": -1,
    "unsafe": -1,
    "phish": -1,
    # positive / legitimate side maps to 1
    "legitimate": 1,
    "benign": 1,
    "good": 1,
    "safe": 1,
    "clean": 1,
}


def _flex_read_csv(path: str) -> pd.DataFrame:
    """Read CSV robustly by trying common encodings/engines/separators and skipping bad lines.
    This helps with inconsistent CSVs from multiple sources.
    """
    # Try a sequence of strategies
    strategies = [
        dict(encoding="utf-8", engine="python", sep=None, on_bad_lines="skip"),
        dict(encoding="utf-8-sig", engine="python", sep=None, on_bad_lines="skip"),
        dict(encoding="latin-1", engine="python", sep=None, on_bad_lines="skip"),
        dict(encoding="utf-8", engine="c", on_bad_lines="skip"),
    ]

    last_err: Optional[Exception] = None
    for opts in strategies:
        try:
            return pd.read_csv(path, **opts)
        except Exception as e:
            last_err = e
            continue
    # If all failed, raise the last error
    if last_err:
        raise last_err
    # Fallback (should not reach)
    return pd.read_csv(path)


def load_mapping(path: Optional[str]) -> Dict:
    if not path:
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def detect_label_column(df: pd.DataFrame, mapping: Dict) -> Optional[str]:
    # Mapping has priority
    label_col = mapping.get("label_column") if isinstance(mapping, dict) else None
    if label_col and label_col in df.columns:
        return label_col

    # Try exact/ci matches
    lowered = {c.lower(): c for c in df.columns}
    for name in KNOWN_LABEL_NAMES:
        if name in lowered:
            return lowered[name]

    # Heuristic: if df has a column named almost like 'class' ignoring case/space
    normalized = {"".join(c.lower().split()): c for c in df.columns}
    for name in KNOWN_LABEL_NAMES:
        key = "".join(name.lower().split())
        if key in normalized:
            return normalized[key]

    # Fallback: if last column looks binary-like
    last = df.columns[-1]
    unique_vals = set(map(str, pd.unique(df[last].astype(str).str.lower())))
    if unique_vals.issubset({"-1", "1", "0", "phishing", "legitimate", "benign", "malicious", "good", "bad", "safe", "unsafe"}):
        return last

    return None


def normalize_label_series(s: pd.Series, mapping: Dict) -> pd.Series:
    # If mapping specifies a value_map, use it first (case-insensitive for strings)
    value_map = mapping.get("value_map") if isinstance(mapping, dict) else None

    def try_map(val):
        if pd.isna(val):
            return val
        # numeric handling
        try:
            f = float(val)
            if pd.isna(f):
                return val
            # Common numeric encodings
            if f in (-1.0, 1.0):
                return int(f)
            if f in (0.0, 1.0):
                # Convert 0->-1, 1->1
                return 1 if f == 1.0 else -1
        except Exception:
            pass

        # string handling
        sval = str(val).strip().lower()
        if value_map and isinstance(value_map, dict):
            # case-insensitive lookup for strings
            for k, v in value_map.items():
                if str(k).strip().lower() == sval:
                    return int(v)
        if sval in DEFAULT_STRING_LABEL_MAP:
            return DEFAULT_STRING_LABEL_MAP[sval]
        return val

    mapped = s.map(try_map)

    # After mapping, if still strings but only 2 unique values, attempt final inference
    if mapped.dtype == object:
        uniq = sorted({str(x).lower() for x in pd.unique(mapped)})
        if len(uniq) == 2 and all(u in DEFAULT_STRING_LABEL_MAP for u in uniq):
            mapped = mapped.map(lambda x: DEFAULT_STRING_LABEL_MAP[str(x).lower()])

    # Coerce to integers if possible
    mapped_num = pd.to_numeric(mapped, errors="coerce")
    if mapped_num.isna().any():
        # If any unmapped, keep original to help diagnose, but try to fill with mode if binary
        candidates = pd.Series(mapped_num.dropna().unique())
        if set(candidates) <= {-1, 1}:
            mapped_num = mapped_num.fillna(1)  # default to legitimate if unknown
    mapped_num = mapped_num.astype("int64", errors="ignore")
    return mapped_num


def ensure_index_column(df: pd.DataFrame, canonical_cols: List[str]) -> pd.DataFrame:
    # Canonical first column is typically 'Index'
    if len(canonical_cols) > 0 and canonical_cols[0].lower() == "index":
        if "Index" not in df.columns:
            # Try to recover existing index-like columns
            for cand in ["index", "Id", "ID", "idx", "no", "No"]:
                if cand in df.columns:
                    df = df.rename(columns={cand: "Index"})
                    break
            if "Index" not in df.columns:
                df.insert(0, "Index", range(len(df)))
        else:
            # ensure it's integer-like
            converted = pd.to_numeric(df["Index"], errors="coerce")
            if converted.isna().any():
                fallback = pd.Series(range(len(df)), index=df.index)
                converted = converted.fillna(fallback)
            df["Index"] = converted.astype(int)
    return df


def apply_rename_map(df: pd.DataFrame, mapping: Dict) -> pd.DataFrame:
    rename_map = mapping.get("rename_map") if isinstance(mapping, dict) else None
    if isinstance(rename_map, dict) and rename_map:
        return df.rename(columns=rename_map)
    return df


def normalize_file(
    in_path: str,
    out_path: str,
    schema_path: Optional[str],
    mapping_path: Optional[str],
    fail_on_missing: bool = False,
) -> Tuple[bool, str]:
    mapping = load_mapping(mapping_path)
    canonical_cols = get_canonical_schema(schema_path)
    label_col_canonical = get_label_column_name(canonical_cols)

    if not canonical_cols or label_col_canonical is None:
        return False, "Failed to load canonical schema/label."

    try:
        df = _flex_read_csv(in_path)
    except Exception as e:
        return False, f"Failed to read {os.path.basename(in_path)}: {e}"

    # Apply user-provided renames first
    df = apply_rename_map(df, mapping)

    # Ensure Index exists if needed by schema
    df = ensure_index_column(df, canonical_cols)

    # Detect label column
    detected_label = detect_label_column(df, mapping)
    if detected_label is None:
        return False, f"Could not detect label column in {os.path.basename(in_path)}. Provide --mapping with 'label_column'."

    # Normalize label values to {-1, 1}
    df[label_col_canonical] = normalize_label_series(df[detected_label], mapping)
    if detected_label != label_col_canonical:
        # Drop the original label column if name differs
        if detected_label in df.columns:
            df = df.drop(columns=[detected_label])

    # Align columns: add missing, drop extras (except canonical label)
    for col in canonical_cols:
        if col not in df.columns:
            # Missing feature -> fill with 0, missing Index handled earlier
            df[col] = 0

    # Drop columns not in canonical schema
    extras = [c for c in df.columns if c not in canonical_cols]
    if extras:
        df = df.drop(columns=extras)

    # Reorder to canonical
    df = df[canonical_cols]

    # Coerce feature columns to numeric ints where possible
    feature_cols = [c for c in canonical_cols if c != label_col_canonical]
    for c in feature_cols:
        df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0).astype("int64")

    # Final safety on label column
    df[label_col_canonical] = pd.to_numeric(df[label_col_canonical], errors="coerce").fillna(1).astype("int64")

    # Validate missing column handling
    missing_after = [c for c in canonical_cols if c not in df.columns]
    if missing_after:
        msg = f"Missing required columns even after normalization: {missing_after}"
        if fail_on_missing:
            return False, msg
        else:
            print("Warning:", msg)

    # Write
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    df.to_csv(out_path, index=False, encoding="utf-8")
    return True, f"Wrote normalized file: {out_path} (rows={len(df)}, cols={len(df.columns)})"


def is_dir(path: str) -> bool:
    try:
        return os.path.isdir(path)
    except Exception:
        return False


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Normalize datasets to match back-end/phishing.csv schema")
    parser.add_argument("-i", "--input", required=True, help="Input CSV file or directory")
    parser.add_argument("-o", "--output", required=True, help="Output CSV file or directory")
    parser.add_argument("-s", "--schema", default=get_default_schema_path(), help="Path to canonical schema CSV (default: back-end/phishing.csv)")
    parser.add_argument("-m", "--mapping", default=None, help="Optional JSON mapping file for column/value names")
    parser.add_argument("--fail-on-missing", action="store_true", help="Fail if any canonical columns are missing in input")

    args = parser.parse_args(argv)

    in_path = os.path.abspath(args.input)
    out_path = os.path.abspath(args.output)

    if is_dir(in_path):
        if not is_dir(out_path):
            print("When input is a directory, output must be a directory as well.", file=sys.stderr)
            return 2
        # Process all CSV files in input dir
        any_fail = False
        for name in os.listdir(in_path):
            if not name.lower().endswith(".csv"):
                continue
            src = os.path.join(in_path, name)
            dst = os.path.join(out_path, os.path.splitext(name)[0] + ".normalized.csv")
            ok, msg = normalize_file(src, dst, args.schema, args.mapping, args.fail_on_missing)
            print(msg)
            any_fail = any_fail or (not ok)
        return 1 if any_fail else 0
    else:
        # Single file
        # If output is a directory, derive filename
        if is_dir(out_path):
            base = os.path.splitext(os.path.basename(in_path))[0] + ".normalized.csv"
            out_path = os.path.join(out_path, base)
        ok, msg = normalize_file(in_path, out_path, args.schema, args.mapping, args.fail_on_missing)
        print(msg)
        return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
