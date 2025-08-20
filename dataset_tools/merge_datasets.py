#!/usr/bin/env python3
"""
Merge and normalize all CSVs from an input folder into a single dataset
matching the canonical schema of back-end/phishing.csv.

Steps per file:
 1) Normalize columns and label to match the canonical schema
 2) Collect normalized frames and concatenate
 3) Drop duplicates, reindex the 'Index' column sequentially, coerce dtypes

Usage:
  python dataset_tools/merge_datasets.py -i collecting_dataset -o back-end/dataset_merged.csv
  python dataset_tools/merge_datasets.py -i collecting_dataset -o merged.csv -m dataset_tools/config/column_mapping.example.json
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import tempfile
from typing import List, Optional, Tuple

import pandas as pd

# Import helpers from our tools, robust to script/module invocation
try:
    from .schema_utils import (
        get_canonical_schema,
        get_default_schema_path,
        get_label_column_name,
    )
    from .normalize_dataset import normalize_file, detect_label_column, normalize_label_series
except Exception:
    try:
        from dataset_tools.schema_utils import (
            get_canonical_schema,
            get_default_schema_path,
            get_label_column_name,
        )
        from dataset_tools.normalize_dataset import normalize_file, detect_label_column, normalize_label_series
    except Exception:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        if current_dir not in sys.path:
            sys.path.append(current_dir)
        from schema_utils import (
            get_canonical_schema,
            get_default_schema_path,
            get_label_column_name,
        )
        from normalize_dataset import normalize_file, detect_label_column, normalize_label_series


def is_dir(path: str) -> bool:
    try:
        return os.path.isdir(path)
    except Exception:
        return False


def _flex_read_csv(path: str) -> pd.DataFrame:
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
    if last_err:
        raise last_err
    return pd.read_csv(path)


def detect_url_column(df: pd.DataFrame) -> Optional[str]:
    candidates = [
        "url", "URL", "Url", "link", "Link", "domain", "Domain", "address", "Address"
    ]
    lowered = {c.lower(): c for c in df.columns}
    for c in candidates:
        if c.lower() in lowered:
            return lowered[c.lower()]
    # Heuristic: any column with many values that look like URLs
    for c in df.columns:
        sample = df[c].astype(str).head(50).str.contains(r"https?://|www\.", regex=True, na=False).mean()
        if sample > 0.3:
            return c
    return None


def has_enough_canonical_features(df: pd.DataFrame, canonical_cols: List[str], threshold: int = 10) -> bool:
    # Count how many canonical feature columns (excluding Index and label) exist in df
    label_col = get_label_column_name(canonical_cols) or "class"
    feature_cols = [c for c in canonical_cols if c not in ("Index", label_col)]
    overlap = sum(1 for c in feature_cols if c in df.columns)
    return overlap >= threshold


def compute_fast_features(url: str) -> List[int]:
    # Fast, offline-only subset aligned with FeatureExt order positions 1..8
    # 1 UsingIp
    using_ip = -1
    try:
        import ipaddress
        try:
            ipaddress.ip_address(url)
            using_ip = -1
        except Exception:
            using_ip = 1
    except Exception:
        using_ip = 1

    # 2 longUrl
    L = len(url)
    long_url = 1 if L < 54 else (0 if L <= 75 else -1)

    # 3 shortUrl (common shorteners)
    shortener_re = re.compile(r"bit\.ly|goo\.gl|t\.co|tinyurl|is\.gd|ow\.ly|adf\.ly|j\.mp|rb\.gy|cutt\.ly|lnkd\.in", re.I)
    short_url = -1 if shortener_re.search(url) else 1

    # 4 symbol@
    symbol_at = -1 if "@" in url else 1

    # 5 redirecting//
    redirecting = -1 if url.rfind("//") > 6 else 1

    # 6 prefixSuffix-
    try:
        from urllib.parse import urlparse
        domain = urlparse(url).netloc
    except Exception:
        domain = ""
    prefix_suffix = -1 if "-" in domain else 1

    # 7 SubDomains (by dots in full URL)
    dot_count = len(re.findall(r"\.", url))
    subdomains = 1 if dot_count == 1 else (0 if dot_count == 2 else -1)

    # 8 HTTPS
    try:
        scheme = url.split(":", 1)[0].lower()
        https = 1 if "https" in scheme else -1
    except Exception:
        https = 1

    # Remaining 22 features as 0 (unknown)
    rest = [0] * 22
    return [using_ip, long_url, short_url, symbol_at, redirecting, prefix_suffix, subdomains, https] + rest


def merge_normalized_frames(frames: List[pd.DataFrame], canonical_cols: List[str]) -> pd.DataFrame:
    if not frames:
        return pd.DataFrame(columns=canonical_cols)
    df = pd.concat(frames, axis=0, ignore_index=True)
    # Drop duplicates across all columns except Index (we'll rebuild Index)
    keep_cols = [c for c in canonical_cols if c != "Index"]
    df = df.drop_duplicates(subset=keep_cols, keep="first").reset_index(drop=True)

    # Rebuild Index sequentially if present in schema
    if canonical_cols and canonical_cols[0] == "Index":
        # Remove existing Index if present, then insert fresh sequential Index at col 0
        if "Index" in df.columns:
            df = df.drop(columns=["Index"])
        df.insert(0, "Index", range(len(df)))

    # Coerce dtypes: features to int64, label to int64
    label_col = get_label_column_name(canonical_cols) or "class"
    feature_cols = [c for c in canonical_cols if c != label_col]
    for c in feature_cols:
        if c in df.columns:
            df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0).astype("int64")
    if label_col in df.columns:
        df[label_col] = pd.to_numeric(df[label_col], errors="coerce").fillna(1).astype("int64")

    # Ensure final column order
    df = df[canonical_cols]
    return df


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Merge and normalize all CSVs in a folder to a single training-ready dataset")
    parser.add_argument("-i", "--input", required=True, help="Input folder containing CSV files")
    parser.add_argument("-o", "--output", required=True, help="Output CSV file path")
    parser.add_argument("-s", "--schema", default=get_default_schema_path(), help="Path to canonical schema CSV (default: back-end/phishing.csv)")
    parser.add_argument("-m", "--mapping", default=None, help="Optional JSON mapping file to assist column/value alignment")
    parser.add_argument("--extract-from-url", action="store_true", help="If a file lacks canonical features but has URLs, build fast features from URLs (offline subset)")
    parser.add_argument("--include-canonical", action="store_true", help="Also include the canonical dataset at --schema (default back-end/phishing.csv)")

    args = parser.parse_args(argv)
    in_dir = os.path.abspath(args.input)
    out_file = os.path.abspath(args.output)

    if not is_dir(in_dir):
        print(f"Input must be a directory: {in_dir}", file=sys.stderr)
        return 2

    canonical_cols = get_canonical_schema(args.schema)
    if not canonical_cols:
        print("Failed to load canonical schema from", args.schema, file=sys.stderr)
        return 2

    tmpdir = tempfile.mkdtemp(prefix="normalized_")
    frames: List[pd.DataFrame] = []
    processed = 0
    failures: List[str] = []

    for name in os.listdir(in_dir):
        if not name.lower().endswith(".csv"):
            continue
        src = os.path.join(in_dir, name)
        dst = os.path.join(tmpdir, os.path.splitext(name)[0] + ".normalized.csv")
        ok, msg = normalize_file(src, dst, args.schema, args.mapping, fail_on_missing=False)
        print(msg)
        if not ok:
            failures.append(name)
            continue
        try:
            df_norm = pd.read_csv(dst)
            # Heuristic: if normalized frame has almost no variance across features, try URL-based fast features
            label_col = get_label_column_name(canonical_cols) or "class"
            feature_cols = [c for c in canonical_cols if c not in ("Index", label_col)]
            non_zero_ratio = 0.0
            if not df_norm.empty:
                nz = (df_norm[feature_cols] != 0).sum().sum()
                total = len(df_norm) * len(feature_cols)
                non_zero_ratio = (nz / total) if total > 0 else 0.0

            if non_zero_ratio < 0.01:
                # Try URL-based fast extraction if allowed
                if args.extract_from_url:
                    try:
                        src_df = _flex_read_csv(src)
                        url_col = detect_url_column(src_df)
                        if not url_col:
                            print(f"No URL column found for {name}, keeping normalized zeros.")
                            frames.append(df_norm)
                            processed += 1
                            continue
                        # Detect and normalize label
                        label_col_detected = detect_label_column(src_df, {}) or label_col
                        y = normalize_label_series(src_df[label_col_detected], {}) if label_col_detected in src_df.columns else pd.Series([1] * len(src_df))
                        urls = src_df[url_col].astype(str).fillna("")
                        # Build features
                        feats: List[List[int]] = []
                        for u in urls:
                            feats.append(compute_fast_features(u))
                        # Assemble DataFrame aligned to canonical schema
                        out = pd.DataFrame(columns=canonical_cols)
                        # Set Index and label first
                        out["Index"] = range(len(feats)) if "Index" in canonical_cols else range(len(feats))
                        out[label_col] = y.values[: len(feats)]
                        # Fill features by position (columns 1..-2 in canonical order)
                        feature_only_cols = [c for c in canonical_cols if c not in ("Index", label_col)]
                        feat_df = pd.DataFrame(feats, columns=[f"f{i}" for i in range(len(feature_only_cols))])
                        for i, col in enumerate(feature_only_cols):
                            out[col] = pd.to_numeric(feat_df[f"f{i}"], errors="coerce").fillna(0).astype("int64")
                        # Reorder
                        out = out[canonical_cols]
                        frames.append(out)
                        processed += 1
                        print(f"Built fast URL-based features for {name}: rows={len(out)}")
                        continue
                    except Exception as e:
                        print(f"Fast URL-based feature build failed for {name}: {e}")
                        # fall back to normalized zeros
                # Default: keep normalized zeros to avoid losing rows
                frames.append(df_norm)
                processed += 1
            else:
                frames.append(df_norm)
                processed += 1
        except Exception as e:
            failures.append(f"{name} ({e})")

    # Optionally include canonical dataset
    if args.include_canonical and os.path.exists(args.schema):
        try:
            dst = os.path.join(tmpdir, "canonical.normalized.csv")
            ok, msg = normalize_file(args.schema, dst, args.schema, args.mapping, fail_on_missing=False)
            print("Canonical:", msg)
            if ok:
                df_canon = pd.read_csv(dst)
                frames.append(df_canon)
                processed += 1
        except Exception as e:
            failures.append(f"canonical ({e})")

    merged = merge_normalized_frames(frames, canonical_cols)

    os.makedirs(os.path.dirname(out_file) or ".", exist_ok=True)
    merged.to_csv(out_file, index=False, encoding="utf-8")

    # Simple summary
    label_col = get_label_column_name(canonical_cols) or "class"
    counts = merged[label_col].value_counts().to_dict() if label_col in merged.columns else {}
    print(f"Merged rows: {len(merged)} | Files processed: {processed} | Failures: {len(failures)}")
    if failures:
        print("Failures:", failures)
    print("Label distribution:", counts)
    print("Output:", out_file)
    return 0 if processed > 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
