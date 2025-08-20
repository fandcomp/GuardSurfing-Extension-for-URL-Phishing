import os
import pandas as pd
from typing import List, Optional


def get_default_schema_path() -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    # back-end/phishing.csv relative to this file
    return os.path.normpath(os.path.join(here, "..", "back-end", "phishing.csv"))


def get_canonical_schema(schema_path: Optional[str] = None) -> List[str]:
    path = schema_path or get_default_schema_path()
    if not os.path.exists(path):
        return []
    try:
        # Read only header row for speed
        cols = pd.read_csv(path, nrows=0).columns.tolist()
        return cols
    except Exception:
        return []


def get_label_column_name(canonical_cols: List[str]) -> Optional[str]:
    # Assume the label column is the last one and named 'class' in current schema
    if not canonical_cols:
        return None
    # prefer exact known name if present
    for name in ("class", "label"):
        if name in canonical_cols:
            return name
    return canonical_cols[-1]
