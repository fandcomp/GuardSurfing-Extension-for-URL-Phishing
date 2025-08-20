# Dataset Tools

A small toolkit to normalize any phishing dataset to match the canonical schema used by `back-end/phishing.csv`.

What it does:
- Reads the canonical column order from `back-end/phishing.csv`.
- Detects the label column (even if named differently) and converts it to {-1, 1}.
- Adds missing columns (filled with 0), drops extra columns, and reorders to match.

## Quick start

- Single CSV to CSV:

```powershell
python dataset_tools/normalize_dataset.py -i path\to\raw.csv -o path\to\normalized.csv
```

- Folder of CSVs to folder:

```powershell
python dataset_tools/normalize_dataset.py -i path\to\raw_folder -o path\to\out_folder
```

- With explicit mapping (helpful when column names differ a lot):

```powershell
python dataset_tools/normalize_dataset.py -i raw.csv -o normalized.csv -m dataset_tools/config/column_mapping.example.json
```

If your label column is not automatically detected, provide it in a JSON mapping file via `--mapping`, e.g.:

```json
{
  "label_column": "Label",
  "rename_map": { "Hppts": "HTTPS" },
  "value_map": { "phishing": -1, "legitimate": 1, "0": -1, "1": 1 }
}
```

## Merge multiple datasets into one

To merge and normalize all CSVs in a folder (e.g., `collecting_dataset/`) into one training-ready CSV:

```powershell
python dataset_tools/merge_datasets.py -i collecting_dataset -o back-end\dataset_merged.csv
```

Include the canonical dataset as well (`back-end/phishing.csv`):

```powershell
python dataset_tools/merge_datasets.py -i collecting_dataset -o back-end\dataset_merged.csv --include-canonical
```

Optionally, pass a mapping file if column names vary widely:

```powershell
python dataset_tools/merge_datasets.py -i collecting_dataset -o back-end\dataset_merged.csv -m dataset_tools\config\column_mapping.example.json
```

If your sources don’t have canonical feature columns but do contain URLs, build fast offline features from URL strings:

```powershell
python dataset_tools/merge_datasets.py -i collecting_dataset -o back-end\dataset_merged.csv --extract-from-url
```

This will:
- Normalize each file to the `back-end/phishing.csv` schema
- Concatenate them, drop duplicates, rebuild the `Index` column, and coerce dtypes
- Write the result to the given output file

## Notes
- The canonical label column name is inferred from `back-end/phishing.csv` (currently `class`).
- Missing Index column (first column) will be created if absent.
- Feature values are coerced to integers and missing values filled with 0.
