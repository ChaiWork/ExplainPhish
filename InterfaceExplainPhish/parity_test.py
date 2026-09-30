"""
Parity Test — verify that each extractor's output matches the feature schema
expected by the trained models.

Usage:
    python parity_test.py --format excel  --file path/to/sample.xlsx
    python parity_test.py --format pdf    --file path/to/sample.pdf
    python parity_test.py --format html   --file path/to/sample.html
    python parity_test.py --format word   --file path/to/sample.docx
    python parity_test.py --format all    --dir  path/to/sample_folder/

What it checks:
    1. Extractor runs without crashing.
    2. Output dict has ALL required keys from selected_features.json.
    3. No extra keys (would indicate a mismatch with the trained model).
    4. All values are numeric (int or float) — except Word's categorical features.
    5. No NaN or Inf values.
    6. Feature value ranges are plausible (non-negative counts, entropy 0-8).

Output:
    PASS / FAIL per file + a summary table.

NOTE on parity vs dataset:
    True parity would compare extractor output against the dataset's own
    feature values for the same raw files. If your dataset does not ship
    the original files, use this script to at least confirm:
      - Schema match (keys and types)
      - Predictions are sensible (not all-benign or all-malicious)
    Then manually spot-check 3-5 known-benign and known-malicious files
    and confirm the model's probability_malicious goes in the right direction.
"""
import argparse
import importlib
import json
import math
import sys
from pathlib import Path

# ── locate the model folder ────────────────────────────────────────────────────
_MODELS_ROOT = (Path(__file__).resolve().parent.parent / "ExplainPhishModel" / "models"
                if (Path(__file__).resolve().parent.parent / "ExplainPhishModel" / "models").exists()
                else Path(__file__).resolve().parent.parent / "ExplainPhish" / "models")

FORMAT_EXTENSIONS = {
    "pdf":   {".pdf"},
    "excel": {".xlsx", ".xlsm", ".xls", ".xlsb"},
    "html":  {".html", ".htm"},
    "word":  {".docx", ".docm", ".dotx", ".dotm", ".doc", ".dot"},
}

# Word features are categorical strings — exclude from numeric checks
CATEGORICAL_FORMATS = {"word"}


def load_required_keys(fmt: str) -> list[str]:
    """Load the expected feature keys from models/<fmt>/selected_features.json."""
    schema_path = _MODELS_ROOT / fmt / "selected_features.json"
    if not schema_path.exists():
        print(f"  [WARN] selected_features.json not found at {schema_path}. "
              f"Skipping schema check.")
        return []
    with open(schema_path, encoding="utf-8") as f:
        return json.load(f)["selected_features"]


def check_values(features: dict, required_keys: list[str], fmt: str) -> list[str]:
    """Return a list of issue strings, empty if all checks pass."""
    issues = []
    categorical = fmt in CATEGORICAL_FORMATS

    for k in required_keys:
        if k not in features:
            issues.append(f"MISSING key: {k}")
            continue
        v = features[k]
        if not categorical or k == "file_size":
            if not isinstance(v, (int, float)):
                issues.append(f"Non-numeric value for '{k}': {type(v).__name__}")
                continue
            if math.isnan(v) or math.isinf(v):
                issues.append(f"NaN/Inf value for '{k}': {v}")
            if v < 0:
                issues.append(f"Negative value for '{k}': {v}  (expected >= 0)")
            if "entropy" in k and v > 8.01:
                issues.append(f"Entropy > 8 bits for '{k}': {v}  (unlikely)")

    extra = set(features.keys()) - set(required_keys)
    if extra:
        issues.append(f"Extra keys not in model schema: {sorted(extra)}")

    return issues


def test_file(file_path: Path, fmt: str, required_keys: list[str]) -> bool:
    """Run the extractor on one file and report results. Returns True on PASS."""
    print(f"\n  File: {file_path.name}")

    # Load extractor
    try:
        mod = importlib.import_module(f"extractors.{fmt}_extractor")
    except ModuleNotFoundError as exc:
        print(f"  [ERROR] Cannot import extractor: {exc}")
        return False

    # Run extractor
    try:
        features = mod.extract(file_path)
    except Exception as exc:
        print(f"  [FAIL] Extractor raised: {type(exc).__name__}: {exc}")
        return False

    # Schema check
    issues = check_values(features, required_keys, fmt)
    if issues:
        print(f"  [FAIL] {len(issues)} issue(s):")
        for issue in issues:
            print(f"         - {issue}")
        return False

    # Print feature values
    print(f"  [PASS] {len(features)} features extracted:")
    for k in required_keys:
        v = features.get(k)
        print(f"         {k:45s} = {v}")
    return True


def run(fmt: str, files: list[Path]) -> None:
    required_keys = load_required_keys(fmt)
    print(f"\n{'='*60}")
    print(f"Format: {fmt.upper()}   ({len(files)} file(s))")
    print(f"Required keys: {required_keys}")
    print("="*60)

    passed, failed = 0, 0
    for f in files:
        ok = test_file(f, fmt, required_keys)
        if ok:
            passed += 1
        else:
            failed += 1

    print(f"\n  Summary: {passed} PASS, {failed} FAIL")


def collect_files(fmt: str, file_arg: str | None, dir_arg: str | None) -> list[Path]:
    exts = FORMAT_EXTENSIONS[fmt]
    if file_arg:
        p = Path(file_arg)
        if not p.exists():
            print(f"File not found: {p}")
            sys.exit(1)
        return [p]
    if dir_arg:
        d = Path(dir_arg)
        if not d.is_dir():
            print(f"Directory not found: {d}")
            sys.exit(1)
        return [f for f in sorted(d.iterdir()) if f.suffix.lower() in exts]
    print("Provide --file or --dir")
    sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="ExplainPhish parity test: verify extractor output schema.")
    parser.add_argument("--format", "-f", required=True,
                        choices=list(FORMAT_EXTENSIONS.keys()) + ["all"])
    parser.add_argument("--file",  help="Path to a single file to test.")
    parser.add_argument("--dir",   help="Path to a directory of files to test.")
    args = parser.parse_args()

    formats = list(FORMAT_EXTENSIONS.keys()) if args.format == "all" else [args.format]
    for fmt in formats:
        files = collect_files(fmt, args.file, args.dir)
        run(fmt, files)


if __name__ == "__main__":
    # Add the interface folder to sys.path so 'extractors' is importable
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    main()