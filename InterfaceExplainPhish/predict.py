"""
ExplainPhish Prediction & Multimodal Voting CLI
==============================================
Runs the trained models (Random Forest, Decision Tree, Logistic Regression),
applies StandardScaler transformation on extracted features, computes
majority voting consensus, and presents explainability drivers for any input file.

Supported Formats:
    - HTML  (.html, .htm)
    - PDF   (.pdf)
    - Excel (.xlsx, .xlsm, .xls)
    - Word  (.docx, .docm, .doc)

Usage:
    python predict.py --file sample.pdf
    python predict.py --file sample.html
    python predict.py --file sample.xlsx
    python predict.py --file sample.docx
    python predict.py --file sample.docx --top 5
    python predict.py --dir path/to/folder/
    python predict.py --file sample.pdf --json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Add current directory to path
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from inference import run_inference, InferenceResult


def format_report(res: InferenceResult) -> str:
    lines = []
    lines.append("=" * 68)
    lines.append(f"  ExplainPhish Detection Report: {res.get('file_name', 'Unknown')}")
    lines.append("=" * 68)

    if res.get("error"):
        lines.append(f"  [ERROR] {res['error']}")
        lines.append("=" * 68)
        return "\n".join(lines)

    lines.append(f"  Format:          {res.get('format_display', res.get('format', 'N/A'))} ({res.get('format')})")
    lines.append(f"  Standardization: Applied via StandardScaler fitted on training benchmark")
    
    # Voting Verdict Box
    vote = res.get("vote", {})
    verdict = vote.get("verdict", "UNKNOWN")
    conf = vote.get("confidence", 0.0) * 100
    band = vote.get("confidence_band", "N/A")
    counts = vote.get("vote_counts", {})
    uncertain = vote.get("uncertain", False)

    verdict_badge = f"[ {verdict} ]"
    lines.append("")
    lines.append(f"  OVERALL CONSENSUS : {verdict_badge}")
    lines.append(f"  Confidence Score  : {conf:.1f}% ({band} confidence)")
    lines.append(f"  Voting Consensus  : {counts.get('malicious', 0)} Malicious vs {counts.get('benign', 0)} Benign")
    if uncertain:
        lines.append("  Agreement Status  : Split decision (majority vote applied)")
    else:
        lines.append("  Agreement Status  : Unanimous consensus across all 3 models")

    # Individual Model Predictions
    lines.append("")
    lines.append("  Individual Model Predictions (on Standardized Features):")
    lines.append("  " + "-" * 62)
    lines.append(f"    {'Model':<22} {'Prediction':<15} {'Malicious Prob'}")
    lines.append("  " + "-" * 62)
    for p in res.get("model_predictions", []):
        m_name = p.get("model", "unknown")
        m_pred = "MALICIOUS" if p.get("prediction") == 1 else "BENIGN"
        m_prob = p.get("probability_malicious", 0.0) * 100
        lines.append(f"    {m_name:<22} {m_pred:<15} {m_prob:5.1f}%")
    lines.append("  " + "-" * 62)

    # Top Risk Drivers
    drivers = res.get("top_risk_drivers", [])
    if drivers:
        lines.append("")
        total_std = len(res.get("standardized_features", {}))
        if total_std and len(drivers) < total_std:
            header_title = f"Top Decision Drivers ({len(drivers)} of {total_std} Features - Impact & Standardized Z-Score):"
        else:
            header_title = f"Top Decision Drivers (All {len(drivers)} Active Features - Impact & Standardized Z-Score):"
        lines.append(f"  {header_title}")
        lines.append("  " + "-" * 62)
        lines.append(f"    {'Feature Name':<28} {'Z-Score':<10} {'Impact'}")
        lines.append("  " + "-" * 62)
        for d in drivers:
            feat = d.get("feature", "")
            z = d.get("std_value", 0.0)
            imp = d.get("impact", 0.0)
            desc = "[+] Increases Risk" if imp > 0 else "[-] Reduces Risk"
            lines.append(f"    {feat:<28} {z:+7.2f}    {imp:+7.3f} ({desc})")
        lines.append("  " + "-" * 62)

    # Extracted Features
    features = res.get("features", {})
    if features:
        lines.append("")
        lines.append(f"  Extracted Raw Features ({len(features)} total):")
        for k, v in features.items():
            if isinstance(v, float):
                lines.append(f"    - {k:<30}: {v:.4f}")
            else:
                lines.append(f"    - {k:<30}: {v}")

    lines.append("=" * 68)
    return "\n".join(lines)


def process_file(
    file_path: Path,
    fmt: str | None = None,
    as_json: bool = False,
    top: int | None = None,
) -> None:
    try:
        res = run_inference(file_path, fmt=fmt, n_top=top)
        if as_json:
            print(json.dumps(res, indent=2), flush=True)
        else:
            print(format_report(res), flush=True)
    except Exception as e:
        if as_json:
            print(json.dumps({"file_name": file_path.name, "error": str(e)}, indent=2), flush=True)
        else:
            print(f"Error processing {file_path.name}: {e}", flush=True)


def main():
    parser = argparse.ArgumentParser(description="ExplainPhish Standardized Prediction & Voting CLI")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--file", "-f", nargs="+", help="Path to single file to analyze")
    group.add_argument("--dir", "-d", nargs="+", help="Directory of files to analyze")
    parser.add_argument("--format", choices=["pdf", "excel", "html", "word"], help="Force specific format")
    parser.add_argument("--top", "-k", type=int, default=None, help="Number of top decision drivers to display (default: all active features)")
    parser.add_argument("--json", action="store_true", help="Output raw JSON instead of text report")

    args = parser.parse_args()

    if args.file:
        file_path = Path(" ".join(args.file))
        if not file_path.is_file():
            print(f"Error: File not found at {file_path}")
            sys.exit(1)
        process_file(file_path, fmt=args.format, as_json=args.json, top=args.top)
    elif args.dir:
        dir_path = Path(" ".join(args.dir))
        if not dir_path.is_dir():
            print(f"Error: Directory not found at {dir_path}")
            sys.exit(1)
        files = sorted([p for p in dir_path.rglob("*") if p.is_file()])
        # Filter for known document formats to ignore system or temp files
        from inference import FORMAT_EXTENSIONS
        all_exts = tuple(ext for exts in FORMAT_EXTENSIONS.values() for ext in exts)
        valid_files = [p for p in files if p.suffix.lower() in all_exts]
        if not valid_files:
            valid_files = files  # fallback to magic byte sniffing if extensions differ
        print(f"Found {len(valid_files)} test documents in {dir_path}", flush=True)
        for p in valid_files:
            process_file(p, fmt=args.format, as_json=args.json, top=args.top)


if __name__ == "__main__":
    main()
