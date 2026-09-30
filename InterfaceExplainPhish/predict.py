"""
ExplainPhish Prediction & Voting CLI

Runs the trained models (Decision Tree, Random Forest, XGBoost), computes
majority voting consensus, and extracts SHAP explanation drivers for any input file.

Usage:
    python predict.py --file sample.pdf
    python predict.py --file sample.xlsx
    python predict.py --dir path/to/folder/
    python predict.py --file sample.pdf --json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Add ExplainPhish to sys.path so we can import its core pipeline
_HERE = Path(__file__).resolve().parent
_EXPLAINPHISH_ROOT = _HERE.parent / "ExplainPhishModel" if (_HERE.parent / "ExplainPhishModel").exists() else _HERE.parent / "ExplainPhish"
if str(_EXPLAINPHISH_ROOT) not in sys.path:
    sys.path.insert(0, str(_EXPLAINPHISH_ROOT))

# Also ensure InterfaceExplainPhish extractors take precedence
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

try:
    from src.inference import run_inference
except ImportError as e:
    print(f"Error: Unable to import ExplainPhish inference core from {_EXPLAINPHISH_ROOT}: {e}")
    sys.exit(1)


def format_report(res: dict) -> str:
    lines = []
    lines.append("=" * 64)
    lines.append(f" ExplainPhish Detection Report: {res.get('file_name', 'Unknown')}")
    lines.append("=" * 64)

    if res.get("error"):
        lines.append(f"  [ERROR] {res['error']}")
        lines.append("=" * 64)
        return "\n".join(lines)

    lines.append(f"  Format:        {res.get('format_display', res.get('format', 'N/A'))} ({res.get('format')})")
    
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
        lines.append("  Uncertainty Flag  : Models disagree (split decision)")
    else:
        lines.append("  Uncertainty Flag  : Unanimous consensus across all models")

    # Individual Model Predictions
    lines.append("")
    lines.append("  Individual Model Predictions:")
    lines.append("  " + "-" * 58)
    lines.append(f"    {'Model':<18} {'Prediction':<15} {'Malicious Prob'}")
    lines.append("  " + "-" * 58)
    for p in res.get("model_predictions", []):
        m_name = p.get("model", "unknown").replace("_", " ").title()
        m_pred = "MALICIOUS" if p.get("prediction") == 1 else "BENIGN"
        m_prob = p.get("probability_malicious", 0.0) * 100
        lines.append(f"    {m_name:<18} {m_pred:<15} {m_prob:5.1f}%")
    lines.append("  " + "-" * 58)

    # Top SHAP Explainability Drivers
    shap_list = res.get("shap_top_features", [])
    if shap_list:
        lines.append("")
        lines.append("  Key Decision Drivers (SHAP Explanations):")
        lines.append("  " + "-" * 58)
        lines.append(f"    {'Feature Name':<28} {'Impact':<10} {'Direction'}")
        lines.append("  " + "-" * 58)
        for s in shap_list:
            feat = s.get("feature", "")
            val = s.get("shap_value", 0.0)
            d = s.get("direction", "")
            arrow = "[+]" if "+" in d or "↑" in d else "[-]"
            desc = "Increases Risk" if "+" in d or "↑" in d else "Reduces Risk"
            lines.append(f"    {feat:<28} {val:+8.4f}   {arrow} ({desc})")
        lines.append("  " + "-" * 58)

    # Extracted Features
    features = res.get("features", {})
    if features:
        lines.append("")
        lines.append(f"  Extracted Features ({len(features)} total):")
        for k, v in features.items():
            if isinstance(v, float):
                lines.append(f"    - {k:<28}: {v:.4f}")
            else:
                lines.append(f"    - {k:<28}: {v}")

    lines.append("=" * 64)
    return "\n".join(lines)


def process_file(file_path: Path, fmt: str | None = None, as_json: bool = False) -> None:
    res = run_inference(file_path, fmt=fmt)
    res["file_name"] = file_path.name
    res["file_path"] = str(file_path)

    if as_json:
        print(json.dumps(res, indent=2))
    else:
        print(format_report(res))


def main():
    parser = argparse.ArgumentParser(description="ExplainPhish Model Prediction & Voting CLI")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--file", "-f", nargs="+", help="Path to single file to analyze")
    group.add_argument("--dir", "-d", nargs="+", help="Directory of files to analyze")
    parser.add_argument("--format", choices=["pdf", "excel", "html", "word"], help="Force specific format")
    parser.add_argument("--json", action="store_true", help="Output raw JSON instead of text report")

    args = parser.parse_args()

    if args.file:
        file_path = Path(" ".join(args.file))
        if not file_path.is_file():
            print(f"Error: File not found at {file_path}")
            sys.exit(1)
        process_file(file_path, fmt=args.format, as_json=args.json)
    elif args.dir:
        dir_path = Path(" ".join(args.dir))
        if not dir_path.is_dir():
            print(f"Error: Directory not found at {dir_path}")
            sys.exit(1)
        files = [p for p in dir_path.iterdir() if p.is_file()]
        print(f"Found {len(files)} files in {dir_path}")
        for p in files:
            process_file(p, fmt=args.format, as_json=args.json)


if __name__ == "__main__":
    main()

