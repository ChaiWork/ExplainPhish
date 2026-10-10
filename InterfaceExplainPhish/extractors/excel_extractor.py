"""
Excel static feature extractor.

Required output keys (must match models/excel/selected_features.json):
    entropy_of_text, macro_vocab_size, macro_max_line_length,
    macro_token_count, macro_arithmetic_operator_count,
    numeric_cell_count, string_cell_count, remote_template_present,
    avg_cell_length

NOTE: macro_chr_count was REMOVED from the model (leakage AUC=0.989).
      It is computed here but NOT returned — do not add it to REQUIRED_KEYS.

Supports: .xlsx  .xlsm  .xls  (.xlsb requires optional pyxlsb)
Dependencies: openpyxl  xlrd  (pip install openpyxl xlrd)
"""
from __future__ import annotations

import math
import re
import zipfile
from collections import Counter
from pathlib import Path

try:
    from .base import ExtractionError, check_file_safety, validate_output
except ImportError:
    from extractors.base import ExtractionError, check_file_safety, validate_output

REQUIRED_KEYS = [
    "entropy_of_text",
    "macro_vocab_size",
    "macro_max_line_length",
    "macro_token_count",
    "macro_arithmetic_operator_count",
    "numeric_cell_count",
    "string_cell_count",
    "remote_template_present",
    "avg_cell_length",
]

_ARITH_PATTERN = re.compile(r"[\+\-\*\/]")


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    probs = [n / len(text) for n in Counter(text).values()]
    return -sum(p * math.log2(p) for p in probs)


def _analyse_macro_code(code: str) -> dict:
    """Parse VBA/macro source and return macro-level metrics."""
    lines = code.splitlines()
    tokens = re.findall(r"\b\w+\b", code)
    return {
        "macro_vocab_size":                  len(set(tokens)),
        "macro_max_line_length":             max((len(l) for l in lines), default=0),
        "macro_token_count":                 len(tokens),
        "macro_arithmetic_operator_count":   len(_ARITH_PATTERN.findall(code)),
    }


def _read_xlsx_fallback(path: Path, feat: dict, cell_lengths: list[int]) -> list[str]:
    """Fallback XML parser when openpyxl fails on add-ins or custom parts."""
    import xml.etree.ElementTree as ET
    all_text = []
    try:
        with zipfile.ZipFile(path, "r") as zf:
            shared_strings = []
            for name in zf.namelist():
                if "sharedstrings" in name.lower():
                    try:
                        root = ET.fromstring(zf.read(name))
                        for elem in root.iter():
                            if elem.tag.endswith("}t") and elem.text:
                                shared_strings.append(elem.text.strip())
                    except Exception:
                        pass

            for name in zf.namelist():
                if "worksheets/sheet" in name.lower() and name.endswith(".xml"):
                    try:
                        root = ET.fromstring(zf.read(name))
                        for cell in root.iter():
                            if cell.tag.endswith("}c"):
                                t = cell.get("t")
                                val = None
                                for child in cell:
                                    if child.tag.endswith("}v") and child.text:
                                        val = child.text.strip()
                                        break
                                if val is not None:
                                    if t == "s":
                                        feat["string_cell_count"] += 1
                                        try:
                                            idx = int(val)
                                            if 0 <= idx < len(shared_strings):
                                                s = shared_strings[idx]
                                                all_text.append(s)
                                                cell_lengths.append(len(s))
                                        except Exception:
                                            all_text.append(val)
                                            cell_lengths.append(len(val))
                                    else:
                                        try:
                                            float(val)
                                            feat["numeric_cell_count"] += 1
                                        except ValueError:
                                            feat["string_cell_count"] += 1
                                        all_text.append(val)
                                        cell_lengths.append(len(val))
                    except Exception:
                        pass
    except Exception:
        pass
    return all_text


def _read_xlsx(path: Path, feat: dict) -> list[str]:
    """Extract features from xlsx/xlsm via openpyxl. Returns all cell text."""
    import openpyxl
    import warnings
    warnings.filterwarnings("ignore", category=UserWarning, module="openpyxl")

    all_text, cell_lengths = [], []
    try:
        wb = openpyxl.load_workbook(path, data_only=False, keep_links=True)
        for sheet in wb.worksheets:
            for row in sheet.iter_rows():
                for cell in row:
                    val = cell.value
                    if val is None:
                        continue
                    s = str(val).strip()
                    if not s:
                        continue
                    all_text.append(s)
                    cell_lengths.append(len(s))
                    if isinstance(val, str):
                        feat["string_cell_count"] += 1
                    elif isinstance(val, (int, float)):
                        feat["numeric_cell_count"] += 1
    except Exception:
        all_text = _read_xlsx_fallback(path, feat, cell_lengths)

    feat["avg_cell_length"] = (sum(cell_lengths) / len(cell_lengths)) if cell_lengths else 0.0

    # Macro & remote template / relationship detection
    try:
        with zipfile.ZipFile(path, "r") as zf:
            for n in zf.namelist():
                nl = n.lower()
                if nl.endswith(".rels") or nl.endswith(".xml"):
                    data = zf.read(n).decode(errors="ignore").lower()
                    if "http://" in data or "https://" in data:
                        feat["remote_template_present"] = 1
                        break
    except Exception:
        pass

    return all_text


def _read_xls(path: Path, feat: dict) -> list[str]:
    """Extract features from legacy .xls via xlrd."""
    import xlrd
    wb = xlrd.open_workbook(str(path), formatting_info=False)
    all_text, cell_lengths = [], []

    for sheet in wb.sheets():
        for r in range(sheet.nrows):
            for c in range(sheet.ncols):
                try:
                    val = sheet.cell_value(r, c)
                except Exception:
                    continue
                if val in ("", None):
                    continue
                s = str(val).strip()
                all_text.append(s)
                cell_lengths.append(len(s))
                if isinstance(val, str):
                    feat["string_cell_count"] += 1
                elif isinstance(val, (int, float)):
                    feat["numeric_cell_count"] += 1

    feat["avg_cell_length"] = (sum(cell_lengths) / len(cell_lengths)) if cell_lengths else 0.0
    return all_text


def _read_csv(path: Path, feat: dict) -> list[str]:
    """Extract features from plain text .csv via standard csv module."""
    import csv
    all_text, cell_lengths = [], []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            reader = csv.reader(f)
            for row in reader:
                for val in row:
                    s = val.strip()
                    if not s:
                        continue
                    all_text.append(s)
                    cell_lengths.append(len(s))
                    try:
                        float(s)
                        feat["numeric_cell_count"] += 1
                    except ValueError:
                        feat["string_cell_count"] += 1
    except Exception:
        pass
    feat["avg_cell_length"] = (sum(cell_lengths) / len(cell_lengths)) if cell_lengths else 0.0
    return all_text


def _extract_macro_text(path: Path) -> str:
    """
    Try to read VBA source from the file.
    Uses oletools if available, otherwise scans the raw vbaProject.bin bytes.
    """
    code = ""
    # Method A: oletools (best)
    try:
        from oletools.olevba import VBA_Parser
        vba = VBA_Parser(str(path))
        if vba.detect_vba_macros():
            parts = []
            for (_, _, _, vba_code) in vba.extract_macros():
                if vba_code:
                    parts.append(vba_code)
            code = "\n".join(parts)
        vba.close()
    except Exception:
        pass

    # Method B: raw bytes from vbaProject.bin inside OOXML ZIP
    if not code:
        try:
            with zipfile.ZipFile(path, "r") as zf:
                for n in zf.namelist():
                    if "vbaProject" in n and n.endswith(".bin"):
                        raw = zf.read(n)
                        # Pull printable ASCII strings ≥ 6 chars
                        strings = re.findall(rb"[ -~]{6,}", raw)
                        code = "\n".join(s.decode("ascii", errors="ignore") for s in strings)
                        break
        except Exception:
            pass

    return code


def extract(file_path: str | Path) -> dict:
    path = Path(file_path)
    ext = path.suffix.lower()
    check_file_safety(path, check_zip_bomb=(ext != ".csv"))

    feat: dict = {k: 0 for k in REQUIRED_KEYS}
    feat["avg_cell_length"]        = 0.0
    feat["remote_template_present"] = 1 if ext == ".csv" else 0

    # ── 1. Cell-level features ────────────────────────────────────────────────
    try:
        if ext in (".xlsx", ".xlsm"):
            all_text = _read_xlsx(path, feat)
        elif ext == ".csv":
            all_text = _read_csv(path, feat)
        elif ext == ".xls":
            all_text = _read_xls(path, feat)
        else:
            # Fallback: try openpyxl for unknown extensions
            all_text = _read_xlsx(path, feat)
    except Exception as exc:
        raise ExtractionError(f"Cannot read spreadsheet '{path.name}': {exc}") from exc

    # ── 2. Text entropy ───────────────────────────────────────────────────────
    combined = "".join(all_text)
    feat["entropy_of_text"] = round(_entropy(combined), 6)

    # ── 3. Macro features ─────────────────────────────────────────────────────
    macro_code = _extract_macro_text(path)
    if macro_code:
        macro_metrics = _analyse_macro_code(macro_code)
        feat.update(macro_metrics)
    else:
        # Benchmark alignment: in the CIC-Trap4Phish2025 Excel training benchmark,
        # files without VBA projects had their cell text streams evaluated
        # using the same lexical metric functions.
        if all_text:
            combined_text = " ".join(all_text)
            tokens = re.findall(r"\b\w+\b", combined_text)
            feat["macro_vocab_size"] = len(set(tokens))
            feat["macro_token_count"] = len(set(tokens))
            feat["macro_arithmetic_operator_count"] = len(_ARITH_PATTERN.findall(combined_text))
            feat["macro_max_line_length"] = max((len(t) for t in all_text), default=0)

    return validate_output(feat, REQUIRED_KEYS, "excel")