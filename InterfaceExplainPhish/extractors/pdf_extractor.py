"""
PDF static feature extractor.

Required output keys (must match models/pdf/selected_features.json):
    text_length, object_count, file_size, metadata_size, title_chars,
    total_filters, entropy_of_streams, stream_count, endstream_count,
    valid_pdf_header

Dependencies:  PyMuPDF (pip install pymupdf)
               pdfminer.six (pip install pdfminer.six)
               PyPDF2 (pip install pypdf2)
"""
from __future__ import annotations

import math
import re
from collections import Counter
from pathlib import Path

try:
    from .base import ExtractionError, check_file_safety, validate_output
except ImportError:
    from extractors.base import ExtractionError, check_file_safety, validate_output

# ── required feature contract ─────────────────────────────────────────────────
REQUIRED_KEYS = [
    "text_length",
    "object_count",
    "file_size",
    "metadata_size",
    "title_chars",
    "total_filters",
    "entropy_of_streams",
    "stream_count",
    "endstream_count",
    "valid_pdf_header",
]

_KNOWN_FILTERS = {
    b"FlateDecode", b"LZWDecode", b"ASCIIHexDecode", b"ASCII85Decode",
    b"RunLengthDecode", b"CCITTFaxDecode", b"JBIG2Decode", b"DCTDecode",
    b"JPXDecode", b"Crypt",
}


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def extract(file_path: str | Path) -> dict:
    """
    Extract static features from a PDF file.

    Parameters
    ----------
    file_path : path to the PDF file.

    Returns
    -------
    dict with exactly the keys in REQUIRED_KEYS.
    """
    path = Path(file_path)
    check_file_safety(path, check_zip_bomb=False)

    raw = path.read_bytes()
    feat: dict = {k: 0 for k in REQUIRED_KEYS}
    feat["file_size"] = path.stat().st_size

    # ── 1. Valid PDF header ────────────────────────────────────────────────────
    feat["valid_pdf_header"] = 1 if raw[:5] == b"%PDF-" else 0

    # ── 2. Object count  (n obj … endobj patterns) ────────────────────────────
    feat["object_count"] = len(re.findall(rb"\d+\s+\d+\s+obj", raw))

    # ── 3. Stream / endstream counts ──────────────────────────────────────────
    feat["stream_count"]    = raw.count(b"stream")
    feat["endstream_count"] = raw.count(b"endstream")

    # ── 4. Filter count ────────────────────────────────────────────────────────
    total_filters = 0
    for f in _KNOWN_FILTERS:
        total_filters += raw.count(f)
    feat["total_filters"] = total_filters

    # ── 5. Entropy of stream content ──────────────────────────────────────────
    stream_data = b"".join(re.findall(rb"stream\r?\n(.*?)endstream", raw, re.DOTALL))
    feat["entropy_of_streams"] = round(_entropy(stream_data), 6)

    # ── 6. Text length (pdfminer) ──────────────────────────────────────────────
    try:
        from pdfminer.high_level import extract_text as _extract_text
        text = _extract_text(str(path)) or ""
        feat["text_length"] = len(text)
    except Exception:
        feat["text_length"] = 0

    # ── 7. Metadata size + title chars (PyMuPDF) ──────────────────────────────
    try:
        import fitz  # PyMuPDF
        doc = fitz.open(str(path))
        meta = doc.metadata or {}
        meta_str = " ".join(str(v) for v in meta.values() if v)
        feat["metadata_size"] = len(meta_str.encode("utf-8", errors="ignore"))
        feat["title_chars"]   = len(str(meta.get("title", "") or ""))
        doc.close()
    except Exception:
        feat["metadata_size"] = 0
        feat["title_chars"]   = 0

    return validate_output(feat, REQUIRED_KEYS, "pdf")