"""
ExplainPhish inference core — three layers:

  1. router.py        — detect file format by magic bytes (not extension)
  2. voting.py        — combine three model outputs into a consensus verdict
  3. inference.py     — orchestrate everything (updated, replaces stub)

This file: router.py
"""
from pathlib import Path

# Magic-byte signatures: (byte_offset, bytes_to_match) → format key
# Listed most-specific first so the first match wins.
_SIGNATURES: list[tuple[int, bytes, str]] = [
    # PDF: always starts with %PDF
    (0, b"%PDF",                          "pdf"),
    # Office Open XML (docx / xlsx): ZIP with [Content_Types].xml inside
    # We first check the ZIP magic, then inspect the zip contents below.
    (0, b"PK\x03\x04",                   "_zip"),   # resolved further below
    # Legacy OLE compound document (doc, xls): D0 CF 11 E0
    (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "word"),  # .doc
    # HTML: check for common ASCII openers (after stripping BOM / whitespace)
    # These are checked as text patterns, handled separately below.
]

# OOXML content-type strings that identify the format inside a ZIP
_OOXML_WORD  = b"wordprocessingml"
_OOXML_EXCEL = b"spreadsheetml"

# Bytes we read for content sniffing
_SNIFF_BYTES = 8192


def detect_format(file_path: str | Path) -> str | None:
    """
    Return the ExplainPhish format key ('pdf', 'word', 'excel', 'html')
    by reading the file's magic bytes and (for ZIP containers) its internal
    content-type declarations.

    Returns None if the format cannot be determined.
    """
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {path}")

    with open(path, "rb") as fh:
        header = fh.read(_SNIFF_BYTES)

    # ── 1. PDF ──────────────────────────────────────────────────────────────
    if header[:4] == b"%PDF":
        return "pdf"

    # ── 2. ZIP container (OOXML: docx / xlsx / xlsb) ────────────────────────
    if header[:4] == b"PK\x03\x04":
        return _resolve_zip_format(path, header)

    # ── 3. Legacy OLE (doc / xls) ────────────────────────────────────────────
    if header[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        # heuristic: try oletools / olefile to distinguish doc vs xls;
        # if unavailable, default to 'word' (more common in phishing datasets).
        return _resolve_ole_format(path)

    # ── 4. HTML (text-based) ─────────────────────────────────────────────────
    if _looks_like_html(header):
        return "html"

    return None   # unknown


# ─── helpers ──────────────────────────────────────────────────────────────────

def _resolve_zip_format(path: Path, header: bytes) -> str | None:
    """Peek inside the ZIP to find the OOXML content-type marker."""
    import zipfile

    # Fast path: look for word/excel markers in the raw ZIP bytes already read.
    if _OOXML_WORD in header:
        return "word"
    if _OOXML_EXCEL in header:
        return "excel"

    # Full scan of the ZIP central directory.
    try:
        with zipfile.ZipFile(path, "r") as zf:
            names = zf.namelist()
            # content_types file is always present in OOXML
            if "[Content_Types].xml" in names:
                ct_data = zf.read("[Content_Types].xml")
                if _OOXML_WORD in ct_data:
                    return "word"
                if _OOXML_EXCEL in ct_data:
                    return "excel"
            # Fallback: look for characteristic top-level folders
            if any(n.startswith("word/") for n in names):
                return "word"
            if any(n.startswith("xl/") for n in names):
                return "excel"
    except (zipfile.BadZipFile, Exception):
        pass

    return None   # ZIP but not a recognised OOXML format


def _resolve_ole_format(path: Path) -> str:
    """Try to distinguish .doc from .xls inside an OLE container."""
    try:
        import olefile
        with olefile.OleFileIO(path) as ole:
            streams = [s[0] for s in ole.listdir()]
            if "Workbook" in streams or "Book" in streams:
                return "excel"
            if "WordDocument" in streams:
                return "word"
    except Exception:
        pass
    return "word"   # safe default for phishing: .doc is far more common


def _looks_like_html(header: bytes) -> bool:
    """Check if the first non-whitespace content looks like an HTML document."""
    # Strip UTF-8 / UTF-16 BOM if present
    for bom in (b"\xef\xbb\xbf", b"\xff\xfe", b"\xfe\xff"):
        if header.startswith(bom):
            header = header[len(bom):]

    text = header.lstrip().lower()
    html_markers = (
        b"<!doctype html",
        b"<html",
        b"<head",
        b"<body",
        b"<script",
        b"<meta",
    )
    return any(text.startswith(m) for m in html_markers)
