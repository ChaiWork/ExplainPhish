"""
BaseExtractor — security guards + contract for all per-format extractors.

Security rules enforced here (applies to every format):
  1. MAX_FILE_SIZE_MB   — reject before opening.
  2. ZIP bomb check     — reject if compressed→uncompressed ratio exceeds limit.
  3. No execution       — never shell-out, never import subprocess for file content.
  4. Read-only          — always open files in binary/read mode.
"""
from __future__ import annotations

import zipfile
from pathlib import Path

# ── tuneable limits ──────────────────────────────────────────────────────────
MAX_FILE_SIZE_MB      = 50          # reject files larger than this
ZIP_BOMB_RATIO        = 100         # compressed:uncompressed expansion limit
ZIP_BOMB_MAX_BYTES    = 500_000_000 # absolute uncompressed ceiling (500 MB)

_BYTES_PER_MB = 1_048_576


class ExtractionError(ValueError):
    """Raised when a file cannot be safely extracted."""


def check_file_safety(path: Path, *, check_zip_bomb: bool = False) -> None:
    """
    Run all security pre-checks.  Raises ExtractionError if a check fails.

    Parameters
    ----------
    path          : Path to the file to check.
    check_zip_bomb: If True, also check ZIP decompression ratio (use for
                    OOXML formats: xlsx, docx, etc.).
    """
    if not path.is_file():
        raise ExtractionError(f"File not found: {path}")

    size_bytes = path.stat().st_size
    size_mb = size_bytes / _BYTES_PER_MB
    if size_mb > MAX_FILE_SIZE_MB:
        raise ExtractionError(
            f"File too large: {size_mb:.1f} MB (limit {MAX_FILE_SIZE_MB} MB). "
            "Reject and ask user to submit a smaller file."
        )

    if check_zip_bomb and zipfile.is_zipfile(path):
        _check_zip_bomb(path, size_bytes)


def _check_zip_bomb(path: Path, compressed_size: int) -> None:
    """Verify the ZIP does not expand beyond safe limits."""
    try:
        with zipfile.ZipFile(path, "r") as zf:
            total_uncompressed = sum(info.file_size for info in zf.infolist())
    except (zipfile.BadZipFile, Exception):
        return   # not a valid zip — let the extractor handle it

    if total_uncompressed > ZIP_BOMB_MAX_BYTES:
        raise ExtractionError(
            f"ZIP bomb rejected: uncompressed size {total_uncompressed / _BYTES_PER_MB:.0f} MB "
            f"exceeds limit {ZIP_BOMB_MAX_BYTES / _BYTES_PER_MB:.0f} MB."
        )

    if compressed_size > 0:
        ratio = total_uncompressed / compressed_size
        if ratio > ZIP_BOMB_RATIO:
            raise ExtractionError(
                f"ZIP bomb rejected: compression ratio {ratio:.0f}x "
                f"exceeds limit {ZIP_BOMB_RATIO}x."
            )


def validate_output(features: dict, required_keys: list[str], fmt: str) -> dict:
    """
    Confirm all required feature keys are present and numeric.
    Raises ExtractionError listing every missing or non-numeric key.

    Call this at the END of every extractor's extract() function.
    """
    missing = [k for k in required_keys if k not in features]
    non_numeric = [k for k in required_keys
                   if k in features and not isinstance(features[k], (int, float))]
    errors = []
    if missing:
        errors.append(f"Missing keys: {missing}")
    if non_numeric:
        errors.append(f"Non-numeric values for: {non_numeric}")
    if errors:
        raise ExtractionError(
            f"[{fmt} extractor] Output validation failed — " + "; ".join(errors)
        )
    return {k: features[k] for k in required_keys}   # return only the required subset