"""
HTML static feature extractor.

Required output keys (must match models/html/selected_features.json):
    url_punct_char_count, external_link_count, embedded_js_count,
    tag_count, whitespace_ratio, internal_link_count, form_count,
    script_entropy, entropy, total_script_characters, min_link_length,
    url_digit_count, html_whitespace_ratio

Dependencies: beautifulsoup4  lxml  (pip install beautifulsoup4 lxml)
"""
from __future__ import annotations

import math
import re
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse

try:
    from .base import ExtractionError, check_file_safety, validate_output
except ImportError:
    from extractors.base import ExtractionError, check_file_safety, validate_output

REQUIRED_KEYS = [
    "url_punct_char_count",
    "external_link_count",
    "embedded_js_count",
    "tag_count",
    "whitespace_ratio",
    "internal_link_count",
    "form_count",
    "script_entropy",
    "entropy",
    "total_script_characters",
    "min_link_length",
    "url_digit_count",
    "html_whitespace_ratio",
]

_PUNCT = re.compile(r"[^\w\s]")


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    probs = [n / len(text) for n in Counter(text).values()]
    return -sum(p * math.log2(p) for p in probs)


def _is_external(href: str) -> bool:
    if not href:
        return False
    try:
        parsed = urlparse(href)
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except Exception:
        # Graceful fallback for malformed URLs (e.g., unmatched brackets raising "Invalid IPv6 URL")
        href_lower = href.strip().lower()
        return href_lower.startswith(("http://", "https://", "//"))


def extract(file_path: str | Path) -> dict:
    path = Path(file_path)
    check_file_safety(path, check_zip_bomb=False)

    try:
        raw = path.read_bytes()
        html_text = raw.decode("utf-8", errors="replace")
    except Exception as exc:
        raise ExtractionError(f"Cannot read HTML file '{path.name}': {exc}") from exc

    try:
        import warnings
        from bs4 import BeautifulSoup, MarkupResemblesLocatorWarning, XMLParsedAsHTMLWarning
        warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)
        warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
        soup = BeautifulSoup(html_text, "lxml")
    except Exception:
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html_text, "html.parser")
        except Exception as exc:
            raise ExtractionError(f"HTML parsing failed: {exc}") from exc

    feat: dict = {k: 0 for k in REQUIRED_KEYS}

    # ── Tags ──────────────────────────────────────────────────────────────────
    all_tags = soup.find_all(True)
    feat["tag_count"] = len(all_tags)

    # ── Links ─────────────────────────────────────────────────────────────────
    all_links = [a.get("href", "") or "" for a in soup.find_all("a", href=True)]
    external = [h for h in all_links if _is_external(h)]
    internal = [h for h in all_links if h and not _is_external(h)]
    feat["external_link_count"] = len(external)
    feat["internal_link_count"] = len(internal)
    feat["min_link_length"]     = min((len(h) for h in all_links if h), default=0)

    all_urls = all_links  # treat hrefs as URLs for the next two metrics
    url_text = " ".join(all_urls)
    feat["url_punct_char_count"] = len(_PUNCT.findall(url_text))
    feat["url_digit_count"]      = sum(c.isdigit() for c in url_text)

    # ── Scripts ───────────────────────────────────────────────────────────────
    scripts = soup.find_all("script")
    inline_scripts = [s.get_text() for s in scripts if not s.get("src")]
    feat["embedded_js_count"]       = len(inline_scripts)
    script_text = " ".join(inline_scripts)
    feat["total_script_characters"] = len(script_text)
    feat["script_entropy"]          = round(_entropy(script_text), 6)

    # ── Forms ─────────────────────────────────────────────────────────────────
    feat["form_count"] = len(soup.find_all("form"))

    # ── Whitespace ratios ─────────────────────────────────────────────────────
    total_chars = len(html_text)
    ws_chars = sum(c.isspace() for c in html_text)
    feat["whitespace_ratio"]      = round(ws_chars / total_chars, 6) if total_chars else 0.0
    feat["html_whitespace_ratio"] = feat["whitespace_ratio"]   # same computation (dataset used both names)

    # ── Overall entropy ───────────────────────────────────────────────────────
    feat["entropy"] = round(_entropy(html_text), 6)

    return validate_output(feat, REQUIRED_KEYS, "html")