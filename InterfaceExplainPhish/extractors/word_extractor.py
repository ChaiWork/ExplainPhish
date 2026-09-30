"""
Word static feature extractor.

Extracts the 43 static features matching models/word/selected_features.json.
Supports: .docx  .docm  .dotx  .dotm  .doc  .dot
Dependencies: optional olefile, oletools for legacy .doc and deep VBA analysis
"""
from __future__ import annotations

import math
import os
import re
import zipfile
from collections import Counter
from pathlib import Path

try:
    from .base import ExtractionError, check_file_safety
except ImportError:
    from extractors.base import ExtractionError, check_file_safety

try:
    from oletools.olevba import VBA_Parser
    HAVE_OLEVBA = True
except Exception:
    HAVE_OLEVBA = False

try:
    import olefile
    HAVE_OLEFILE = True
except Exception:
    HAVE_OLEFILE = False

FEATURE_ORDER = [
    "ole_object_count",
    "ole_object_type_count",
    "macro_present",
    "dde_present",
    "vba_keywords_count",
    "entropy",
    "struct_ContentType",
    "struct_PartName",
    "file_size",
    "struct_pos",
    "struct_val",
    "struct_typeface",
    "struct_script",
    "path_/w-p",
    "path_w-r",
    "path_/w-r",
    "path_a-hlink",
    "path_w-p",
    "path_a-accent3",
    "struct_ang",
    "path_/a-effectLst",
    "path_a-themeElements",
    "struct_dist",
    "path_a-alpha",
    "struct_Extension",
    "path_a-dk1",
    "path_a-ln",
    "path_/a-accent6",
    "struct_w",
    "struct_name",
    "path_a-lt2",
    "path_/a-outerShdw",
    "path_a-accent4",
    "path_/a-dk1",
    "path_a-accent1",
    "path_a-sysClr",
    "path_a-lt1",
    "path_/a-accent4",
    "struct_{http://schemas.openxmlformats.org/wordprocessingml/2006/main}sz",
    "path_a-solidFill",
    "struct_{http://schemas.openxmlformats.org/wordprocessingml/2006/main}themeFill",
    "struct_{http://schemas.openxmlformats.org/wordprocessingml/2006/main}csb1",
    "struct_{http://schemas.openxmlformats.org/wordprocessingml/2006/main}styleId",
]

REQUIRED_KEYS = FEATURE_ORDER


def calculate_entropy(text: str) -> float:
    if not text:
        return 0.0
    probs = [n / len(text) for n in Counter(text).values()]
    return -sum(p * math.log2(p) for p in probs)


def safe_read_zip_entry(z: zipfile.ZipFile, name: str) -> str:
    try:
        with z.open(name) as f:
            return f.read().decode(errors="ignore")
    except Exception:
        return ""


def extract(file_path: str | Path) -> dict:
    path = Path(file_path)
    check_file_safety(path, check_zip_bomb=True)

    feats = {col: 0 for col in FEATURE_ORDER}
    try:
        feats["file_size"] = path.stat().st_size
    except Exception:
        feats["file_size"] = 0

    text_all = ""

    # Case A: OOXML (.docx/.docm/.dotx/.dotm)
    if zipfile.is_zipfile(path):
        try:
            with zipfile.ZipFile(path, "r") as z:
                names = z.namelist()
                for name in names:
                    low = name.lower()
                    for key in FEATURE_ORDER:
                        if key.startswith("path_"):
                            needle = key[5:].lower()
                            if needle and needle in low:
                                feats[key] += 1

                xml_files = [n for n in names if n.lower().endswith(".xml")]
                for n in xml_files:
                    xml_text = safe_read_zip_entry(z, n)
                    if not xml_text:
                        continue
                    text_all += xml_text
                    for key in FEATURE_ORDER:
                        if key.startswith("struct_"):
                            needle = key[7:]
                            if needle:
                                feats[key] += xml_text.count(needle)

                feats["entropy"] = calculate_entropy(text_all)

                ole_like = [n for n in names if "/embeddings/" in n.lower()]
                feats["ole_object_count"] += len(ole_like)
                type_exts = set(os.path.splitext(n)[1].lower() for n in ole_like if os.path.splitext(n)[1])
                feats["ole_object_type_count"] += len(type_exts)

                if HAVE_OLEVBA:
                    vb = VBA_Parser(str(path))
                    try:
                        if vb.detect_vba_macros():
                            feats["macro_present"] = 1
                            vba_text = ""
                            for (_, _, _, vba_code) in vb.extract_macros():
                                if vba_code:
                                    vba_text += vba_code + "\n"
                            if vba_text:
                                feats["vba_keywords_count"] = len(re.findall(
                                    r"\b(CreateObject|Shell|AppActivate|Environ|Execute|FileCopy|Dir|Kill|Put|Get|Open)\b",
                                    vba_text, re.IGNORECASE))
                                feats["dde_present"] = int(("DDEAUTO" in vba_text) or ("DDE" in vba_text))
                    finally:
                        vb.close()
        except Exception:
            pass

    # Case B: Legacy OLE (.doc/.dot)
    elif HAVE_OLEFILE and olefile.isOleFile(str(path)):
        try:
            with olefile.OleFileIO(str(path)) as ole:
                names = ole.listdir(streams=True, storages=True)
                cand = ["/".join(n) for n in names if any(s.lower() in ("objectpool", "ole", "\x01ole") for s in n)]
                feats["ole_object_count"] = len(cand)
                exts = set(os.path.splitext(os.path.basename(n))[1].lower() for n in cand if os.path.splitext(n)[1])
                feats["ole_object_type_count"] = len(exts)
            if HAVE_OLEVBA:
                vb = VBA_Parser(str(path))
                try:
                    if vb.detect_vba_macros():
                        feats["macro_present"] = 1
                        vba_text = ""
                        for (_, _, _, vba_code) in vb.extract_macros():
                            if vba_code:
                                vba_text += vba_code + "\n"
                        if vba_text:
                            feats["vba_keywords_count"] = len(re.findall(
                                r"\b(CreateObject|Shell|AppActivate|Environ|Execute|FileCopy|Dir|Kill|Put|Get|Open)\b",
                                vba_text, re.IGNORECASE))
                            feats["dde_present"] = int(("DDEAUTO" in vba_text) or ("DDE" in vba_text))
                            feats["entropy"] = calculate_entropy(vba_text)
                finally:
                    vb.close()
        except Exception:
            pass

    missing = [k for k in REQUIRED_KEYS if k not in feats]
    if missing:
        raise ExtractionError(f"[word extractor] Missing keys: {missing}")

    return feats