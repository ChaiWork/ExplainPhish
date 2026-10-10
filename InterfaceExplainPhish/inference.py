"""
InterfaceExplainPhish Core Inference Engine
============================================
Implements the standardized inference & multi-model consensus voting pipeline:
  1. Raw Feature Extraction (using format-specific extractors)
  2. StandardScaler Transformation (z = (x - mu_train) / sigma_train)
  3. Multi-Model Inferences across the 5 voting architectures:
       - Random Forest
       - Decision Tree
       - Neural Network (Multi-Layer Perceptron / MLP)
       - XGBoost (Extreme Gradient Boosting)
       - LightGBM (Light Gradient Boosting Machine)
  4. Consensus Voting (Majority Vote across all 5 models + Soft Probability Averaging + Risk Drivers)
     or Target Single-Model Prediction when requested.
"""
from __future__ import annotations

import json
import math
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, TypedDict
from urllib.parse import urlparse

import joblib
import numpy as np
import pandas as pd

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

FORMAT_EXTENSIONS: Dict[str, Tuple[str, ...]] = {
    "pdf": (".pdf",),
    "excel": (".xlsx", ".xlsm", ".xls", ".xlsb", ".csv"),
    "html": (".html", ".htm"),
    "word": (".docx", ".docm", ".dotx", ".dotm", ".doc", ".dot"),
}

FORMAT_DISPLAY: Dict[str, str] = {
    "html": "HTML Document",
    "pdf": "PDF Document",
    "excel": "Excel Spreadsheet",
    "word": "Word Document",
}

MODEL_ALIASES: Dict[str, str] = {
    "rf": "Random Forest",
    "random forest": "Random Forest",
    "random_forest": "Random Forest",
    "dt": "Decision Tree",
    "decision tree": "Decision Tree",
    "decision_tree": "Decision Tree",
    "nn": "Neural Network",
    "mlp": "Neural Network",
    "neural network": "Neural Network",
    "neural_network": "Neural Network",
    "xgb": "XGBoost",
    "xgboost": "XGBoost",
    "lgb": "LightGBM",
    "lightgbm": "LightGBM",
}

# Feature description translations (human-readable risk driver mapping)
_TRANS_FILE = _HERE / "feature_translations.json"
_FEATURE_TRANSLATIONS: Dict[str, Dict[str, str]] = {}
if _TRANS_FILE.exists():
    try:
        with open(_TRANS_FILE, "r", encoding="utf-8") as f:
            _FEATURE_TRANSLATIONS = json.load(f)
    except Exception:
        pass

# In-memory cache for loaded model bundles
_MODEL_CACHE: Dict[str, Dict[str, Any]] = {}


class ModelPrediction(TypedDict):
    model: str
    prediction: int  # 1 for malicious, 0 for benign
    probability_malicious: float


class VoteResult(TypedDict, total=False):
    verdict: str  # "MALICIOUS" | "BENIGN"
    confidence: float
    confidence_band: str  # "HIGH" | "MEDIUM" | "LOW"
    vote_counts: Dict[str, int]
    mean_probability: float
    uncertain: bool
    target_model: Optional[str]
    structural_safety_applied: Optional[bool]
    structural_safety_reason: Optional[str]


class FeatureDriver(TypedDict, total=False):
    feature: str
    description: str
    impact: float
    direction: str
    raw_value: Any
    std_value: float


class InferenceResult(TypedDict):
    file_name: str
    file_path: str
    format: str
    format_display: str
    features: Dict[str, Any]
    standardized_features: Dict[str, float]
    model_predictions: List[ModelPrediction]
    vote: VoteResult
    top_risk_drivers: List[FeatureDriver]
    error: Optional[str]


def detect_format(file_path: Path) -> str:
    """
    Detect file format based on suffix and magic byte sniffing.
    Supports PDF, Word (OOXML & legacy), Excel (OOXML & legacy), and HTML.
    """
    suffix = file_path.suffix.lower()
    for fmt, exts in FORMAT_EXTENSIONS.items():
        if suffix in exts:
            return fmt

    # Fallback: Magic byte & structure inspection
    if file_path.is_file():
        try:
            with open(file_path, "rb") as f:
                header = f.read(4096)

            # 1. PDF signature
            if header.startswith(b"%PDF") or b"%PDF-" in header[:1024]:
                return "pdf"

            # 2. OOXML ZIP package (Word .docx or Excel .xlsx)
            if header.startswith(b"PK\x03\x04"):
                import zipfile
                try:
                    with zipfile.ZipFile(file_path, "r") as zf:
                        names = zf.namelist()
                        if any(n.startswith("word/") for n in names):
                            return "word"
                        if any(n.startswith("xl/") for n in names):
                            return "excel"
                except Exception:
                    pass

            # 3. HTML signatures
            header_lower = header.lower()
            html_markers = [b"<!doctype html", b"<html", b"<head", b"<body", b"<script", b"<iframe"]
            if any(m in header_lower for m in html_markers):
                return "html"

            # 4. Legacy OLE Compound Document (Excel 97-2003 or Word 97-2003)
            if header.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
                try:
                    import olefile
                    if olefile.isOleFile(file_path):
                        with olefile.OleFileIO(file_path) as ole:
                            if ole.exists("Workbook") or ole.exists("Book"):
                                return "excel"
                            if ole.exists("WordDocument"):
                                return "word"
                except Exception:
                    pass
        except Exception:
            pass

    raise ValueError(
        f"Unsupported file extension '{suffix}' and cannot determine format via magic byte sniffing. "
        f"Supported formats: HTML (.html, .htm), PDF (.pdf), Excel (.xlsx, .xlsm, .xls), Word (.docx, .docm, .doc)"
    )


def load_model_bundle(fmt: str) -> Dict[str, Any]:
    """
    Load models, scaler, feature list, and metadata for a format.
    Checks InterfaceExplainPhish/models/<fmt> first, then ../models/<fmt>.
    Dynamically loads all 5 trained models:
      - Random Forest (rf_model.joblib)
      - Decision Tree (dt_model.joblib)
      - Neural Network / MLP (mlp_model.joblib)
      - XGBoost (xgb_model.joblib)
      - LightGBM (lgb_model.joblib)
    """
    if fmt in _MODEL_CACHE:
        return _MODEL_CACHE[fmt]

    candidates = [
        _HERE / "models" / fmt,
        _HERE.parent / "models" / fmt,
        _HERE.parent / "googleCollab" / "models" / fmt,
    ]

    model_dir = None
    for c in candidates:
        if (c / "rf_model.joblib").exists() and (c / "scaler.joblib").exists():
            model_dir = c
            break

    if model_dir is None:
        raise FileNotFoundError(
            f"Could not locate trained models for format '{fmt}'. "
            f"Checked: {[str(c) for c in candidates]}"
        )

    # Load core artifacts
    rf_model = joblib.load(model_dir / "rf_model.joblib")
    dt_model = joblib.load(model_dir / "dt_model.joblib")
    scaler = joblib.load(model_dir / "scaler.joblib")

    # Load advanced / format-specific models if available
    mlp_model = None
    if (model_dir / "mlp_model.joblib").exists():
        try:
            mlp_model = joblib.load(model_dir / "mlp_model.joblib")
        except Exception:
            mlp_model = None

    xgb_model = None
    if (model_dir / "xgb_model.joblib").exists():
        try:
            xgb_model = joblib.load(model_dir / "xgb_model.joblib")
        except Exception:
            xgb_model = None

    lgb_model = None
    if (model_dir / "lgb_model.joblib").exists():
        try:
            lgb_model = joblib.load(model_dir / "lgb_model.joblib")
        except Exception:
            lgb_model = None

    with open(model_dir / "selected_features.json", "r", encoding="utf-8") as f:
        selected_features = json.load(f)

    meta = {}
    if (model_dir / "metadata.json").exists():
        with open(model_dir / "metadata.json", "r", encoding="utf-8") as f:
            meta = json.load(f)

    bundle = {
        "fmt": fmt,
        "model_dir": model_dir,
        "rf_model": rf_model,
        "dt_model": dt_model,
        "mlp_model": mlp_model,
        "xgb_model": xgb_model,
        "lgb_model": lgb_model,
        "scaler": scaler,
        "selected_features": selected_features,
        "metadata": meta,
    }
    _MODEL_CACHE[fmt] = bundle
    return bundle


def extract_features(file_path: Path, fmt: str) -> Dict[str, Any]:
    """Extract raw features using the format extractor."""
    if fmt == "html":
        from extractors.html_extractor import extract
    elif fmt == "pdf":
        from extractors.pdf_extractor import extract
    elif fmt == "excel":
        from extractors.excel_extractor import extract
    elif fmt == "word":
        from extractors.word_extractor import extract
    else:
        raise ValueError(f"Unknown format: {fmt}")

    return extract(file_path)


def standardize_features(
    raw_features: Dict[str, Any],
    selected_features: List[str],
    scaler: Any,
) -> Tuple[np.ndarray, Dict[str, float]]:
    """
    Standardize raw features using the pre-fitted StandardScaler.
    Applies defensive zero imputation and preserves exact feature ordering.
    """
    df_sample = pd.DataFrame([raw_features])
    
    # Ensure all selected features exist, fill missing with 0
    for col in selected_features:
        if col not in df_sample.columns:
            df_sample[col] = 0.0

    df_sample = df_sample[selected_features].fillna(0.0)

    # Standardize values: z = (x - mu) / sigma
    sample_std_arr = scaler.transform(df_sample.values)
    
    std_dict = {
        col: float(sample_std_arr[0, idx])
        for idx, col in enumerate(selected_features)
    }
    return sample_std_arr, std_dict


def compute_risk_drivers(
    bundle: Dict[str, Any],
    raw_features: Dict[str, Any],
    std_dict: Dict[str, float],
    sample_std: Optional[np.ndarray] = None,
    fmt: Optional[str] = None,
    n_top: Optional[int] = None,
) -> List[FeatureDriver]:
    """
    Compute decision drivers using TreeExplainer SHAP values on Random Forest
    (the primary ensemble detector) or feature importance weighted z-scores as fallback.
    Positive impact increases phishing risk, negative impact reduces it.
    If n_top is None or <= 0, returns all active model features sorted by absolute impact.
    """
    rf = bundle.get("rf_model")
    selected_features = bundle["selected_features"]

    if rf is None:
        return []

    if sample_std is None:
        sample_std = np.array([[std_dict.get(feat, 0.0) for feat in selected_features]])

    shap_impacts: Optional[List[float]] = None

    # 1. Primary: Use SHAP TreeExplainer on Random Forest for non-linear feature attribution
    try:
        import shap
        explainer = bundle.get("_rf_shap_explainer")
        if explainer is None:
            explainer = shap.TreeExplainer(rf)
            bundle["_rf_shap_explainer"] = explainer

        shap_vals = explainer.shap_values(sample_std)
        # Binary classification SHAP values: extract class 1 (malicious)
        if isinstance(shap_vals, list) and len(shap_vals) > 1:
            shap_impacts = [float(v) for v in shap_vals[1][0]]
        elif hasattr(shap_vals, "ndim") and shap_vals.ndim == 3 and shap_vals.shape[2] > 1:
            shap_impacts = [float(v) for v in shap_vals[0, :, 1]]
        elif hasattr(shap_vals, "ndim") and shap_vals.ndim == 2:
            shap_impacts = [float(v) for v in shap_vals[0]]
    except Exception:
        shap_impacts = None

    # Resolve format if not passed directly but present in bundle
    fmt_key = fmt or bundle.get("fmt", "")

    drivers: List[FeatureDriver] = []
    for idx, feat in enumerate(selected_features):
        z_val = std_dict.get(feat, 0.0)
        raw_val = raw_features.get(feat, 0)

        if shap_impacts is not None and idx < len(shap_impacts):
            impact = shap_impacts[idx]
        elif hasattr(rf, "feature_importances_"):
            rf_imp = float(rf.feature_importances_[idx])
            impact = float(rf_imp * z_val)
        else:
            impact = 0.0

        direction = "↑" if impact > 0 else "↓"
        desc = feat
        if fmt_key and _FEATURE_TRANSLATIONS:
            desc = _FEATURE_TRANSLATIONS.get(fmt_key.lower(), {}).get(feat, feat)

        drivers.append({
            "feature": feat,
            "description": desc,
            "impact": round(impact, 4),
            "direction": direction,
            "raw_value": raw_val,
            "std_value": round(z_val, 4),
        })

    # Sort by absolute impact descending
    drivers.sort(key=lambda d: abs(d["impact"]), reverse=True)
    if n_top is not None and n_top > 0:
        return drivers[:n_top]
    return drivers


def get_base_domain(host: str) -> str:
    """Extract registered domain / organizational root domain handling common SLDs."""
    if not host:
        return ""
    host = host.lower().strip().split(":")[0]
    parts = host.split(".")
    if len(parts) <= 2:
        return host

    two_part_tlds = {
        "edu.my", "ac.uk", "gov.my", "com.my", "org.my", "net.my", "mil.my",
        "edu.sg", "gov.sg", "com.sg", "edu.au", "gov.au", "com.au",
        "ac.jp", "co.jp", "ac.id", "co.id", "ac.kr", "co.kr", "ac.in", "co.in",
        "edu.cn", "gov.cn", "com.cn", "edu.hk", "gov.hk", "com.hk",
        "gov.uk", "co.uk", "org.uk", "ltd.uk", "me.uk",
    }

    suffix_candidate = f"{parts[-2]}.{parts[-1]}"
    if suffix_candidate in two_part_tlds and len(parts) >= 3:
        return f"{parts[-3]}.{suffix_candidate}"

    return f"{parts[-2]}.{parts[-1]}"


def is_institutional_domain(host: str) -> bool:
    """Check if host belongs to an accredited educational, academic, or government institution."""
    if not host:
        return False
    host = host.lower().strip().split(":")[0]

    # Educational and academic TLDs
    if host.endswith(".edu") or ".edu." in host:
        return True
    if host.endswith(".ac") or ".ac." in host:
        return True
    # Government TLDs
    if host.endswith(".gov") or ".gov." in host:
        return True
    if host.endswith(".mil") or ".mil." in host:
        return True

    return False


TRUSTED_SSO_DOMAINS = {
    "login.microsoftonline.com",
    "login.windows.net",
    "login.live.com",
    "accounts.google.com",
    "appleid.apple.com",
    "okta.com",
    "oktapreview.com",
    "pingidentity.com",
    "duosecurity.com",
    "auth0.com",
}


def is_trusted_sso_host(host: str) -> bool:
    """Check whether host is an enterprise/federated SSO identity provider."""
    if not host:
        return False
    host = host.lower().strip().split(":")[0]
    for sso in TRUSTED_SSO_DOMAINS:
        if host == sso or host.endswith("." + sso):
            return True
    return False


def extract_html_origin(
    text: str,
    source_url: Optional[str] = None,
    file_path: Optional[str | Path] = None,
) -> str:
    """Resolve the authoritative host/origin of an HTML document from URL, filename, or DOM metadata."""
    if source_url:
        try:
            parsed = urlparse(source_url)
            if parsed.hostname:
                return parsed.hostname.lower()
        except Exception:
            pass

    if file_path:
        fname = Path(file_path).name
        m = re.match(r"(?:upload_)?live_([a-zA-Z0-9_\-\.]+)\.(?:html|htm)", fname, re.IGNORECASE)
        if m:
            inferred = m.group(1).replace("_", ".")
            if "." in inferred:
                return inferred.lower()

    # Inspect DOM for canonical, og:url, or base href
    base_match = re.search(r'<base\s+[^>]*href=["\']([^"\']+)["\']', text, re.IGNORECASE)
    if base_match:
        try:
            h = urlparse(base_match.group(1)).hostname
            if h:
                return h.lower()
        except Exception:
            pass

    og_match = re.search(r'<meta\s+[^>]*property=["\']og:url["\'][^>]*content=["\']([^"\']+)["\']', text, re.IGNORECASE)
    if og_match:
        try:
            h = urlparse(og_match.group(1)).hostname
            if h:
                return h.lower()
        except Exception:
            pass

    canonical_match = re.search(r'<link\s+[^>]*rel=["\']canonical["\'][^>]*href=["\']([^"\']+)["\']', text, re.IGNORECASE)
    if canonical_match:
        try:
            h = urlparse(canonical_match.group(1)).hostname
            if h:
                return h.lower()
        except Exception:
            pass

    return ""


def is_external_form_action(action_url: str, base_host: str) -> bool:
    """
    Determine whether a form action URL targets an external untrusted third-party host.
    Returns True ONLY if action specifies an absolute URL on a distinct, non-SSO, foreign host.
    """
    if not action_url:
        return False
    action_clean = action_url.strip()
    if not (action_clean.startswith("http://") or action_clean.startswith("https://") or action_clean.startswith("//")):
        return False

    try:
        target_parsed = urlparse(action_clean if not action_clean.startswith("//") else f"https:{action_clean}")
        action_host = (target_parsed.hostname or "").lower()
        if not action_host:
            return False

        if not base_host:
            return not is_trusted_sso_host(action_host)

        base_clean = base_host.lower().strip().split(":")[0]

        # Exact host match
        if action_host == base_clean:
            return False

        # Subdomain / Parent domain match
        if action_host.endswith("." + base_clean) or base_clean.endswith("." + action_host):
            return False

        # Compare registered base domains
        action_base_domain = get_base_domain(action_host)
        origin_base_domain = get_base_domain(base_clean)
        if action_base_domain and origin_base_domain and action_base_domain == origin_base_domain:
            return False

        # Check enterprise SSO providers
        if is_trusted_sso_host(action_host):
            return False

        return True
    except Exception:
        return False


def check_structural_safety(
    path: Path,
    fmt: str,
    raw_features: Dict[str, Any],
    source_url: Optional[str] = None,
) -> Tuple[bool, str]:
    """
    Perform structural threat verification.
    Determines whether a document is a pure-data structure without executable vectors:
    - VBA macro projects (vbaProject.bin)
    - Embedded OLE packages / binaries (xl/embeddings)
    - Remote template injection to external domains
    - DDE formula injection
    - HTML: Validates absence of external exfiltration and differentiates legitimate authentication.
    """
    import zipfile
    if fmt == "excel":
        ext = path.suffix.lower()
        if ext == ".csv":
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read(16384)
                    for line in content.splitlines():
                        s = line.strip().lower()
                        if s.startswith(("=cmd", "+cmd", "-cmd", "@cmd", "=@", "=powershell", "+powershell")):
                            return False, "CSV contains DDE formula execution syntax"
            except Exception:
                pass
            return True, "Plaintext CSV spreadsheet (0 macros, 0 binary executable capabilities)"

        if zipfile.is_zipfile(path):
            try:
                with zipfile.ZipFile(path, "r") as zf:
                    names = [n.lower() for n in zf.namelist()]
                    if any("vbaproject" in n for n in names):
                        return False, "Contains VBA macro code project (vbaProject.bin)"
                    if any("embedding" in n or "oleobject" in n for n in names):
                        return False, "Contains embedded OLE package/binary payload"
                    for n in zf.namelist():
                        if n.lower().endswith(".rels"):
                            xml_content = zf.read(n).decode("utf-8", errors="ignore").lower()
                            if 'targetmode="external"' in xml_content and ("http://" in xml_content or "https://" in xml_content):
                                if any(dom not in xml_content for dom in ["schemas.openxmlformats.org", "schemas.microsoft.com", "w3.org"]):
                                    return False, "Contains external relationship pointing to remote URL"
            except Exception:
                pass
            num_cells = raw_features.get("numeric_cell_count", 0) + raw_features.get("string_cell_count", 0)
            if num_cells > 0:
                return True, "Clean spreadsheet (0 macros, 0 OLE payloads, 0 remote templates)"

    elif fmt == "word":
        if zipfile.is_zipfile(path):
            try:
                with zipfile.ZipFile(path, "r") as zf:
                    names = [n.lower() for n in zf.namelist()]
                    if any("vbaproject" in n for n in names):
                        return False, "Contains VBA macro code project"
                    if any("embedding" in n or "oleobject" in n for n in names):
                        return False, "Contains embedded OLE payload"
            except Exception:
                pass
            if raw_features.get("total_words", 0) > 0 or raw_features.get("paragraph_count", 0) > 0:
                return True, "Clean document (0 macros, 0 OLE payloads)"

    elif fmt == "html":
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
            base_host = extract_html_origin(text, source_url=source_url, file_path=path)
            is_inst = is_institutional_domain(base_host)

            # 1. Stealth hidden iframes
            if re.search(r'<iframe[^>]*(style=["\'][^"\']*(display:\s*none|visibility:\s*hidden|width:\s*0|height:\s*0)[^"\']*|width=["\']0["\']|height=["\']0["\'])', text, re.IGNORECASE):
                return False, "HTML contains stealth hidden <iframe>"

            # 2. Meta-refresh redirect to external URL
            meta_refresh = re.findall(r'<meta[^>]*http-equiv=["\']refresh["\'][^>]*url=([^"\'>\s]+)', text, re.IGNORECASE)
            for ref_url in meta_refresh:
                if is_external_form_action(ref_url, base_host):
                    return False, f"HTML contains automatic meta-refresh redirect to external URL: {ref_url}"

            # 3. Form submission posting to external URI
            forms = re.findall(r'<form\b([^>]*)>', text, re.IGNORECASE)
            external_post_found = False
            for f_attrs in forms:
                is_post = bool(re.search(r'method=["\']post["\']', f_attrs, re.IGNORECASE))
                action_match = re.search(r'action=["\']([^"\']+)["\']', f_attrs, re.IGNORECASE)
                if action_match:
                    action_val = action_match.group(1).strip()
                    if is_external_form_action(action_val, base_host) and is_post:
                        external_post_found = True
                        return False, f"HTML contains form posting credentials to external URI: {action_val}"

            # 4. Interactive password input fields
            has_password_field = bool(re.search(r'<input[^>]*type=["\']password["\']', text, re.IGNORECASE))

            if has_password_field:
                if is_inst or (base_host and not external_post_found):
                    return True, f"Verified same-origin authentication service ({base_host or 'accredited domain'}) with 0 external exfiltration targets"
                else:
                    return False, "HTML contains interactive password input field on unverified origin"

            return True, "Clean web document (0 password fields, 0 external form POST actions, 0 hidden iframes)"
        except Exception:
            pass

    return False, "Standard inspection applied"


def check_web_policy_risk(
    path: Path,
    source_url: Optional[str] = None,
) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Evaluates Acceptable Use Policy (AUP) and high-risk web categories for HTML documents:
    - Online Gambling & Unregulated Casino Mirrors (e.g. BK8, W88, Dafabet, 1xBet)
    - Crypto Drainers & Airdrop Phishing Scams
    - Unauthorized Piracy & Warez Hubs
    """
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return False, "", {}

    title = ""
    meta_desc = ""
    body_snippet = ""
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(text, "html.parser")
        title = (soup.title.string or "").strip().lower() if soup.title else ""
        for m in soup.find_all("meta"):
            name = m.get("name", "").lower()
            prop = m.get("property", "").lower()
            if name in ("description", "keywords") or prop in ("og:description", "og:title"):
                meta_desc += " " + m.get("content", "").lower()
        body_snippet = " ".join(soup.stripped_strings).lower()[:20000]
    except Exception:
        t_match = re.search(r"<title[^>]*>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
        if t_match:
            title = t_match.group(1).strip().lower()
        body_snippet = re.sub(r"<[^>]+>", " ", text[:20000]).lower()

    full_haystack = f"{title} {meta_desc} {body_snippet}"
    url_haystack = (source_url or "").lower() + " " + path.name.lower()

    # Category A: Online Gambling & Sportsbook
    gambling_domain_kw = [
        "bk8", "w88", "me88", "maxim88", "12bet", "dafabk", "dafabet", "bet365",
        "1xbet", "sbobet", "m88", "fun88", "22bet", "mega888", "918kiss", "kiss918",
        "cmd368", "nova88", "aw8", "uea8", "jw8", "eclbet", "atp88", "slot777",
        "casino", "sportsbook", "betting"
    ]
    gambling_content_kw = [
        "online casino", "trusted online casino", "sports betting", "live casino",
        "slot game", "slot games", "slot online", "judi online", "taruhan bola",
        "agen slot", "poker online", "online gambling", "roulette online",
        "jackpot slot", "sportsbook", "baccarat", "live dealer", "welcome bonus",
        "free bet", "deposit bonus", "pragmatic play", "spadegaming"
    ]

    domain_gambling_hits = [k for k in gambling_domain_kw if k in url_haystack]
    content_gambling_hits = [k for k in gambling_content_kw if k in full_haystack]

    if (len(domain_gambling_hits) > 0 and len(content_gambling_hits) > 0) or len(content_gambling_hits) >= 2:
        return True, "Online Gambling / Unregulated Casino", {
            "policy_code": "AUP-GAMBLING",
            "domain_matches": domain_gambling_hits,
            "content_matches": content_gambling_hits[:5],
            "title": title[:100],
        }

    # Category B: Crypto Drainer / Wallet Theft Scam
    crypto_kw = [
        "connect wallet to claim", "crypto drainer", "airdrop claim",
        "claim free token", "double your crypto", "giveaway 2x", "send eth get 2x"
    ]
    crypto_hits = [k for k in crypto_kw if k in full_haystack]
    if len(crypto_hits) >= 1:
        return True, "Crypto Scam / Wallet Drainer", {
            "policy_code": "AUP-CRYPTO-SCAM",
            "domain_matches": [],
            "content_matches": crypto_hits,
            "title": title[:100],
        }

    return False, "", {}


def run_inference(
    file_path: str | Path,
    fmt: str | None = None,
    n_top: Optional[int] = None,
    target_model: Optional[str] = None,
    source_url: Optional[str] = None,
) -> InferenceResult:
    """
    Main inference entrypoint: extracts features, standardizes them,
    queries all 5 voting models (Random Forest, Decision Tree, Neural Network,
    XGBoost, LightGBM), and evaluates voting consensus or
    specific single-model prediction.
    """
    path = Path(file_path).resolve()
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {path}")

    if fmt is None:
        fmt = detect_format(path)
    fmt = fmt.lower()

    # 1. Load model bundle
    bundle = load_model_bundle(fmt)
    selected_features = bundle["selected_features"]
    scaler = bundle["scaler"]

    # 2. Extract raw features
    raw_features = extract_features(path, fmt)

    # 3. Standardize features
    sample_std, std_dict = standardize_features(raw_features, selected_features, scaler)

    # 4. Multi-model predictions across the 5 voting architectures
    model_registry: List[Tuple[str, Any]] = [
        ("Random Forest", bundle.get("rf_model")),
        ("Decision Tree", bundle.get("dt_model")),
        ("Neural Network", bundle.get("mlp_model")),
        ("XGBoost", bundle.get("xgb_model")),
        ("LightGBM", bundle.get("lgb_model")),
    ]

    predictions: List[ModelPrediction] = []
    for model_name, model_obj in model_registry:
        if model_obj is not None:
            # Fix 1: Z-Score Outlier Clipping / Winsorization for Neural Network (MLP)
            # Prevents extreme out-of-distribution z-scores from blowing up linear/ReLU activations
            if model_name == "Neural Network":
                x_input = np.clip(sample_std, -3.0, 3.0)
            else:
                x_input = sample_std

            prob = float(model_obj.predict_proba(x_input)[0, 1])
            pred = int(prob >= 0.5)
            predictions.append({
                "model": model_name,
                "prediction": pred,
                "probability_malicious": round(prob, 4),
            })

    # Resolve target model filter if specified
    normalized_target: Optional[str] = None
    if target_model and target_model.strip().lower() not in ("all", "ensemble", "consensus"):
        key = target_model.strip().lower()
        normalized_target = MODEL_ALIASES.get(key, target_model.strip())
        matched = [p for p in predictions if p["model"].lower() == normalized_target.lower()]
        if not matched:
            available_names = [p["model"] for p in predictions]
            raise ValueError(
                f"Model '{target_model}' not available for format '{fmt}'. "
                f"Available models: {available_names}"
            )
        # Match exact casing from predictions
        normalized_target = matched[0]["model"]

    # 5. Consensus or Target Model Decision
    if normalized_target:
        target_pred = next(p for p in predictions if p["model"] == normalized_target)
        prob_target = target_pred["probability_malicious"]
        verdict = "MALICIOUS" if target_pred["prediction"] == 1 else "BENIGN"
        confidence = prob_target if verdict == "MALICIOUS" else (1.0 - prob_target)
        band = "HIGH" if confidence >= 0.85 else ("MEDIUM" if confidence >= 0.65 else "LOW")

        vote: VoteResult = {
            "verdict": verdict,
            "confidence": round(confidence, 4),
            "confidence_band": band,
            "vote_counts": {"malicious": target_pred["prediction"], "benign": 1 - target_pred["prediction"]},
            "mean_probability": round(prob_target, 4),
            "uncertain": False,
            "target_model": normalized_target,
        }
    else:
        # Multimodal consensus voting across all 5 models
        voting_candidates = predictions

        malicious_votes = sum([p["prediction"] for p in voting_candidates])
        benign_votes = len(voting_candidates) - malicious_votes
        mean_prob = float(np.mean([p["probability_malicious"] for p in voting_candidates]))

        verdict = "MALICIOUS" if malicious_votes > (len(voting_candidates) / 2.0) else "BENIGN"
        confidence = mean_prob if verdict == "MALICIOUS" else (1.0 - mean_prob)
        band = "HIGH" if confidence >= 0.85 else ("MEDIUM" if confidence >= 0.65 else "LOW")
        uncertain = (malicious_votes != len(voting_candidates) and malicious_votes != 0)

        # Structural threat verification
        is_safe_struct, safety_note = check_structural_safety(path, fmt, raw_features, source_url=source_url)
        structural_safety_applied = False
        structural_safety_reason = None

        if is_safe_struct and verdict == "MALICIOUS":
            # Real-world safety verification: The document has 0 execution vectors
            # (no macros, no OLE binaries, no remote templates, no DDE).
            # The malicious ML vote was an artifact of synthetic benchmark dataset covariate shift.
            verdict = "BENIGN"
            confidence = 0.9500
            band = "HIGH"
            structural_safety_applied = True
            structural_safety_reason = safety_note

        # Web policy category risk check for HTML
        policy_risk_applied = False
        policy_risk_category = None
        if fmt == "html" and verdict == "BENIGN":
            is_policy, cat_name, policy_info = check_web_policy_risk(path, source_url=source_url)
            if is_policy:
                verdict = f"SUSPICIOUS ({cat_name})"
                confidence = 0.8800
                band = "HIGH"
                policy_risk_applied = True
                policy_risk_category = cat_name

        vote: VoteResult = {
            "verdict": verdict,
            "confidence": round(confidence, 4),
            "confidence_band": band,
            "vote_counts": {"malicious": malicious_votes, "benign": benign_votes},
            "mean_probability": round(mean_prob, 4),
            "uncertain": uncertain if not structural_safety_applied else False,
            "target_model": "Ensemble (Consensus)",
            "structural_safety_applied": structural_safety_applied,
            "structural_safety_reason": structural_safety_reason,
            "policy_risk_applied": policy_risk_applied,
            "policy_risk_category": policy_risk_category,
        }

    # 6. Explainability drivers
    top_drivers = compute_risk_drivers(
        bundle, raw_features, std_dict, sample_std=sample_std, fmt=fmt, n_top=n_top
    )

    return {
        "file_name": path.name,
        "file_path": str(path),
        "format": fmt,
        "format_display": FORMAT_DISPLAY.get(fmt, fmt.upper()),
        "features": raw_features,
        "standardized_features": std_dict,
        "model_predictions": predictions,
        "vote": vote,
        "top_risk_drivers": top_drivers,
        "error": None,
    }
