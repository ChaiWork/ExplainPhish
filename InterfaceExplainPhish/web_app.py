"""
ExplainPhish Web Workstation Backend (FastAPI)
==============================================
High-performance REST API and web application server serving the
ExplainPhish Autonomous SOC Agent Pipeline.
"""

from __future__ import annotations

import json
import os
import re
import sys
import tempfile
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from langgraph_pipeline import get_explainphish_graph, run_pipeline
from inference import FORMAT_DISPLAY

app = FastAPI(
    title="ExplainPhish SOC Workstation",
    description="Autonomous Cybersecurity Incident Response & Threat Investigation Console",
    version="2.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

STATIC_DIR = _HERE / "web"
DOWNLOADS_DIR = _HERE / "downloads"
DOWNLOADS_DIR.mkdir(parents=True, exist_ok=True)


class URLAnalyzeRequest(BaseModel):
    url: str


class SampleAnalyzeRequest(BaseModel):
    sample_path: str


@app.get("/api/health")
def api_health():
    return {
        "status": "healthy",
        "engine": "ExplainPhish LangGraph SOC Agent",
        "supported_formats": list(FORMAT_DISPLAY.values()),
        "models": ["Random Forest", "Decision Tree", "Neural Network (MLP)", "XGBoost", "LightGBM"],
    }


@app.get("/api/samples")
def api_list_samples():
    """List sample test documents available in downloads/ and Sample/ catalogs."""
    samples = []
    
    # Check downloads directory
    if DOWNLOADS_DIR.exists():
        for f in sorted(DOWNLOADS_DIR.iterdir()):
            if f.is_file() and not f.name.startswith("."):
                samples.append({
                    "id": str(f.resolve()),
                    "name": f.name,
                    "category": "Live Web / Downloaded",
                    "size_bytes": f.stat().st_size,
                    "format": f.suffix.replace(".", "").upper(),
                })

    # Check local Sample catalog if available
    sample_cat = _HERE / "Sample"
    if sample_cat.exists():
        for folder in sorted(sample_cat.iterdir()):
            if folder.is_dir():
                for sf in sorted(folder.iterdir()):
                    if sf.is_file() and not sf.name.startswith("."):
                        samples.append({
                            "id": str(sf.resolve()),
                            "name": sf.name,
                            "category": folder.name,
                            "size_bytes": sf.stat().st_size,
                            "format": sf.suffix.replace(".", "").upper(),
                        })

    return {"samples": samples}


@app.post("/api/analyze/file")
async def api_analyze_file(file: UploadFile = File(...)):
    """Upload and execute full 7-node LangGraph autonomous triage on file."""
    if not file.filename:
        raise HTTPException(status_code=400, detail="Missing filename")

    clean_name = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", file.filename)
    target_path = DOWNLOADS_DIR / f"upload_{clean_name}"

    content = await file.read()
    if len(content) > 50 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="File size exceeds maximum 50MB sandbox limit")

    target_path.write_bytes(content)

    try:
        result = run_pipeline(target_path)
        clean_result = sanitize_result(result)
        return clean_result
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Pipeline error: {str(exc)}")


@app.post("/api/analyze/url")
def api_analyze_url(req: URLAnalyzeRequest):
    """Fetch live web resource and triage through autonomous agent."""
    raw_url = req.url.strip()
    parsed = urlparse(raw_url)
    if not parsed.scheme or not parsed.netloc:
        raise HTTPException(status_code=400, detail="Invalid URL format. Must include http:// or https://")

    # Anti-SSRF check
    hostname = parsed.hostname or ""
    if hostname in ("localhost", "127.0.0.1", "0.0.0.0") or hostname.startswith("192.168.") or hostname.startswith("10."):
        raise HTTPException(status_code=400, detail="Forbidden target: local and internal IP ranges are restricted.")

    req_obj = urllib.request.Request(
        raw_url,
        headers={
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        },
    )

    try:
        with urllib.request.urlopen(req_obj, timeout=15) as resp:
            content = resp.read(15 * 1024 * 1024)
            content_type = resp.headers.get("Content-Type", "")
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Failed to fetch remote URL: {exc}")

    ext = Path(parsed.path).suffix.lower()
    if not ext or ext not in (".html", ".htm", ".pdf", ".xlsx", ".docx"):
        ext = ".pdf" if "pdf" in content_type.lower() else ".html"

    clean_host = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", parsed.netloc)
    target_path = DOWNLOADS_DIR / f"live_{clean_host}{ext}"
    target_path.write_bytes(content)

    try:
        result = run_pipeline(target_path, source_url=raw_url)
        clean_result = sanitize_result(result)
        return clean_result
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Pipeline error: {str(exc)}")


@app.post("/api/analyze/sample")
def api_analyze_sample(req: SampleAnalyzeRequest):
    """Run pipeline on existing sample file from the catalog."""
    path = Path(req.sample_path).resolve()
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Sample file not found on disk")

    try:
        result = run_pipeline(path)
        clean_result = sanitize_result(result)
        return clean_result
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Pipeline error: {str(exc)}")


def sanitize_result(res: Dict[str, Any]) -> Dict[str, Any]:
    """Ensure JSON serializability (convert numpy floats and sanitize keys)."""
    out = {}
    for k, v in res.items():
        if k in ("raw_features", "standardized_features"):
            # Include serialized floats
            out[k] = {str(fk): float(fv) if isinstance(fv, (int, float)) else str(fv) for fk, fv in v.items()}
        else:
            out[k] = v
    return out


# Serve static web frontend
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    @app.get("/")
    def serve_frontend():
        return FileResponse(STATIC_DIR / "index.html")


def main():
    import uvicorn
    port = int(os.environ.get("PORT", 8080))
    print(f"[*] Starting ExplainPhish Web SOC Workstation on http://localhost:{port}")
    uvicorn.run("web_app:app", host="0.0.0.0", port=port, reload=False)


if __name__ == "__main__":
    main()
