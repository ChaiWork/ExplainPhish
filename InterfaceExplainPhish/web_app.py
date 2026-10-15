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
import ssl
import sys
import tempfile
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from langgraph_pipeline import (
    get_explainphish_graph,
    get_pipeline_state,
    resume_pipeline,
    run_pipeline,
)
from inference import FORMAT_DISPLAY
from llm_engine import get_active_provider_config, chat_with_soc_agent
from report_exporter import generate_pdf_report, generate_docx_report

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


@app.middleware("http")
async def add_no_cache_headers(request, call_next):
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


STATIC_DIR = _HERE / "web"
DOWNLOADS_DIR = _HERE / "downloads"
DOWNLOADS_DIR.mkdir(parents=True, exist_ok=True)
_LATEST_INVESTIGATION_STATE: Dict[str, Any] = {}


class URLAnalyzeRequest(BaseModel):
    url: str
    hitl: Optional[bool] = False
    auto_approve: Optional[bool] = False


class SampleAnalyzeRequest(BaseModel):
    sample_path: str
    hitl: Optional[bool] = False
    auto_approve: Optional[bool] = False


class AnalystResumeRequest(BaseModel):
    thread_id: str
    decision: str = "APPROVE"  # "APPROVE" or "OVERRIDE"
    verdict: Optional[str] = None
    threat_level: Optional[str] = None
    notes: Optional[str] = None
    analyst_id: Optional[str] = "SOC-Analyst-Tier2"


class ChatRequest(BaseModel):
    message: str
    state: Optional[Dict[str, Any]] = None
    history: Optional[List[Dict[str, str]]] = None


@app.get("/api/health")
def api_health():
    llm_info = get_active_provider_config()
    return {
        "status": "healthy",
        "engine": "ExplainPhish LangGraph SOC Agent (with Cognitive LLM Triage)",
        "llm_engine": {
            "provider": llm_info["provider"],
            "model": llm_info["model"],
            "mode": llm_info["mode"],
            "status": "Ready",
        },
        "supported_formats": list(FORMAT_DISPLAY.values()),
        "models": ["Random Forest", "Decision Tree", "Neural Network (MLP)", "XGBoost", "LightGBM"],
    }


@app.get("/api/llm/status")
def api_llm_status():
    return get_active_provider_config()


@app.post("/api/chat")
def api_chat(req: ChatRequest):
    """Conversational SOC analyst copilot powered by live LLM or cognitive engine."""
    current_state = req.state or {}
    reply = chat_with_soc_agent(current_state, req.message, history=req.history)
    return {
        "response": reply,
        "provider": get_active_provider_config().get("provider", "ExplainPhish AI"),
    }


@app.post("/api/pipeline/resume")
def api_pipeline_resume(req: AnalystResumeRequest):
    """Resume an interrupted LangGraph triage workflow with analyst approval or verdict override."""
    if not req.thread_id:
        raise HTTPException(status_code=400, detail="Missing required thread_id")
    try:
        result = resume_pipeline(
            thread_id=req.thread_id,
            analyst_decision={
                "decision": req.decision,
                "verdict": req.verdict,
                "threat_level": req.threat_level,
                "notes": req.notes,
                "analyst_id": req.analyst_id or "SOC-Analyst",
            },
        )
        res_clean = sanitize_result(result)
        _LATEST_INVESTIGATION_STATE.clear()
        _LATEST_INVESTIGATION_STATE.update(res_clean)
        return res_clean
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to resume pipeline: {str(exc)}")


@app.get("/api/pipeline/status/{thread_id}")
def api_pipeline_status(thread_id: str):
    """Query state of an active or interrupted LangGraph thread."""
    st = get_pipeline_state(thread_id)
    if not st:
        raise HTTPException(status_code=404, detail=f"Thread '{thread_id}' not found in state store")
    return sanitize_result(st)


async def resolve_export_state(request: Request, thread_id: Optional[str] = None) -> Dict[str, Any]:
    """Safely extracts and resolves investigation state from incoming request body, query params, or in-memory cache."""
    state: Dict[str, Any] = {}

    # 1. Try to read JSON body if POST/PUT
    if request.method in ("POST", "PUT"):
        try:
            body = await request.body()
            if body:
                data = json.loads(body.decode("utf-8", errors="replace"))
                if isinstance(data, dict):
                    state = data.get("state") if isinstance(data.get("state"), dict) else data
                elif isinstance(data, str) and not thread_id:
                    thread_id = data
        except Exception:
            state = {}

    # 2. Check query params or body for thread_id
    tid = thread_id or request.query_params.get("thread_id") or (state.get("thread_id") if isinstance(state, dict) else None)
    if tid:
        pipeline_state = get_pipeline_state(tid)
        if pipeline_state:
            merged = dict(pipeline_state)
            merged.update(state)
            return merged

    # 3. If state is empty or missing key report data, fallback to latest cached state if available
    if not state or not state.get("final_verdict"):
        if _LATEST_INVESTIGATION_STATE:
            merged = dict(_LATEST_INVESTIGATION_STATE)
            merged.update(state)
            return merged

    return state or {}


@app.api_route("/api/export/pdf", methods=["GET", "POST"])
async def api_export_pdf(
    request: Request,
    thread_id: Optional[str] = None,
):
    """Compile and download executive PDF incident report.
    Supports POST (with JSON state body or thread_id) and GET (with ?thread_id=... or latest cached report).
    """
    try:
        state = await resolve_export_state(request, thread_id)
        pdf_bytes = generate_pdf_report(state)
        raw_name = state.get("file_name", "incident")
        clean_name = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", raw_name)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="SOC_Report_{clean_name}.pdf"'},
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"PDF generation error: {str(exc)}")


@app.api_route("/api/export/docx", methods=["GET", "POST"])
async def api_export_docx(
    request: Request,
    thread_id: Optional[str] = None,
):
    """Compile and download executive Microsoft Word (.docx) incident report.
    Supports POST (with JSON state body or thread_id) and GET (with ?thread_id=... or latest cached report).
    """
    try:
        state = await resolve_export_state(request, thread_id)
        docx_bytes = generate_docx_report(state)
        raw_name = state.get("file_name", "incident")
        clean_name = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", raw_name)
        return Response(
            content=docx_bytes,
            media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            headers={"Content-Disposition": f'attachment; filename="SOC_Report_{clean_name}.docx"'},
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"DOCX generation error: {str(exc)}")


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
async def api_analyze_file(
    file: UploadFile = File(...),
    hitl: Optional[bool] = False,
    auto_approve: Optional[bool] = None,
):
    """Upload and execute full LangGraph autonomous triage on file with optional HITL."""
    if not file.filename:
        raise HTTPException(status_code=400, detail="Missing filename")

    clean_name = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", file.filename)
    target_path = DOWNLOADS_DIR / f"upload_{clean_name}"

    content = await file.read()
    if len(content) > 50 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="File size exceeds maximum 50MB sandbox limit")

    target_path.write_bytes(content)

    try:
        is_hitl = bool(hitl)
        should_auto_approve = auto_approve if auto_approve is not None else (not is_hitl)
        result = run_pipeline(
            target_path,
            enable_hitl=is_hitl,
            auto_approve=should_auto_approve,
        )
        clean_result = sanitize_result(result)
        _LATEST_INVESTIGATION_STATE.clear()
        _LATEST_INVESTIGATION_STATE.update(clean_result)
        return clean_result
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Pipeline error: {str(exc)}")


@app.post("/api/analyze/url")
def api_analyze_url(req: URLAnalyzeRequest):
    """Fetch live web resource and triage through autonomous agent."""
    raw_url = req.url.strip()
    if not raw_url.startswith("http://") and not raw_url.startswith("https://"):
        raw_url = "https://" + raw_url

    parsed = urlparse(raw_url)
    if not parsed.scheme or not parsed.netloc:
        raise HTTPException(status_code=400, detail="Invalid URL format. Please provide a valid web domain or URL.")

    # Anti-SSRF check
    hostname = parsed.hostname or ""
    if hostname in ("localhost", "127.0.0.1", "0.0.0.0") or hostname.startswith("192.168.") or hostname.startswith("10."):
        raise HTTPException(status_code=400, detail="Forbidden target: local and internal IP ranges are restricted.")

    req_obj = urllib.request.Request(
        raw_url,
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        },
    )

    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req_obj, timeout=20, context=ctx) as resp:
            content = resp.read(15 * 1024 * 1024)
            content_type = resp.headers.get("Content-Type", "")
    except ssl.SSLError:
        try:
            # Fallback for institutional / educational certificates with intermediate chain issues
            unverified_ctx = ssl._create_unverified_context()
            with urllib.request.urlopen(req_obj, timeout=20, context=unverified_ctx) as resp:
                content = resp.read(15 * 1024 * 1024)
                content_type = resp.headers.get("Content-Type", "")
        except Exception as exc:
            err_msg = str(exc)
            inaccessible = generate_inaccessible_domain_triage(raw_url, err_msg)
            _LATEST_INVESTIGATION_STATE.clear()
            _LATEST_INVESTIGATION_STATE.update(inaccessible)
            return inaccessible
    except Exception as exc:
        err_msg = str(exc)
        if any(term in err_msg.lower() for term in ("nodename nor servname", "name or service not known", "getaddrinfo failed", "timed out", "connection refused", "network is unreachable", "ssl", "certificate")):
            inaccessible = generate_inaccessible_domain_triage(raw_url, err_msg)
            _LATEST_INVESTIGATION_STATE.clear()
            _LATEST_INVESTIGATION_STATE.update(inaccessible)
            return inaccessible
        raise HTTPException(status_code=502, detail=f"Failed to fetch remote URL: {exc}")

    ext = Path(parsed.path).suffix.lower()
    if not ext or ext not in (".html", ".htm", ".pdf", ".xlsx", ".docx"):
        ext = ".pdf" if "pdf" in content_type.lower() else ".html"

    clean_host = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", parsed.netloc)
    target_path = DOWNLOADS_DIR / f"live_{clean_host}{ext}"
    target_path.write_bytes(content)

    try:
        is_hitl = bool(req.hitl)
        should_auto_approve = req.auto_approve if req.auto_approve is not None else (not is_hitl)
        result = run_pipeline(
            target_path,
            source_url=raw_url,
            enable_hitl=is_hitl,
            auto_approve=should_auto_approve,
        )
        clean_result = sanitize_result(result)
        _LATEST_INVESTIGATION_STATE.clear()
        _LATEST_INVESTIGATION_STATE.update(clean_result)
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
        is_hitl = bool(req.hitl)
        should_auto_approve = req.auto_approve if req.auto_approve is not None else (not is_hitl)
        result = run_pipeline(
            path,
            enable_hitl=is_hitl,
            auto_approve=should_auto_approve,
        )
        clean_result = sanitize_result(result)
        _LATEST_INVESTIGATION_STATE.clear()
        _LATEST_INVESTIGATION_STATE.update(clean_result)
        return clean_result
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Pipeline error: {str(exc)}")


def generate_inaccessible_domain_triage(raw_url: str, error_detail: str) -> Dict[str, Any]:
    from datetime import datetime, timezone
    import hashlib

    parsed = urlparse(raw_url)
    hostname = parsed.hostname or raw_url
    url_hash = hashlib.sha256(raw_url.encode()).hexdigest()
    md5_hash = hashlib.md5(raw_url.encode()).hexdigest()
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    is_dns_failure = any(term in error_detail.lower() for term in ("nodename nor servname", "name or service not known", "getaddrinfo failed"))

    if is_dns_failure:
        verdict = "INACCESSIBLE (DNS NXDOMAIN / Dead Domain)"
        threat_level = "SUSPICIOUS"
        category_title = "Dismantled / Non-Existent Web Domain"
        summary = (
            f"Target host '{hostname}' cannot be resolved via authoritative DNS (NXDOMAIN). "
            "In cyber incident response, this indicates an ephemeral phishing domain that has been "
            "dismantled/taken down by the registrar, or a non-existent typosquatting lure."
        )
        indicators = [
            f"Authoritative DNS Resolution Failed: {error_detail}",
            f"Host '{hostname}' has 0 active IPv4 (A) or IPv6 (AAAA) records",
            "Typical lifecycle: Short-lived phishing attack infrastructure taken down by registrar or hosting provider",
        ]
        tactic_id = "T1566.002"
        technique_name = "Inactive / Taken Down Spearphishing Domain"
        actions = [
            {
                "stage": "Infrastructure Verification",
                "tier": "Tier 1 - Registrar Status Check",
                "action": f"Query WHOIS/RDAP for {hostname} to verify whether domain was suspended by registrar (ClientHold/ServerHold).",
            },
            {
                "stage": "Threat Intelligence",
                "tier": "Tier 2 - Passive DNS Correlation",
                "action": f"Search VirusTotal / URLhaus passive DNS history for {hostname} to identify past C2 IP addresses.",
            },
            {
                "stage": "Perimeter Defense",
                "tier": "Tier 3 - Preventive DNS Sinkhole",
                "action": f"Maintain preventive block on enterprise DNS resolvers (Cisco Umbrella / Infoblox) to prevent reactivation.",
            },
        ]
    else:
        verdict = "INACCESSIBLE (Connection Unreachable)"
        threat_level = "MEDIUM"
        category_title = "Unreachable Web Resource"
        summary = f"Remote endpoint '{hostname}' refused connection or timed out ({error_detail})."
        indicators = [f"Network Connection Failed: {error_detail}"]
        tactic_id = "T1566.002"
        technique_name = "Unreachable Target Host"
        actions = [
            {
                "stage": "Connectivity Verification",
                "tier": "Tier 1 - Host Reachability",
                "action": f"Check perimeter firewall egress logs for connection attempts to {hostname}.",
            }
        ]

    soc_md = f"""# 🟠 SOC Incident Response Report — {hostname}
**Generated:** `{timestamp}` | **Pipeline:** `ExplainPhish LangGraph Agent v2.0` | **Classification:** `{threat_level}`

---

## 1. Executive Summary
- **Target URL:** `{raw_url}`
- **Host:** `{hostname}`
- **Verdict:** **{verdict}**
- **Threat Level:** `{threat_level}`
- **Status:** `{category_title}`

> [!NOTE]
> **Autonomous Forensics Decision:** {summary}

## 2. Infrastructure Telemetry & Indicators
"""
    for ind in indicators:
        soc_md += f"- {ind}\n"

    soc_md += """
## 3. Prescriptive SOAR Incident Response Playbook
| Stage | Action Tier | Prescribed Response Action |
| :--- | :--- | :--- |
"""
    for a in actions:
        soc_md += f"| **{a['stage']}** | `{a['tier']}` | {a['action']} |\n"

    soc_md += "\n---\n*Report automatically generated by ExplainPhish Autonomous Security Agent.*\n"

    return {
        "file_name": f"{hostname}.dns_status",
        "file_path": f"/downloads/status_{hostname}.txt",
        "format_display": "Web Domain (Offline / Inaccessible)",
        "source_url": raw_url,
        "file_size_bytes": 0,
        "file_hash_sha256": url_hash,
        "file_hash_md5": md5_hash,
        "final_verdict": verdict,
        "ensemble_verdict": "SUSPICIOUS",
        "threat_level": threat_level,
        "confidence_score": 0.90,
        "confidence_band": "HIGH",
        "is_borderline": True,
        "borderline_reasons": ["Target domain does not resolve to active IP infrastructure"],
        "model_predictions": [
            {"model": "DNS Resolver", "prediction": 0, "probability_malicious": 0.50},
            {"model": "Host Prober", "prediction": 0, "probability_malicious": 0.50},
        ],
        "top_risk_drivers": [
            {
                "feature": "dns_nxdomain",
                "description": "Domain name does not exist or has been suspended",
                "raw_value": 0,
                "std_value": 0,
                "direction": "↑",
                "impact": 0.5,
            }
        ],
        "deep_analysis": {
            "forensic_inspection_conducted": True,
            "verdict_adjustment": "ESCALATE_TO_SUSPICIOUS",
            "rationale": summary,
            "indicators": indicators,
        },
        "indicators_of_compromise": [
            {"type": "Inaccessible / Dead Domain", "value": hostname}
        ],
        "mitre_tactics": [
            {
                "id": tactic_id,
                "tactic": "Initial Access",
                "technique": technique_name,
                "description": summary,
            }
        ],
        "soc_playbook_actions": actions,
        "applied_rules": {
            "intake_safety": "Rule 1 (Intake Safety): Evaluated remote host reachable bounds",
            "feature_extraction": "Rule 2 (DNS Telemetry): Checked authoritative A/AAAA record resolution",
            "deep_threat_analysis": f"Rule 5D (Infrastructure Triage): {category_title}",
            "mitre_mapping": "Rule 6 (MITRE & SOAR): Generated dead infrastructure mitigation playbooks",
            "soc_report": "Rule 7 (Executive Synthesis): Synthesized dead domain triage dossier",
        },
        "executive_summary": summary,
        "soc_report_markdown": soc_md,
    }


def sanitize_result(res: Dict[str, Any]) -> Dict[str, Any]:
    """Ensure JSON serializability (convert numpy floats, serialize interrupts, and sanitize keys)."""
    out = {}
    for k, v in res.items():
        if k == "__interrupt__":
            # Extract interrupt values cleanly into a serializable list
            clean_ints = []
            if isinstance(v, (list, tuple)):
                for item in v:
                    val = getattr(item, "value", item)
                    clean_ints.append(val if isinstance(val, dict) else str(val))
            out["interrupts"] = clean_ints
            continue

        if k in ("raw_features", "standardized_features") and isinstance(v, dict):
            clean_dict = {}
            for fk, fv in v.items():
                try:
                    clean_dict[str(fk)] = float(fv)
                except (ValueError, TypeError):
                    clean_dict[str(fk)] = str(fv)
            out[k] = clean_dict
        else:
            out[k] = v
    return out


# Serve static web frontend
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    @app.get("/app.css")
    def serve_css():
        return FileResponse(STATIC_DIR / "app.css", media_type="text/css")

    @app.get("/app.js")
    def serve_js():
        return FileResponse(STATIC_DIR / "app.js", media_type="application/javascript")

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
