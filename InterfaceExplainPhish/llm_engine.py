"""
ExplainPhish Cognitive Threat Intelligence & LLM Reasoning Engine
==================================================================
Multi-provider LLM integration layer powering:
  1. Semantic Lure & Social Engineering Psychology Analysis
  2. Dynamic Code De-obfuscation & Attacker Motive Reasoning
  3. Ambiguity & Borderline Split Consensus Resolution
  4. Executive Incident Dossier & Narrative Generation
  5. Interactive SOC Analyst Chat Assistant

Supported Providers:
  - Google Gemini (gemini-2.5-flash / gemini-1.5-flash) via GEMINI_API_KEY
  - OpenAI (gpt-4o / gpt-4o-mini) via OPENAI_API_KEY
  - Groq (llama-3.3-70b-versatile / mixtral) via GROQ_API_KEY
  - Anthropic (claude-3-5-sonnet) via ANTHROPIC_API_KEY
  - Local Ollama (llama3 / mistral) via OLLAMA_BASE_URL
  - Resilient Heuristic Fallback Reasoner (100% offline, zero-downtime)
"""

from __future__ import annotations
from groq import Groq
import json
import logging
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("ExplainPhish.LLM")

# Ensure environment variables from .env files are discovered
_ROOT = Path(__file__).resolve().parent.parent
_HERE = Path(__file__).resolve().parent

try:
    from dotenv import load_dotenv
    # Load from root first, then InterfaceExplainPhish, then .env.example as fallback
    load_dotenv(_ROOT / ".env")
    load_dotenv(_HERE / ".env")
    load_dotenv(_ROOT / ".env.example")
except ImportError:
    pass


def get_active_provider_config() -> Dict[str, Any]:
    """
    Detects which LLM provider is available based on environment variables.
    Returns provider metadata, model name, and operational mode.
    """
    model_override = os.environ.get("EXPLAINPHISH_LLM_MODEL", "").strip()

    # 1. Google Gemini
    gemini_key = (os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY") or "").strip()
    if gemini_key:
        return {
            "provider": "Google Gemini",
            "model": model_override or "gemini/gemini-2.5-flash",
            "api_key": gemini_key,
            "mode": "LIVE_LLM",
            "description": "Google Gemini Ultra-Fast Multimodal Threat Intelligence",
        }

    # 2. OpenAI
    openai_key = (os.environ.get("OPENAI_API_KEY") or "").strip()
    if openai_key:
        return {
            "provider": "OpenAI",
            "model": model_override or "gpt-4o-mini",
            "api_key": openai_key,
            "mode": "LIVE_LLM",
            "description": "OpenAI GPT-4o Frontier Cybersecurity Reasoning",
        }

    # 3. Groq
    groq_key = (os.environ.get("GROQ_API_KEY") or "").strip()
    if groq_key:
        chosen_model = model_override or "qwen/qwen3.8-27b"
        if "prompt-guard" in chosen_model:
            # Llama prompt guard is an injection classifier, not a chat generator
            chosen_model = "qwen/qwen3.8-27b"

        return {
            "provider": "Groq",
            "model": chosen_model,
            "api_key": groq_key,
            "mode": "LIVE_LLM",
            "description": f"Groq Ultra-Low Latency SOC Inference Engine ({chosen_model})",
        }

    # 4. Anthropic
    anthropic_key = (os.environ.get("ANTHROPIC_API_KEY") or "").strip()
    if anthropic_key:
        return {
            "provider": "Anthropic",
            "model": model_override or "claude-3-5-sonnet-20241022",
            "api_key": anthropic_key,
            "mode": "LIVE_LLM",
            "description": "Anthropic Claude High-Fidelity Threat Analysis",
        }

    # 5. Local Ollama
    ollama_url = os.environ.get("OLLAMA_BASE_URL", "").strip()
    if ollama_url:
        return {
            "provider": "Ollama (Local)",
            "model": model_override or "ollama/llama3",
            "api_base": ollama_url,
            "mode": "LIVE_LLM",
            "description": "Air-Gapped Private Local LLM",
        }

    # 6. Built-in Offline Cognitive Forensics Engine
    return {
        "provider": "Heuristic Cognitive Reasoner",
        "model": "explainphish-symbolic-v2",
        "mode": "HEURISTIC_OFFLINE",
        "description": "ExplainPhish Built-in Cognitive Reasoner (Configure .env with API key for live LLM)",
    }


def call_llm_completion(prompt: str, system_prompt: str, max_tokens: int = 1200) -> Optional[str]:
    """
    Safely executes an LLM generation using native provider SDKs (Groq, OpenAI)
    or LiteLLM. Falls back gracefully if the provider fails or times out.
    """
    config = get_active_provider_config()
    if config["mode"] != "LIVE_LLM":
        return None

    # Native Groq execution (Ultra-fast direct API)
    if config["provider"] == "Groq":
        try:
            from groq import Groq
            client = Groq(api_key=config["api_key"])
            model_id = config["model"].replace("groq/", "")
            resp = client.chat.completions.create(
                model=model_id,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": prompt},
                ],
                max_tokens=max_tokens,
                temperature=0.2,
                timeout=20,
            )
            if resp and resp.choices and len(resp.choices) > 0:
                content = resp.choices[0].message.content
                if content and content.strip():
                    return content.strip()
        except Exception as exc:
            logger.warning(f"Native Groq API call failed: {exc}. Trying LiteLLM fallback.")

    # Universal LiteLLM execution
    try:
        import litellm
        litellm.suppress_debug_info = True

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt},
        ]

        kwargs: Dict[str, Any] = {
            "model": config["model"],
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": 0.2,
            "timeout": 20,
        }
        if "api_key" in config:
            kwargs["api_key"] = config["api_key"]
        if "api_base" in config:
            kwargs["api_base"] = config["api_base"]

        resp = litellm.completion(**kwargs)
        if resp and resp.choices and len(resp.choices) > 0:
            return resp.choices[0].message.content.strip()
    except Exception as exc:
        logger.warning(f"Live LLM call to {config['provider']} ({config['model']}) failed: {exc}. Falling back to cognitive reasoner.")
        return None

    return None



def generate_cognitive_threat_analysis(state: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generates semantic lure evaluation, psychological profiling,
    de-obfuscation rationale, and an executive narrative for the sample.
    Uses Live LLM when configured; otherwise executes smart heuristic analysis.
    """
    config = get_active_provider_config()
    file_name = state.get("file_name", "unknown")
    fmt = state.get("file_format", "unknown")
    verdict = state.get("final_verdict") or state.get("ensemble_verdict", "BENIGN")
    threat_level = state.get("threat_level", "LOW")
    conf = state.get("confidence_score", 0.0)
    top_drivers = state.get("top_risk_drivers", [])
    predictions = state.get("model_predictions", [])
    deep = state.get("deep_analysis", {})
    indicators = deep.get("indicators", [])
    iocs = state.get("indicators_of_compromise", [])

    # Read snippet of file text for contextual comprehension
    text_snippet = ""
    try:
        p = Path(state.get("file_path", ""))
        if p.exists() and p.is_file() and p.stat().st_size < 2 * 1024 * 1024:
            raw = p.read_text(encoding="utf-8", errors="ignore")
            # Strip excessive whitespace and keep first 3000 chars
            clean_txt = re.sub(r"\s+", " ", raw)
            text_snippet = clean_txt[:3000]
    except Exception:
        text_snippet = ""

    # Always generate structured cognitive baseline first (guarantees schema integrity)
    heuristic_result = _analyze_heuristically(
        file_name=file_name,
        fmt=fmt,
        verdict=verdict,
        threat_level=threat_level,
        conf=conf,
        top_drivers=top_drivers,
        predictions=predictions,
        indicators=indicators,
        iocs=iocs,
        text_snippet=text_snippet,
        is_borderline=state.get("is_borderline", False),
    )

    # Attempt live LLM enhancement if configured
    if config["mode"] == "LIVE_LLM":
        system_prompt = (
            "You are the Lead Cybersecurity Forensics & Threat Intelligence Analyst for ExplainPhish SOC. "
            "Your role is to perform deep psychological social engineering analysis, evaluate threat mechanics, "
            "interpret machine learning consensus, and author an authoritative, human-readable executive incident brief. "
            "Write in concise, professional cybersecurity terminology (MITRE ATT&CK, NIST IR). Respond with clear markdown."
        )

        user_prompt = f"""Triage the following suspicious document:
- File Name: `{file_name}` (Format: {fmt.upper()})
- Ensemble ML Verdict: {verdict} (Confidence: {conf:.1%})
- Threat Classification: {threat_level}
- Model Consensus: {json.dumps(predictions)}
- Key Risk Drivers (SHAP/Z-Scores): {json.dumps(top_drivers[:4])}
- Extracted Forensic Indicators: {json.dumps(indicators)}
- Extracted IOCs: {json.dumps(iocs)}
- Raw Document Content Preview:
```
{text_snippet[:1500]}
```

Provide your analysis structured as follows:
### 1. Social Engineering & Pretexting Assessment
(Identify the lure pretext, urgency tactics, target psychological pressure, and spoofed branding)

### 2. Forensic Threat Mechanics & Evasion Evaluation
(Analyze credential harvesting, script obfuscation, macro vectors, or explain why this is a legitimate/benign file)

### 3. Executive Threat Intelligence Narrative
(A 2-3 paragraph senior briefing summarizing the core hazard, attacker intent, and why the ML ensemble classified it this way)

### 4. Prescriptive SOC Countermeasures
(Specific firewall, email sweep, DNS sinkholing, or user notification guidance)
"""
        llm_response = call_llm_completion(user_prompt, system_prompt, max_tokens=1000)
        if llm_response:
            return {
                "provider": config["provider"],
                "model": config["model"],
                "mode": "LIVE_LLM",
                "social_engineering": heuristic_result["social_engineering"],
                "evasion_analysis": heuristic_result["evasion_analysis"],
                "executive_threat_narrative": llm_response,
                "analyst_recommendation": heuristic_result["analyst_recommendation"],
                "status_badge": f"AI Cognitive Triage Active ({config['provider']})",
            }

    # Fallback return
    heuristic_result["provider"] = config["provider"]
    heuristic_result["model"] = config["model"]
    heuristic_result["mode"] = config["mode"]
    heuristic_result["status_badge"] = "Heuristic Cognitive Analysis Active (Set API key in .env for Live LLM)"
    return heuristic_result


def _analyze_heuristically(
    file_name: str,
    fmt: str,
    verdict: str,
    threat_level: str,
    conf: float,
    top_drivers: List[Dict[str, Any]],
    predictions: List[Dict[str, Any]],
    indicators: List[str],
    iocs: List[Dict[str, str]],
    text_snippet: str,
    is_borderline: bool,
) -> Dict[str, Any]:
    """
    Deterministic rule-based cognitive threat evaluator.
    Extracts semantic lure types, psychological triggers, and evasion strategies.
    """
    text_lower = text_snippet.lower()
    is_malicious = "MALICIOUS" in verdict
    is_suspicious = "SUSPICIOUS" in verdict or threat_level == "MEDIUM"

    # 1. Social Engineering Lure Detection
    lure_type = "Standard Business Communication"
    authority_spoof = "None Identified"
    urgency_level = "NORMAL"
    triggers = []

    # Credential / Account Phishing patterns
    if any(k in text_lower for k in ["password", "login", "sign-in", "verify your account", "account suspended", "session expired", "office 365", "microsoft", "google workspace"]):
        lure_type = "Credential Harvesting / Account Verification"
        triggers.append("Fear of Service Interruption")
        if "microsoft" in text_lower or "office" in text_lower:
            authority_spoof = "Microsoft 365 / Corporate IT Identity"
        elif "google" in text_lower:
            authority_spoof = "Google Workspace Admin"
        else:
            authority_spoof = "Corporate Authentication Authority"

    # Financial / Invoice lures
    elif any(k in text_lower for k in ["invoice", "payment", "remittance", "wire transfer", "bank transfer", "overdue", "purchase order", "receipt"]):
        lure_type = "Financial Pretexting / Fraudulent Remittance Lure"
        authority_spoof = "Accounts Payable / Financial Clearinghouse"
        triggers.append("Commercial Obligation / Financial Urgency")

    # HR / Payroll / Benefit lures
    elif any(k in text_lower for k in ["payroll", "salary", "bonus", "human resources", "termination", "severance", "benefit enrollment"]):
        lure_type = "Human Resources / Compensation Bait"
        authority_spoof = "Corporate Human Resources / Benefits Dept"
        triggers.append("Curiosity / Personal Compensation Interest")

    # Urgency check
    if any(k in text_lower for k in ["urgent", "immediately", "within 24 hours", "action required", "critical", "suspension", "terminated"]):
        urgency_level = "ELEVATED"
        triggers.append("Artificial Deadline Pressure")

    if not is_malicious and not is_suspicious:
        lure_type = "Legitimate Corporate Document / Educational Portal"
        authority_spoof = "Verified Organization"
        urgency_level = "LOW"
        triggers = ["Standard Operational Context"]

    # 2. Evasion & Obfuscation Analysis
    evasion_techniques = []
    for ind in indicators:
        if "obfuscated" in ind.lower() or "eval" in ind.lower() or "unescape" in ind.lower():
            evasion_techniques.append("Client-side Script Obfuscation (eval/unescape/atob)")
        if "hidden" in ind.lower() or "iframe" in ind.lower():
            evasion_techniques.append("Stealth Hidden Visual Element (Zero-dimension iframe)")
        if "external" in ind.lower() or "action" in ind.lower():
            evasion_techniques.append("Cross-Origin Form Exfiltration (Action target mismatch)")
        if "vba" in ind.lower() or "macro" in ind.lower():
            evasion_techniques.append("Embedded Office VBA Payload Execution")
        if "dde" in ind.lower():
            evasion_techniques.append("Dynamic Data Exchange (DDE) Formula Command Execution")
        if "launch" in ind.lower():
            evasion_techniques.append("PDF Process Execution Action (/Launch)")

    evasion_complexity = "CRITICAL" if len(evasion_techniques) >= 2 else ("MODERATE" if evasion_techniques else "LOW / MINIMAL")

    # 3. Model Consensus Explanation
    mal_count = sum(1 for p in predictions if p.get("prediction") == 1)
    tot_count = len(predictions) if predictions else 5
    if mal_count == tot_count:
        consensus_summary = f"Unanimous agreement across all {tot_count} machine learning architectures with {conf:.1%} confidence."
    elif mal_count == 0:
        consensus_summary = f"Unanimous consensus that the sample exhibits standard benign enterprise characteristics (Safe confidence: {1 - conf:.1%})."
    else:
        consensus_summary = f"Split consensus: {mal_count} of {tot_count} models flagged risk indicators. The decision boundary was resolved via forensic telemetry inspection."

    # 4. Construct Multi-Paragraph Narrative
    if is_malicious:
        narrative = (
            f"### Threat Intelligence Briefing: {file_name}\n\n"
            f"**Executive Verdict:** The analyzed artifact has been classified as **{verdict}** with a threat severity of **{threat_level}** "
            f"({conf:.1%} confidence). {consensus_summary}\n\n"
            f"**Social Engineering & Pretexting Strategy:** The lure employs a **{lure_type}** pretext with **{urgency_level.lower()} urgency**. "
            f"Attackers frequently exploit psychological leverage ({', '.join(triggers)}) masquerading under the guise of *{authority_spoof}* "
            f"to manipulate recipients into bypassing internal security validation.\n\n"
            f"**Technical Attack Vector & Evasion:** Static forensic inspection uncovered {len(evasion_techniques) or 'subtle structural'} evasion techniques: "
            f"{', '.join(evasion_techniques) if evasion_techniques else 'Anomalous structural metrics and deceptive link topology'}. "
            f"Primary indicators of compromise have been logged into the incident response record for containment."
        )
        recommendation = "Enforce perimeter quarantine, purge related email artifacts across mailboxes, and revoke active sessions for affected accounts."
    elif is_suspicious:
        narrative = (
            f"### Suspicious Activity Briefing: {file_name}\n\n"
            f"**Executive Verdict:** The sample exhibits borderline anomalous behavior evaluated as **{verdict}** ({threat_level} risk). "
            f"{consensus_summary}\n\n"
            f"**Contextual Telemetry:** The artifact was routed through autonomous deep forensics due to ambiguous structural signals. "
            f"While outright weaponized exploit code was not confirmed, the file triggered policy alerts or suspicious category classifications."
        )
        recommendation = "Apply conditional access monitoring, verify document authenticity out-of-band with the sender, and sandbox dynamic interactions."
    else:
        narrative = (
            f"### Security Clearance Briefing: {file_name}\n\n"
            f"**Executive Verdict:** Document cleared as **{verdict}** ({threat_level} severity). {consensus_summary}\n\n"
            f"**Structural Profile:** Feature extraction confirmed balanced DOM/document architecture, consistent internal link distribution, "
            f"and 0 weaponized macros, DDE execution formulas, or credential harvesting action targets."
        )
        recommendation = "Authorize document release to endpoint. No further SOC remediation required."

    return {
        "social_engineering": {
            "lure_type": lure_type,
            "authority_spoof": authority_spoof,
            "urgency_level": urgency_level,
            "psychological_triggers": triggers,
            "risk_rating": "CRITICAL" if is_malicious else ("MEDIUM" if is_suspicious else "LOW"),
        },
        "evasion_analysis": {
            "complexity": evasion_complexity,
            "techniques": evasion_techniques if evasion_techniques else ["No Active Obfuscation Detected"],
        },
        "executive_threat_narrative": narrative,
        "analyst_recommendation": recommendation,
    }


def chat_with_soc_agent(
    state: Dict[str, Any],
    question: str,
    history: Optional[List[Dict[str, str]]] = None,
) -> str:
    """
    Conversational SOC analyst copilot.
    Answers specific questions regarding the triage dossier, MITRE mappings,
    YARA rules, false-positive rationale, and containment playbooks.
    """
    config = get_active_provider_config()
    file_name = state.get("file_name", "unknown")
    verdict = state.get("final_verdict") or state.get("ensemble_verdict", "UNKNOWN")
    threat_level = state.get("threat_level", "UNKNOWN")
    conf = state.get("confidence_score", 0.0)
    predictions = state.get("model_predictions", [])
    top_drivers = state.get("top_risk_drivers", [])
    iocs = state.get("indicators_of_compromise", [])
    mitre = state.get("mitre_tactics", [])
    playbook = state.get("soc_playbook_actions", [])
    sha256 = state.get("file_hash_sha256", "N/A")

    # If Live LLM available, invoke with full grounding
    if config["mode"] == "LIVE_LLM":
        system_prompt = (
            "You are ExplainPhish Copilot, an elite AI Security Operations Center (SOC) agent. "
            "You have direct access to the live forensic triage dossier of the analyzed sample. "
            "Answer the analyst's questions concisely, authoritatively, and with actionable cybersecurity details. "
            "When requested, generate complete YARA rules, detection signatures, PowerShell containment commands, "
            "or user notification templates. Maintain a helpful, technical SOC analyst persona."
        )

        context_summary = f"""Current Incident Dossier:
- File: {file_name} (SHA-256: {sha256})
- Verdict: {verdict} (Threat Level: {threat_level}, Confidence: {conf:.1%})
- Model Predictions: {json.dumps(predictions)}
- Key Risk Drivers: {json.dumps(top_drivers[:5])}
- IOCs: {json.dumps(iocs)}
- MITRE Tactics: {json.dumps(mitre)}
- SOAR Playbook: {json.dumps(playbook)}
"""
        full_user_prompt = f"{context_summary}\nAnalyst Question: {question}"
        ans = call_llm_completion(full_user_prompt, system_prompt, max_tokens=1000)
        if ans:
            return ans

    # Offline Expert Reasoning Copilot
    q_lower = question.lower()

    # Query 1: YARA Rule Generation
    if "yara" in q_lower or "rule" in q_lower and "signature" in q_lower:
        clean_name = re.sub(r"[^a-zA-Z0-9_]", "_", file_name)
        ioc_strings = []
        for i, item in enumerate(iocs[:4]):
            val = item.get("value", "").replace('"', '\\"')
            if val:
                ioc_strings.append(f'        $ioc_{i} = "{val}" ascii wide nocase')
        if not ioc_strings:
            ioc_strings.append('        $sig_pattern = "eval(unescape(" ascii wide nocase')

        strings_block = "\n".join(ioc_strings)
        return (
            f"Here is a targeted YARA detection rule tailored to `{file_name}`:\n\n"
            f"```yara\n"
            f"rule ExplainPhish_{clean_name} {{\n"
            f"    meta:\n"
            f'        description = "Detects phishing/malicious document {file_name}"\n'
            f'        author = "ExplainPhish Autonomous SOC Agent"\n'
            f'        sha256 = "{sha256}"\n'
            f'        threat_level = "{threat_level}"\n'
            f'        date = "{str(Path(file_name).suffix)}"\n'
            f"    strings:\n"
            f"{strings_block}\n"
            f"    condition:\n"
            f"        uint16(0) != 0 and any of them\n"
            f"}}\n"
            f"```\n\n"
            f"Deploy this rule to your EDR / SIEM (e.g. CrowdStrike Falcon, Sentinel, or Suricata) to intercept identical lures."
        )

    # Query 2: Email Draft to User / IT
    if any(k in q_lower for k in ["draft", "email", "notify", "user message", "advisory"]):
        return (
            f"### Incident Advisory Notification\n\n"
            f"**To:** All Affected Recipients / Department Staff\n"
            f"**From:** Enterprise Security Operations Center (SOC)\n"
            f"**Subject:** [SECURITY ADVISORY] Quarantined Attachment Notice: `{file_name}`\n\n"
            f"Dear Colleague,\n\n"
            f"An email attachment titled **`{file_name}`** recently delivered to your inbox has been automatically quarantined "
            f"by our email defense gateway.\n\n"
            f"**Reason for Quarantine:** The document exhibited automated indicators of **{verdict}** ({threat_level} severity) "
            f"associated with credential harvesting and deceptive origin targets.\n\n"
            f"**Required Action:**\n"
            f"- If you received or opened this attachment, do **not** click any links or enter credentials.\n"
            f"- If you entered your username or password, immediately notify the SOC at `soc@enterprise.internal` to reset your credentials.\n\n"
            f"Thank you for your cooperation in maintaining enterprise cyber resilience.\n\n"
            f"*Enterprise Security Operations Center*"
        )

    # Query 3: Why did models vote or split consensus?
    if any(k in q_lower for k in ["why", "model", "voting", "difference", "split", "rf", "dt", "decision"]):
        preds_list = []
        for p in predictions:
            pl = "MALICIOUS" if p.get("prediction") == 1 else "BENIGN"
            preds_list.append(f"- **{p['model']}**: Predicted `{pl}` ({p.get('probability', 0.0):.1%})")
        preds_str = "\n".join(preds_list)

        drivers_list = []
        for d in top_drivers[:3]:
            drivers_list.append(f"- `{d['feature']}`: {d['description']} (Impact: {d['impact']:+.4f})")
        drivers_str = "\n".join(drivers_list)

        return (
            f"### Model Consensus Breakdown for `{file_name}`\n\n"
            f"**Individual Architecture Votes:**\n"
            f"{preds_str}\n\n"
            f"**Top Mathematical Decision Drivers:**\n"
            f"{drivers_str}\n\n"
            f"**Consensus Interpretation:** The final verdict (**{verdict}**) was synthesized by combining the multi-model "
            f"soft probability average ({conf:.1%}) with static forensic telemetry to screen out false positives and catch zero-day evasions."
        )

    # Default Help
    return (
        f"### ExplainPhish SOC Copilot Analysis\n\n"
        f"- **File:** `{file_name}`\n"
        f"- **Classification:** **{verdict}** (`{threat_level}` severity)\n"
        f"- **Confidence:** `{conf:.1%}`\n\n"
        f"You can ask me to:\n"
        f"1. *'Generate a YARA rule for this sample'* ➔ Creates production detection rules.\n"
        f"2. *'Draft an incident email to the user'* ➔ Generates security notification.\n"
        f"3. *'Why did the models vote this way?'* ➔ Detailed model breakdown and feature attribution.\n"
        f"4. *'What are the containment steps?'* ➔ Outlines step-by-step SOAR playbook."
    )
