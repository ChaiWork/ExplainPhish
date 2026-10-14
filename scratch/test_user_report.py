import os
import sys
sys.path.insert(0, os.path.abspath("."))
from InterfaceExplainPhish.report_exporter import generate_pdf_report, generate_docx_report

narrative = """The absence of extracted IOCs (URLs, IPs) in the static preview is a significant red flag indicating **Dynamic Payload Delivery** or **Obfuscated Exfiltration**. The high `script_entropy` (5.345) confirms the presence of packed or obfuscated JavaScript. This script likely:
1. Captures input from hidden form fields.
2. Encodes the credentials (e.g., Base64, XOR).
3. Exfiltrates data via a non-standard channel (e.g., DNS tunneling, image beaconing, or a dynamically constructed 'fetch' request to a C2 server not visible in the static HTML source).
* **Evasion Techniques:**
* **Inline Resources:** The use of `data:` URIs for the favicon prevents network requests to external domains, evading simple URL-based blocklists.
* **DOM Complexity:** The `tag_count` of 120 suggests a complex DOM structure, likely used to hide malicious elements within legitimate-looking UI components (e.g., invisible iframes or hidden divs).
* **Punctuation in URLs:** The `url_punct_char_count` of 9 indicates the presence of URLs with special characters, which may be used to bypass naive regex-based URL filters or to encode exfiltration data in query parameters.
* **Macro Vector:** Not applicable (HTML file).
* **Verdict:** This is **not** a benign file. The combination of brand spoofing, high script entropy, and lack of visible external links is characteristic of a **Drive-by Credential Harvester** or a **Phishing Kit** page (e.g., Evilginx, Modlishka) designed to intercept credentials in real-time.

### 3. Executive Threat Intelligence Narrative

The analyzed artifact, `upload_sample_06759.html`, is a high-fidelity phishing page designed to harvest Microsoft Outlook credentials. The ensemble ML model correctly classified this as **MALICIOUS** with 93.7% confidence, driven primarily by the Neural Network (99.99%) and XGBoost (98.49%) models, which are highly sensitive to structural anomalies in HTML and JavaScript patterns. The key risk driver, `script_entropy` (5.345), indicates the presence of obfuscated JavaScript, a hallmark of modern phishing kits that aim to evade static signature-based detection.

The attacker's intent is **Credential Theft** to facilitate further intrusion, such as Business Email Compromise (BEC) or lateral movement within the target organization. The absence of extracted IOCs in the static analysis suggests the malicious payload is dynamically generated or exfiltrated via obfuscated channels, making traditional URL blocklisting insufficient. The use of inline base64 resources and a complex DOM structure demonstrates a sophisticated evasion strategy aimed at bypassing email security gateways and endpoint protection systems that rely on static content inspection.

This incident highlights the increasing sophistication of phishing campaigns that leverage legitimate-looking interfaces and obfuscated code to bypass traditional defenses. The high consensus among advanced ML models (Neural Network, XGBoost, LightGBM) underscores the reliability of the detection, while the lower confidence from
<script>alert('xss')</script>
tag_count < 10
iframe <iframe src='http://evil.com?a=1&b=2'>"""

test_state = {
    "file_name": "upload_sample_06759.html",
    "final_verdict": "MALICIOUS",
    "threat_level": "CRITICAL",
    "confidence_score": 0.937,
    "file_size_bytes": 102400,
    "file_hash_sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
    "model_predictions": [
        {"model": "Neural Network", "prediction": 1, "probability": 0.9999},
        {"model": "XGBoost", "prediction": 1, "probability": 0.9849},
        {"model": "LightGBM", "prediction": 1, "probability": 0.9500},
        {"model": "Random Forest", "prediction": 1, "probability": 0.9200},
        {"model": "Decision Tree", "prediction": 1, "probability": 0.8500},
    ],
    "top_risk_drivers": [
        {"feature": "script_entropy", "description": "Obfuscated script entropy", "direction": "↑", "impact": 0.5345},
        {"feature": "tag_count", "description": "DOM tag count < 150", "direction": "↑", "impact": 0.3210},
    ],
    "indicators_of_compromise": [
        {"type": "Inline Base64 Resource", "value": "data:image/x-icon;base64,AAABAA..."},
        {"type": "Suspicious URI Query", "value": "https://evil.com/login?redirect=outlook&token=123&track=yes"},
    ],
    "soc_playbook_actions": [
        {"stage": "Perimeter Containment", "tier": "TIER-1 IMMEDIATE", "action": "Block outbound DNS requests to harvested endpoints & domains <evil.com>"},
    ],
    "llm_triage": {
        "provider": "Groq",
        "model": "qwen/qwen3.8-27b",
        "executive_threat_narrative": narrative,
    },
}

pdf_bytes = generate_pdf_report(test_state)
print("PDF generation success! Bytes:", len(pdf_bytes))
assert pdf_bytes.startswith(b"%PDF-1.")

docx_bytes = generate_docx_report(test_state)
print("DOCX generation success! Bytes:", len(docx_bytes))
assert docx_bytes.startswith(b"PK\x03\x04")
print("ALL ASSERTIONS PASSED!")
