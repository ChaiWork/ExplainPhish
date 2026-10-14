import html
import io
import re
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter

def _safe_xml(text) -> str:
    if text is None:
        return ""
    return html.escape(str(text), quote=False)

def _safe_markdown_to_paragraph_xml(text: str) -> str:
    if not text:
        return ""
    s = html.escape(str(text), quote=False)
    s = re.sub(r"###+\s*", "", s)
    s = re.sub(r"\*\*([^\*\n]+?)\*\*", r"<b>\1</b>", s)
    s = re.sub(r"(?<!\*)\*([^\*\n]+?)\*(?!\*)", r"<i>\1</i>", s)
    s = re.sub(r"`([^`\n]+?)`", r"<font name='Courier'>\1</font>", s)
    return s.strip()

def _make_safe_paragraph(text, style, is_markdown: bool = False) -> Paragraph:
    try:
        content = _safe_markdown_to_paragraph_xml(text) if is_markdown else _safe_xml(text)
        return Paragraph(content, style)
    except Exception:
        raw_escaped = html.escape(str(text or ""), quote=False)
        return Paragraph(raw_escaped, style)

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

This incident highlights the increasing sophistication of phishing campaigns that leverage legitimate-looking interfaces and obfuscated code to bypass traditional defenses. The high consensus among advanced ML models (Neural Network, XGBoost, LightGBM) underscores the reliability of the detection, while the lower confidence from"""

styles = getSampleStyleSheet()
style_body = styles["Normal"]
style_bullet = ParagraphStyle("Bullet", parent=styles["Normal"], leftIndent=12, spaceAfter=3)
style_h3 = ParagraphStyle("H3", parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=11, spaceBefore=8, spaceAfter=4)

buf = io.BytesIO()
doc = SimpleDocTemplate(buf, pagesize=letter)
story = []

lines = narrative.split("\n")
for raw_line in lines:
    line = raw_line.strip()
    if not line:
        continue
    if line.startswith("#"):
        heading = re.sub(r"^#+\s*", "", line)
        story.append(_make_safe_paragraph(f"<b>{heading}</b>", style_h3, is_markdown=False))
        continue
    if re.match(r"^(\*|-|\d+\.)\s+", line):
        m_num = re.match(r"^(\d+\.)\s*", line)
        cleaned_bullet = re.sub(r"^(\*|-|\d+\.)\s*", "", line)
        prefix = f"{m_num.group(1)} " if m_num else "• "
        story.append(_make_safe_paragraph(f"{prefix}{cleaned_bullet}", style_bullet, is_markdown=True))
        continue
    story.append(_make_safe_paragraph(line, style_body, is_markdown=True))

doc.build(story)
print("SUCCESS! Document compiled cleanly, size:", len(buf.getvalue()))
