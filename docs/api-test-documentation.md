# 🧪 ExplainPhish — Web API Test Documentation & Verification Report

**Document Version:** `1.0.0`  
**Pipeline:** `ExplainPhish LangGraph SOC Agent v2.0`  
**Test Suite File:** [`tests/test_web_api.py`](file:///Users/jiaxianlim/Downloads/ExplainPhish-master/tests/test_web_api.py)  
**Execution Runtime:** `Python 3.13.6` | `pytest 9.0.3` | `FastAPI TestClient`  
**Overall Status:** ✅ **16 / 16 PASSED (100% Pass Rate)**

---

## 1. Executive Summary

This document serves as the formal test verification record for the **ExplainPhish Autonomous SOC Workstation Web API**. It records all endpoint definitions, security boundary protections, input validation rules, integration test cases, and execution results.

### Test Execution Benchmark
```text
===================================== test session starts ======================================
platform darwin -- Python 3.13.6, pytest-9.0.3, pluggy-1.6.0 -- /usr/local/bin/python3.13
cachedir: .pytest_cache
rootdir: /Users/jiaxianlim/Downloads/ExplainPhish-master
collected 16 items

tests/test_web_api.py::TestHealthAndDiscovery::test_health_endpoint PASSED               [  6%]
tests/test_web_api.py::TestHealthAndDiscovery::test_serve_frontend PASSED                [ 12%]
tests/test_web_api.py::TestHealthAndDiscovery::test_samples_endpoint PASSED              [ 18%]
tests/test_web_api.py::TestFileUploadAnalysis::test_upload_valid_html_file PASSED        [ 25%]
tests/test_web_api.py::TestFileUploadAnalysis::test_upload_oversized_file_rejected PASSED [ 31%]
tests/test_web_api.py::TestCatalogSampleAnalysis::test_analyze_existing_sample PASSED    [ 37%]
tests/test_web_api.py::TestCatalogSampleAnalysis::test_analyze_non_existent_sample PASSED [ 43%]
tests/test_web_api.py::TestURLAnalysisAndSecurity::test_anti_ssrf_blocks_private_hosts[http://localhost:8080/admin] PASSED [ 50%]
tests/test_web_api.py::TestURLAnalysisAndSecurity::test_anti_ssrf_blocks_private_hosts[http://127.0.0.1:5000/secret] PASSED [ 56%]
tests/test_web_api.py::TestURLAnalysisAndSecurity::test_anti_ssrf_blocks_private_hosts[http://0.0.0.0:8000/] PASSED [ 62%]
tests/test_web_api.py::TestURLAnalysisAndSecurity::test_anti_ssrf_blocks_private_hosts[http://192.168.1.1/router-login] PASSED [ 68%]
tests/test_web_api.py::TestURLAnalysisAndSecurity::test_anti_ssrf_blocks_private_hosts[http://10.0.0.5/internal] PASSED [ 75%]
tests/test_web_api.py::TestURLAnalysisAndSecurity::test_invalid_url_format PASSED        [ 81%]
tests/test_web_api.py::TestURLAnalysisAndSecurity::test_inaccessible_nxdomain_graceful_triage PASSED [ 87%]
tests/test_web_api.py::TestURLAnalysisAndSecurity::test_mocked_successful_url_fetch PASSED [ 93%]
tests/test_web_api.py::TestSanitizeResult::test_sanitize_result_converts_floats_and_handles_nested_dicts PASSED [100%]

====================================== 16 passed in 3.32s ======================================
```

---

## 2. API Endpoint Coverage Matrix

| Endpoint Route | HTTP Method | Handler Function | Security & Validation Controls | Test Status |
| :--- | :---: | :--- | :--- | :---: |
| `/api/health` | `GET` | `api_health()` | Service status, engine name, active ML architectures | ✅ PASSED |
| `/` | `GET` | `serve_frontend()` | Static file streaming, SPA fallback | ✅ PASSED |
| `/api/samples` | `GET` | `api_list_samples()` | Directory safety, file metadata discovery | ✅ PASSED |
| `/api/analyze/file` | `POST` | `api_analyze_file()` | Multipart parser, 50MB sandbox limit, filename sanitizer | ✅ PASSED |
| `/api/analyze/sample`| `POST` | `api_analyze_sample()` | Path existence check (404), catalog isolation | ✅ PASSED |
| `/api/analyze/url` | `POST` | `api_analyze_url()` | Anti-SSRF (RFC 1918 + loopback), URL parser, NXDOMAIN triage | ✅ PASSED |
| *Internal Helper* | `UTIL` | `sanitize_result()` | Converts NumPy `float32`/`int64` to native JSON floats/ints | ✅ PASSED |

---

## 3. Detailed Test Catalog & Verification Records

### Suite 1: Health & Discovery (`TestHealthAndDiscovery`)

#### `TEST-01`: Service Health Check (`test_health_endpoint`)
- **Route:** `GET /api/health`
- **Objective:** Verify operational readiness of the API and LangGraph pipeline.
- **Assertions:**
  - Status code equals `200 OK`
  - Body contains `"status": "healthy"`
  - `engine` string contains `"ExplainPhish LangGraph SOC Agent"`
  - Supported document formats list includes at least 4 formats (`HTML`, `PDF`, `Excel`, `Word`)
  - Active model architectures list includes Random Forest, Decision Tree, Neural Network, XGBoost, and LightGBM.
- **Result:** ✅ PASS

#### `TEST-02`: Frontend Entrypoint (`test_serve_frontend`)
- **Route:** `GET /`
- **Objective:** Ensure single-page web console (`index.html`) is served with correct `text/html` headers.
- **Assertions:**
  - Status code equals `200 OK`
  - `Content-Type` header includes `text/html`
  - Document body contains the `"ExplainPhish"` title string.
- **Result:** ✅ PASS

#### `TEST-03`: Sample Catalog Discovery (`test_samples_endpoint`)
- **Route:** `GET /api/samples`
- **Objective:** Ensure the catalog engine scans available sample folders and returns structured document items.
- **Assertions:**
  - Status code equals `200 OK`
  - Body contains list `"samples"`
- **Result:** ✅ PASS

---

### Suite 2: File Upload & Sandbox Protection (`TestFileUploadAnalysis`)

#### `TEST-04`: Valid HTML Document Analysis (`test_upload_valid_html_file`)
- **Route:** `POST /api/analyze/file`
- **Payload:** Multipart form-data containing simulated HTML credential form.
- **Objective:** Verify full 7-stage LangGraph execution on uploaded document.
- **Assertions:**
  - Status code equals `200 OK`
  - Final verdict returned (`MALICIOUS`, `BENIGN`, or `SUSPICIOUS`)
  - Risk categorization (`threat_level`, `confidence_score`)
  - Multi-model predictions list returned with $\ge 3$ models
  - Explainable AI (XAI) risk drivers populated with human-readable descriptions
  - MITRE ATT&CK techniques mapped (e.g. `T1566.002`)
  - Prescriptive SOAR playbooks and complete Markdown report generated.
- **Result:** ✅ PASS

#### `TEST-05`: Oversized Payload Rejection (`test_upload_oversized_file_rejected`)
- **Route:** `POST /api/analyze/file`
- **Payload:** File stream exceeding 50 MB (51 MB test buffer).
- **Objective:** Validate that the memory sandbox boundary prevents ZIP bombs / DoS payload exhaustion.
- **Assertions:**
  - Status code equals `400 Bad Request`
  - Error detail explicitly cites `"File size exceeds maximum 50MB sandbox limit"`.
- **Result:** ✅ PASS

---

### Suite 3: Catalog Sample Analysis (`TestCatalogSampleAnalysis`)

#### `TEST-06`: Analyze Existing Sample File (`test_analyze_existing_sample`)
- **Route:** `POST /api/analyze/sample`
- **Payload:** `{"sample_path": "<path_to_temporary_html_file>"}`
- **Objective:** Validate direct execution on sample file stored on disk.
- **Assertions:**
  - Status code equals `200 OK`
  - Response contains `final_verdict` and `ensemble_verdict`.
- **Result:** ✅ PASS

#### `TEST-07`: Missing Sample File Handling (`test_analyze_non_existent_sample`)
- **Route:** `POST /api/analyze/sample`
- **Payload:** `{"sample_path": "/path/to/definitely_non_existent_file_999.html"}`
- **Objective:** Ensure non-existent file paths return a clean 404 rather than internal server exceptions.
- **Assertions:**
  - Status code equals `404 Not Found`
  - Error message cites `"Sample file not found on disk"`.
- **Result:** ✅ PASS

---

### Suite 4: URL Analysis & Security Controls (`TestURLAnalysisAndSecurity`)

#### `TEST-08` to `TEST-12`: Anti-SSRF Attack Protection (`test_anti_ssrf_blocks_private_hosts`)
- **Route:** `POST /api/analyze/url`
- **Objective:** Protect enterprise network infrastructure from Server-Side Request Forgery (SSRF) attempts targeting cloud metadata endpoints, internal routers, and loopback servers.
- **Test Payloads Tested:**
  1. `http://localhost:8080/admin` (Local web port)
  2. `http://127.0.0.1:5000/secret` (IPv4 loopback)
  3. `http://0.0.0.0:8000/` (Any local interface)
  4. `http://192.168.1.1/router-login` (RFC 1918 Class C private gateway)
  5. `http://10.0.0.5/internal` (RFC 1918 Class A private network)
- **Assertions:**
  - Status code equals `400 Bad Request`
  - Error detail confirms `"Forbidden target: local and internal IP ranges are restricted."`
- **Result:** ✅ ALL 5 PASSED

#### `TEST-13`: Malformed URL Validation (`test_invalid_url_format`)
- **Route:** `POST /api/analyze/url`
- **Payload:** `{"url": "   "}` (Whitespace / Empty URL)
- **Objective:** Validate input rejection on empty or invalid URI schema.
- **Assertions:**
  - Status code equals `400 Bad Request`
  - Error detail cites `"Invalid URL format"`.
- **Result:** ✅ PASS

#### `TEST-14`: Inaccessible / Dead Domain Graceful Triage (`test_inaccessible_nxdomain_graceful_triage`)
- **Route:** `POST /api/analyze/url`
- **Payload:** `{"url": "https://definitely-non-existent-phishing-test-domain-12345.xyz"}`
- **Objective:** Phishing lures often become unreachable (DNS NXDOMAIN) once taken down. The API must not crash with 500/502; instead, it must generate an autonomous "Dismantled Domain" SOC incident dossier.
- **Assertions:**
  - Status code equals `200 OK`
  - Verdict contains `"INACCESSIBLE (DNS NXDOMAIN / Dead Domain)"`
  - Threat level assigned as `"SUSPICIOUS"`
  - MITRE ATT&CK technique mapped to `T1566.002` (Spearphishing Link)
  - Prescriptive SOAR actions generated for Registrar WHOIS queries and Passive DNS correlation.
- **Result:** ✅ PASS

#### `TEST-15`: Mocked Live Remote Ingestion (`test_mocked_successful_url_fetch`)
- **Route:** `POST /api/analyze/url`
- **Objective:** Emulate a successful HTTP retrieval of an active remote credential harvesting page and execute LangGraph triage without network dependency.
- **Assertions:**
  - Status code equals `200 OK`
  - Full triage response generated with valid verdict.
- **Result:** ✅ PASS

---

### Suite 5: Data Serialization & Type Parity (`TestSanitizeResult`)

#### `TEST-16`: NumPy Float/Int JSON Serialization (`test_sanitize_result_converts_floats_and_handles_nested_dicts`)
- **Helper:** `sanitize_result(res)`
- **Objective:** Scikit-learn, XGBoost, and LightGBM models output non-standard `np.float32`, `np.float64`, and `np.int64` scalars. If unhandled, FastAPI's JSON encoder or standard Pydantic serializers will raise `TypeError: Object of type float32 is not JSON serializable`.
- **Assertions:**
  - Successfully converts nested feature dictionaries containing NumPy types.
  - Confirms JSON serialization via `json.dumps()` completes without errors.
  - Verifies float/int types are converted to standard Python native types.
- **Result:** ✅ PASS

---

## 4. How to Run the Tests

### Method A: Pytest Command (Recommended)
```bash
/usr/local/bin/python3.13 -m pytest tests/test_web_api.py -v
```

### Method B: Direct Python Execution
```bash
/usr/local/bin/python3.13 tests/test_web_api.py
```

### Method C: Run with Code Coverage
```bash
/usr/local/bin/python3.13 -m pytest tests/test_web_api.py --cov=InterfaceExplainPhish
```

---

## 5. Security Summary & Quality Gates

```
+-------------------------------------------------------------------------+
|                  EXPLAINPHISH API SECURITY ASSURANCE                    |
+-------------------------------------------------------------------------+
| [√] Anti-SSRF Layer     : Blocks 127.0.0.1, localhost, 192.168.*, 10.*  |
| [√] DoS / File Boundary : Rejects files > 50 MB                         |
| [√] Safe Ingestion      : Static parsing only (Zero dynamic execution)  |
| [√] Ephemeral Triage    : Converts NXDOMAIN dead domains to SOC records |
| [√] Type Normalization  : Converts all NumPy scalars to standard JSON   |
| [√] Multi-Model Support : Random Forest, Decision Tree, Neural Network, |
|                           XGBoost, LightGBM (100% Feature Parity)       |
+-------------------------------------------------------------------------+
```
