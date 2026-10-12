# 🧪 ExplainPhish Test Suite

This directory contains automated unit and integration tests for ExplainPhish.

## Test Files
- [`test_web_api.py`](./test_web_api.py): Complete API test suite covering FastAPI routes, security controls, anti-SSRF protections, file upload limits, and JSON serialization.

## Full Documentation & Report
For detailed test specifications, endpoint coverage matrices, security assurance gates, and execution benchmarks, see:
👉 [**docs/api-test-documentation.md**](../docs/api-test-documentation.md)

## Running Tests

### Pytest (Verbose)
```bash
python3 -m pytest tests/test_web_api.py -v
```

### Direct Python Execution
```bash
python3 tests/test_web_api.py
```
