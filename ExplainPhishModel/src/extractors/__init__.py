"""
ExplainPhish Interface — Extractor Layer

Each sub-module exposes:
    extract(file_path: Path) -> dict[str, float | int | str]

Key contract:
  - Keys must exactly match models/<format>/selected_features.json.
  - Missing keys are an error; never silently filled with zeros.
  - No subprocess calls, no macro execution, read-only file access.
  - Security pre-checks (file size, ZIP bomb) are enforced in base.py.
"""