"""
Pytest configuration and shared fixtures for ExplainPhish test suite.
"""

import sys
from pathlib import Path

# Ensure workspace root and InterfaceExplainPhish are always on sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
INTERFACE_DIR = ROOT_DIR / "InterfaceExplainPhish"

for p in (ROOT_DIR, INTERFACE_DIR):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))
