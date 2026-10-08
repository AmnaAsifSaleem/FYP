"""
tests/conftest.py
=================
Shared pytest configuration for the CAVE-OT test suite.

Layout
------
All tests live in tests/.  Sub-directories:
  tests/ui/   — Node.js browser regression scripts (require node on PATH)

What runs by default
--------------------
python -m pytest           (or just: pytest)

  • All tests in tests/*.py EXCEPT those that require a live PostgreSQL
    instance — those are skipped automatically unless CAVE_OT_TEST_DB=1.
  • Browser tests (test_alert_graph_ui, test_vulnerability_cards,
    test_scan_controls → test_browser_control_transitions) skip gracefully
    when node is not on PATH.
  • Remediation advisor LLM tests are NOT in this suite by design —
    they require a live GROQ_API_KEY and make outbound network requests.
    The remediation contract and blocked-approval tests that DO run here
    mock _call_groq, so they need no key and no internet access.

Opt-in live PostgreSQL tests
-----------------------------
$env:CAVE_OT_TEST_DB = '1'
python -m pytest

  Runs the 8 additional database integration tests in
  test_policy_database_flow.py using a disposable throwaway schema.
  They never write to production tables.

Path setup
----------
sys.path is extended here once so every test file can import from the
project root and from the three main sub-packages without duplicating the
same four sys.path.insert() calls in every file.
"""

import os
import sys

# ── Project root on sys.path ──────────────────────────────────────────────
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (
    _ROOT,
    os.path.join(_ROOT, "Dashboard"),
    os.path.join(_ROOT, "Database"),
    os.path.join(_ROOT, "Policy_Compliance"),
    os.path.join(_ROOT, "Remediation"),
):
    if _p not in sys.path:
        sys.path.insert(0, _p)
