import pytest


@pytest.fixture(autouse=True)
def _allow_external_llm_for_unit_tests(monkeypatch):
    """Gateway unit tests mock the HTTP layer; the production default (external LLM off) is
    covered separately in backend/tests/test_security.py."""
    monkeypatch.setenv("ALLOW_EXTERNAL_LLM", "true")
