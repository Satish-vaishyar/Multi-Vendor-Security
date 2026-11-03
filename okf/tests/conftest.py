import pytest


@pytest.fixture(autouse=True)
def _allow_external_llm_for_unit_tests(monkeypatch):
    """Gateway unit tests mock the HTTP layer; the production default (external LLM off) is
    covered separately in backend/tests/test_security.py."""
    monkeypatch.setenv("ALLOW_EXTERNAL_LLM", "true")


@pytest.fixture(autouse=True)
def _dummy_api_key_for_mocked_gateway(monkeypatch):
    """The module-level gateway reads FEATHERLESS_API_KEY once at import. The HTTP layer is mocked in these tests, so a
    dummy key keeps them independent of the developer's environment (previously they failed without a real key)."""
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent))
    import llm_gateway as gw
    monkeypatch.setattr(gw.gateway, "api_key", "test-key")
