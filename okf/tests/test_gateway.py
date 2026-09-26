"""Gateway tests (mocked HTTP): covers llm_gateway.py without touching the network."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import httpx  # noqa: E402
import llm_gateway as gw  # noqa: E402
from llm_gateway import (FeatherlessGateway, parse_config_to_ir, suggest_mapping,  # noqa: E402
                         interpret_unknown_token, list_models)


class FakeResp:
    def __init__(self, status=200, payload=None, text=""):
        self.status_code = status
        self._payload = payload
        self.text = text or ""

    def json(self):
        return self._payload


def _chat_payload(content):
    return {"choices": [{"message": {"content": content}}]}


def test_chat_success(monkeypatch):
    monkeypatch.setattr(httpx, "post", lambda *a, **k: FakeResp(200, _chat_payload("hi")))
    r = gw.gateway.chat([{"role": "user", "content": "x"}])
    assert r.ok and r.raw == "hi"


def test_chat_offline_no_key():
    r = FeatherlessGateway(api_key="").chat([{"role": "user", "content": "x"}])
    assert not r.ok and r.offline and "OFFLINE" in r.error


def test_chat_http_error(monkeypatch):
    monkeypatch.setattr(httpx, "post", lambda *a, **k: FakeResp(500, None, "boom"))
    r = gw.gateway.chat([{"role": "user", "content": "x"}])
    assert not r.ok and "500" in r.error


def test_chat_exception(monkeypatch):
    def _raise(*a, **k):
        raise ConnectionError("down")
    monkeypatch.setattr(httpx, "post", _raise)
    r = gw.gateway.chat([{"role": "user", "content": "x"}])
    assert not r.ok and "down" in r.error


def test_extract_and_coerce():
    assert FeatherlessGateway._extract_json("no json here") is None
    assert FeatherlessGateway._extract_json("{bad json}") is None  # braces, invalid JSON
    c = FeatherlessGateway._coerce
    assert c("42") == 42 and c("3.5") == 3.5 and c("true") is True
    assert c("FALSE") is False and c("2c") == "2c" and c(2) == 2 and c(None) is None


def test_parse_online_success(monkeypatch):
    raw = ('[{"line": "ip ssh version 2", "canonical_property": "SSH.VERSION", '
           '"canonical_value": "2", "confidence": 0.9}, '
           '{"line": "x", "canonical_property": "NOPE", "canonical_value": 1}]')
    monkeypatch.setattr(gw.gateway, "chat",
                        lambda *a, **k: gw.GatewayResponse(ok=True, model="m", raw=raw))
    out = parse_config_to_ir("ip ssh version 2", vendor="cisco")
    assert out["offline"] is False and out["mappings"][0]["canonical_value"] == 2
    assert len(out["mappings"]) == 1  # invalid property filtered


def test_parse_fallback_paths(monkeypatch):
    monkeypatch.setattr(gw.gateway, "chat",
                        lambda *a, **k: gw.GatewayResponse(ok=False, model="m", error="e"))
    out = parse_config_to_ir("ip ssh version 2", vendor="cisco")
    assert out["mappings"] and out["mappings"][0]["canonical_property"] == "SSH.VERSION"
    monkeypatch.setattr(gw.gateway, "chat",
                        lambda *a, **k: gw.GatewayResponse(ok=True, model="m",
                                                           raw='{"not": "a list"}'))
    out2 = parse_config_to_ir("ip ssh version 2", vendor="cisco")
    assert out2["mappings"]  # non-list LLM output -> heuristic fallback


def test_suggest_paths(monkeypatch):
    monkeypatch.setattr(gw.gateway, "chat",
                        lambda *a, **k: gw.GatewayResponse(
                            ok=True, model="m",
                            raw='{"suggestions": [{"canonical_property": "SSH.VERSION", '
                                '"value": "2", "confidence": 0.9}, '
                                '{"canonical_property": "NOPE", "value": 1}]}'))
    s = suggest_mapping("whatever", vendor="cisco")
    assert s["offline"] is False and s["training_suggestions"][0]["value"] == 2
    assert len(s["training_suggestions"]) == 1
    # invalid shape -> heuristic hit
    monkeypatch.setattr(gw.gateway, "chat",
                        lambda *a, **k: gw.GatewayResponse(ok=True, model="m", raw='{"x": []}'))
    h = suggest_mapping("ip ssh version 2", vendor="cisco")
    assert h["training_suggestions"][0]["canonical_property"] == "SSH.VERSION"
    # heuristic miss -> generic defaults
    d = suggest_mapping("blorp xyz hyperflux", vendor="unknown")
    assert len(d["training_suggestions"]) == 3


def test_interpret_paths(monkeypatch):
    calls = []
    # KNOWN via heuristic, chat must not fire
    monkeypatch.setattr(gw.gateway, "chat", lambda *a, **k: calls.append(1) or
                        gw.GatewayResponse(ok=False, model="m", error="e"))
    assert interpret_unknown_token("ip ssh version 2")["status"] == "KNOWN"
    assert calls == []
    # online verdict
    monkeypatch.setattr(gw.gateway, "chat", lambda *a, **k: gw.GatewayResponse(
        ok=True, model="m", raw='{"status": "UNKNOWN", "reason": "never seen"}'))
    r = interpret_unknown_token("blorp xyz hyperflux")
    assert r["status"] == "UNKNOWN" and r["offline"] is False
    # online garbage -> offline fallback
    monkeypatch.setattr(gw.gateway, "chat", lambda *a, **k: gw.GatewayResponse(
        ok=True, model="m", raw="not json"))
    assert interpret_unknown_token("blorp xyz hyperflux")["status"] == "UNKNOWN"
    # forced offline UNCERTAIN (low-confidence heuristic hit)
    monkeypatch.setattr(gw.gateway, "api_key", "")
    u = interpret_unknown_token("shutdown")
    assert u["status"] == "UNCERTAIN" and u["offline"] is True
    assert interpret_unknown_token("blorp xyz hyperflux")["status"] == "UNKNOWN"


def test_list_models_paths(monkeypatch):
    monkeypatch.setattr(gw.gateway, "api_key", "")
    assert list_models()["offline"] is True
    monkeypatch.setattr(gw.gateway, "api_key", "k")
    monkeypatch.setattr(httpx, "get", lambda *a, **k: FakeResp(200, {"data": []}))
    assert list_models()["offline"] is False
    def _raise(*a, **k):
        raise TimeoutError("t")
    monkeypatch.setattr(httpx, "get", _raise)
    assert "error" in list_models()
