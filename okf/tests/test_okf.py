"""OKF regression tests: engines, crosswalk, learning loop, gateway-offline."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from src.control_kb import ControlKB
from src.engines import ComplianceEngine, eval_op
from src.knowledge_extras import MappingRegistry, nest_flat_ir
from src.learning_engine import LearningEngine

def test_operators():
    assert eval_op(2, "EQUALS", 2) is True
    assert eval_op(1, "EQUALS", 2) is False
    assert eval_op(None, "EQUALS", 2) is None
    assert eval_op("3", "GTE", 2) is True
    assert eval_op("x", "IN", ["x", "y"]) is True

def test_insecure_config_fails():
    ckb = ControlKB().load()
    maps = MappingRegistry().load()
    learn = LearningEngine(maps)
    cfg = "ip ssh version 1\nip http server\ntransport input telnet\nsnmp-server community public\n"
    parsed = learn.audit_config(cfg, vendor="cisco")
    findings = ComplianceEngine(ckb.all()).evaluate(parsed["nested_ir"])
    by_id = {f.control_id: f.status for f in findings}
    assert by_id["OKF-SSH-001"] == "FAIL"
    assert by_id["OKF-TELNET-001"] == "FAIL"
    assert by_id["OKF-HTTP-001"] == "FAIL"

def test_secure_config_passes():
    ckb = ControlKB().load()
    maps = MappingRegistry().load()
    learn = LearningEngine(maps)
    cfg = "ip ssh version 2\nno ip http server\ntransport input ssh\n"
    parsed = learn.audit_config(cfg, vendor="cisco")
    findings = ComplianceEngine(ckb.all()).evaluate(parsed["nested_ir"])
    by_id = {f.control_id: f.status for f in findings}
    assert by_id["OKF-SSH-001"] == "PASS"
    assert by_id["OKF-TELNET-001"] == "PASS"

def test_gateway_single_file_rule():
    import pathlib
    gw = pathlib.Path(__file__).parent.parent / "llm_gateway.py"
    assert gw.exists()
    src_files = list((pathlib.Path(__file__).parent.parent / "src").glob("*.py"))
    for f in src_files:
        txt = f.read_text(encoding="utf-8")
        assert "api.featherless.ai" not in txt, f"LLM call outside gateway: {f.name}"
        assert "FEATHERLESS_API_KEY" not in txt, f"API key outside gateway: {f.name}"
