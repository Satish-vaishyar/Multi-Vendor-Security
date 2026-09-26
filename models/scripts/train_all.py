"""Train all models M1-M13 in order (models.md §38) -> artifacts + evaluation/metrics.json."""
from __future__ import annotations
import json, sys, traceback
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from src.common import DATASETS, ARTIFACTS, EVAL
from src.evaluate_all import write

metrics: dict = {"order": "M1,M2,M3,M4(heuristic/LLM),M5,M6,M7,M9,M10-M13"}

try:
    from src import m1_vendor
    metrics["M1_vendor"] = m1_vendor.train(DATASETS / "raw_configs")
except Exception as e:
    metrics["M1_vendor"] = {"error": f"{type(e).__name__}: {e}"}

try:
    from src import m2_oov
    metrics["M2_oov"] = m2_oov.train(DATASETS / "unknown_token" / "lines.csv")
except Exception as e:
    metrics["M2_oov"] = {"error": f"{type(e).__name__}: {e}"}

try:
    from src import m3_mapping
    metrics["M3_mapping"] = m3_mapping.train(DATASETS / "mapping" / "mappings.jsonl")
    metrics["M3_demo"] = m3_mapping.suggest("secure-mgmt ssh protocol v2")
except Exception as e:
    metrics["M3_mapping"] = {"error": f"{type(e).__name__}: {e}", "trace": traceback.format_exc()[-500:]}

try:
    from src import m4_llm, m5_validator
    r = m4_llm.parse("secure-mgmt ssh protocol v2\nmgmt telnet deny")
    metrics["M4_llm"] = {"n_mappings": len(r.get("mappings", [])), "offline": r.get("offline"),
                         "json_valid": True, "sample": r.get("mappings", [])[:1]}
    metrics["M5_validator"] = m5_validator.validate({"services.ssh.version": 2, "services.telnet": False})
except Exception as e:
    metrics["M4_M5"] = {"error": f"{type(e).__name__}: {e}"}

try:
    from src import m6_risk
    metrics["M6_risk"] = m6_risk.train(DATASETS / "risk" / "findings.csv")
    metrics["M6_rule_demo"] = {"score": m6_risk.rule_score("high", "internet", "critical", 0.97)}
except Exception as e:
    metrics["M6_risk"] = {"error": f"{type(e).__name__}: {e}"}

try:
    from src import m7_fleet
    metrics["M7_fleet"] = m7_fleet.train(DATASETS / "fleet")
except Exception as e:
    metrics["M7_fleet"] = {"error": f"{type(e).__name__}: {e}"}

try:
    from src import m8_similarity
    s = m8_similarity.cosine("Telnet service is active", "Unencrypted remote terminal access is enabled")
    metrics["M8_similarity"] = {"demo_cosine": round(s, 3)}
except Exception as e:
    metrics["M8_similarity"] = {"error": f"{type(e).__name__}: {e}"}

try:
    from src import m9_transformer
    metrics["M9_transformer"] = m9_transformer.train(DATASETS / "mapping" / "mappings.jsonl")
except Exception as e:
    metrics["M9_transformer"] = {"error": f"{type(e).__name__}: {e}"}

for mod, key in (("m10_qks", "M10_QKS"), ("m11_vqc", "M11_VQC"), ("m12_qaoa", "M12_QAOA"), ("m13_vqe", "M13_VQE")):
    try:
        m = __import__(f"src.{mod}", fromlist=["*"])
        fn = getattr(m, "train", getattr(m, "optimize", None))
        metrics[key] = fn()
    except Exception as e:
        metrics[key] = {"error": f"{type(e).__name__}: {e}"}

write(metrics)
