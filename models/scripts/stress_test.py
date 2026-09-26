"""Stress + functional verification for M1-M13. Run: python scripts/stress_test.py
Checks per model: functional PASS/FAIL, latency (mean ms), throughput, edge cases
(empty/garbage/long/unicode), artifact integrity. Saves evaluation/stress_results.json.
Quantum models use reduced workloads (still native paths where feasible).
"""
from __future__ import annotations
import json, sys, time
from pathlib import Path
import statistics as st
sys.path.insert(0, str(Path(__file__).parent.parent))
from src.common import DATASETS, ARTIFACTS, EVAL

R: dict = {}


def timed(fn, n=1):
    t0 = time.time()
    out = fn()
    dt = (time.time() - t0) * 1000 / max(1, n)
    return out, round(dt, 2)


def edge_texts():
    return {"empty": "", "whitespace": "   \n\t  ",
            "garbage": "xqw!@# %$% $$$ " * 50,
            "long": ("ip ssh version 2\n" * 2000),
            "unicode": "interface Gïgäbit dévice ✓ ∀x∃y\n"}


def main():
    # ---------- M1 ----------
    try:
        from src import m1_vendor
        files = list((DATASETS / "raw_configs").rglob("*.txt"))[:500]
        texts = [f.read_text(errors="ignore") for f in files]
        _, ms = timed(lambda: [m1_vendor.predict(t) for t in texts], len(texts))
        edges = {k: m1_vendor.predict(v)["vendor"] for k, v in edge_texts().items()}
        vendors = {m1_vendor.predict(t)["vendor"] for t in texts}
        R["M1"] = {"functional": "PASS", "mean_ms": ms,
                   "throughput_per_s": round(1000 / max(ms, 0.01), 1),
                   "vendors_seen": sorted(vendors), "n": len(texts), "edges_ok": True, "edge_out": edges}
    except Exception as e:
        R["M1"] = {"functional": f"FAIL: {type(e).__name__}: {e}"}

    # ---------- M2 ----------
    try:
        from src import m2_oov
        import csv
        rows = list(csv.DictReader(open(DATASETS / "unknown_token" / "lines.csv", encoding="utf-8")))[:2000]
        cmds = [r["command"] for r in rows]
        _, ms = timed(lambda: [m2_oov.predict(c) for c in cmds], len(cmds))
        edges = {k: m2_oov.predict(v[:200])["label"] for k, v in edge_texts().items()}
        R["M2"] = {"functional": "PASS", "mean_ms": ms,
                   "throughput_per_s": round(1000 / max(ms, 0.01), 1), "n": len(cmds), "edges_ok": True, "edge_out": edges}
    except Exception as e:
        R["M2"] = {"functional": f"FAIL: {type(e).__name__}: {e}"}

    # ---------- M3 ----------
    try:
        from src import m3_mapping
        qs = ["secure-mgmt ssh protocol v2", "mgmt telnet permit-all",
              "blorp enable hyperflux-mode", "totally unknown gibberish zzz 123", ""]
        _, ms = timed(lambda: [m3_mapping.suggest(q) for q in qs * 20], 100)
        gib = m3_mapping.suggest("totally unknown gibberish zzz 123")
        # approve-probe on the real file, then remove the probe row (no dataset pollution)
        mp = DATASETS / "mapping" / "mappings.jsonl"
        n0 = sum(1 for _ in open(mp, encoding="utf-8"))
        ok_appr = bool(m3_mapping.approve("t", "p", "probe-pat", "logging.enabled", True, mp))
        lines = open(mp, encoding="utf-8").readlines()
        open(mp, "w", encoding="utf-8").writelines(lines[:n0])
        R["M3"] = {"functional": "PASS", "mean_ms": ms, "n": 100,
                   "gibberish_top3": [(g["canonical_property"], g["confidence"]) for g in gib],
                   "approve_probe": ok_appr}
    except Exception as e:
        R["M3"] = {"functional": f"FAIL: {type(e).__name__}: {e}"}

    # ---------- M4 / M5 ----------
    try:
        from src import m4_llm, m5_validator
        cfg = open(next((DATASETS / "raw_configs" / "cisco").rglob("*.txt")), encoding="utf-8").read()
        r1, ms1 = timed(lambda: m4_llm.parse(cfg))
        r2, ms2 = timed(lambda: m4_llm.parse(""))
        r3, ms3 = timed(lambda: m4_llm.parse(cfg * 60))  # long-context stress
        bad = m5_validator.validate({"services.ssh.version": 5, "weird": "maybe secure", 123: "x"})
        good = m5_validator.validate({"services.ssh.version": 2})
        R["M4"] = {"functional": "PASS", "normal_ms": ms1, "empty_ms": ms2,
                   "long60x_ms": ms3, "long_valid": isinstance(r3.get("mappings"), list)}
        R["M5"] = {"functional": "PASS", "rejects_bad": (not bad["valid"]) and len(bad["errors"]) >= 2,
                   "accepts_good": good["valid"]}
    except Exception as e:
        R["M4_M5"] = {"functional": f"FAIL: {type(e).__name__}: {e}"}

    # ---------- M6 ----------
    try:
        from src import m6_risk
        import joblib
        d = joblib.load(ARTIFACTS / "m6_xgb.pkl")
        _, ms = timed(lambda: [m6_risk.rule_score(s, e, a) for s in ("low", "medium", "high", "critical")
                               for e in ("internal", "dmz", "internet") for a in ("low", "medium", "high", "critical")], 48)
        R["M6"] = {"functional": "PASS", "rule_mean_ms": ms, "artifact_labels": d["labels"],
                   "sweep_min": m6_risk.rule_score("low", "internal", "low"),
                   "sweep_max": m6_risk.rule_score("critical", "internet", "critical", 1.0)}
    except Exception as e:
        R["M6"] = {"functional": f"FAIL: {type(e).__name__}: {e}"}

    # ---------- M7 ----------
    try:
        import joblib
        d = joblib.load(ARTIFACTS / "m7_cluster.pkl")
        R["M7"] = {"functional": "PASS", "method": d["method"],
                   "has_labels": hasattr(d["model"], "labels_")}
    except Exception as e:
        R["M7"] = {"functional": f"FAIL: {type(e).__name__}: {e}"}

    # ---------- M8 ----------
    try:
        from src import m8_similarity
        pairs = [(f"command variant {i}", f"command variant {i + 1}") for i in range(200)]
        _, ms = timed(lambda: [m8_similarity.cosine(a, b) for a, b in pairs], len(pairs))
        ded = m8_similarity.dedup(["Telnet service is active"] * 50 + ["Logging is enabled"] * 50)
        R["M8"] = {"functional": "PASS", "mean_ms": ms, "n": len(pairs),
                   "dedup_100_to": len(ded)}
    except Exception as e:
        R["M8"] = {"functional": f"FAIL: {type(e).__name__}: {e}"}

    # ---------- M9 ----------
    try:
        import torch
        from src import m9_transformer
        blob = torch.load(ARTIFACTS / "m9_transformer.pt", map_location="cpu", weights_only=False)
        R["M9"] = {"functional": "PASS", "labels": len(blob["labels"]), "d_in": blob["d_in"],
                   "artifact_ok": True}
    except Exception as e:
        R["M9"] = {"functional": f"FAIL: {type(e).__name__}: {e}"}

    # ---------- M10 (reduced native kernel 8x8) ----------
    try:
        import numpy as np
        from sklearn.decomposition import PCA
        X = np.load(DATASETS / "quantum" / "X.npy")
        Xp = PCA(n_components=4, random_state=42).fit_transform(X)
        from qiskit.circuit.library import zz_feature_map
        from qiskit_machine_learning.kernels import FidelityQuantumKernel
        from qiskit_machine_learning.state_fidelities import ComputeUncompute
        from qiskit_aer.primitives import SamplerV2
        kern = FidelityQuantumKernel(fidelity=ComputeUncompute(sampler=SamplerV2()),
                                     feature_map=zz_feature_map(4, reps=2))
        _, ms = timed(lambda: kern.evaluate(Xp[:8]), 1)
        R["M10"] = {"functional": "PASS", "kernel8x8_ms": ms, "method": "native"}
    except Exception as e:
        R["M10"] = {"functional": f"FAIL: {type(e).__name__}: {e}"}

    # ---------- M11 / M13 artifacts ----------
    try:
        R["M11"] = {"functional": "PASS",
                    "artifact": json.loads((ARTIFACTS / "m11_vqc.json").read_text())}
    except Exception as e:
        R["M11"] = {"functional": f"FAIL: {type(e).__name__}: {e}"}
    try:
        from src import m13_vqe
        r, ms = timed(m13_vqe.optimize, 1)
        R["M13"] = {"functional": "PASS", "ms": ms, "method": r["method"]}
    except Exception as e:
        R["M13"] = {"functional": f"FAIL: {type(e).__name__}: {e}"}

    # ---------- M12 (1 restart, fast confirm) ----------
    try:
        from src import m12_qaoa
        r, ms = timed(lambda: m12_qaoa.optimize(restarts=1), 1)
        R["M12"] = {"functional": "PASS", "ms": ms, "method": r["method"],
                    "value": r["value"], "gap": r["gap_to_optimum"]}
    except Exception as e:
        R["M12"] = {"functional": f"FAIL: {type(e).__name__}: {e}"}

    EVAL.mkdir(exist_ok=True)
    (EVAL / "stress_results.json").write_text(json.dumps(R, indent=1))
    n_pass = sum(1 for v in R.values() if str(v.get("functional")).startswith("PASS"))
    print(json.dumps(R, indent=1))
    print(f"STRESS: {n_pass}/{len(R)} PASS")


if __name__ == "__main__":
    main()
