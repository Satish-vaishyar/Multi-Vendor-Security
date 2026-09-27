"""Bridge to sibling folders.

`okf/src` and `models/src` are both top-level `src` packages with DISJOINT
module names and EMPTY `__init__.py` files, so they can share one importable
`src` package: okf's directory owns the package, and the models modules the
backend needs are registered under `src.*` from their file locations, in
dependency order. Everything is imported ONCE per process — no per-request
reloading, so the MiniLM backbone (M2/M3/M8) and sklearn artifacts stay hot.

Ownership (per docs):
- okf/      : Canonical Property Registry, Control KB, Compliance engine,
              Remediation KB, Risk engine, Mapping registry, LearningEngine
              (llm_gateway), full CVE engine.
- models/   : M1 vendor detector, M2 OOV, M3 mapping, M5 validator, M6 risk,
              M7 fleet, M8 similarity (M9–M13 research, never imported).
- backend/  : orchestration, REST API, PQC + Security Analytics engines.
"""
from __future__ import annotations
import importlib.util
import sys
import threading
from functools import lru_cache
from pathlib import Path

from app.core import config as cfg

_LOCK = threading.Lock()

# models modules the backend uses, in dependency order (common/embed first:
# the rest do `from src.common import ...` / `from src import embed`).
_MODELS_MODULES = ["common", "embed", "m1_vendor", "m2_oov", "m3_mapping",
                   "m5_validator", "m6_risk", "m7_fleet", "m8_similarity"]


def _ensure_paths() -> None:
    # NOTE: OKF_DIR must precede MODELS_DIR: both contain a top-level `src`
    # package and `import src` has to resolve to the OKF tree (each insert
    # goes to position 0, so insert models first).
    for p in (str(Path(cfg.MODELS_DIR)), str(Path(cfg.OKF_DIR))):
        if p in sys.path:
            sys.path.remove(p)
        sys.path.insert(0, p)


def _ensure_bridge() -> None:
    """Idempotently wire both `src` trees into one importable namespace."""
    with _LOCK:
        _ensure_paths()
        if "src" not in sys.modules:
            import src  # noqa: F401  (okf's package: empty __init__)
        import src as _pkg
        okf_init = Path(getattr(_pkg, "__file__", "") or "")
        if not (okf_init.parent / "learning_engine.py").exists():
            raise RuntimeError(f"`src` package is not the OKF tree: {okf_init}")
        models_src = Path(cfg.MODELS_DIR) / "src"
        for mod in _MODELS_MODULES:
            name = f"src.{mod}"
            if name in sys.modules:
                continue
            if not (models_src / f"{mod}.py").exists():
                # Missing tree (e.g. misconfigured MODELS_DIR): leave it
                # unregistered so the caller's try/except takes its fallback.
                continue
            spec = importlib.util.spec_from_file_location(name, models_src / f"{mod}.py")
            if spec is None or spec.loader is None:  # pragma: no cover - defensive
                raise RuntimeError(f"cannot locate models module {mod}")
            module = importlib.util.module_from_spec(spec)
            sys.modules[name] = module
            spec.loader.exec_module(module)


@lru_cache(maxsize=1)
def okf_layer():
    """Load OKF registries + engines once (103 props, 82 controls, 5 frameworks)."""
    _ensure_bridge()
    import src.property_registry as pr
    import src.control_kb as ckb_mod
    import src.knowledge_extras as kx
    import src.engines as eng
    import src.learning_engine as le
    props = pr.PropertyRegistry().load()
    ckb = ckb_mod.ControlKB().load()
    fwk = ckb_mod.FrameworkRegistry().load()
    xwalk = ckb_mod.Crosswalk().load()
    rem = kx.RemediationKB().load()
    maps = kx.MappingRegistry().load()
    learn = le.LearningEngine(maps)
    return {"props": props, "ckb": ckb, "fwk": fwk, "xwalk": xwalk, "rem": rem,
            "maps": maps, "learn": learn, "nest": kx.nest_flat_ir,
            "ComplianceEngine": eng.ComplianceEngine, "RiskEngine": kx.RiskEngine}


@lru_cache(maxsize=1)
def cve_layer():
    _ensure_bridge()
    from src.cve.kb import VulnKB
    from src.cve import inventory, correlator
    from src.cve.cbom import build_cbom
    from src.cve.update import sync_now, assets_affected
    return {"kb": VulnKB, "inventory": inventory, "correlator": correlator,
            "build_cbom": build_cbom, "sync_now": sync_now,
            "assets_affected": assets_affected}


def m1_predict(text: str) -> dict:
    """M1 Vendor Detector (rules + TF-IDF LogReg, artifacts in models/)."""
    _ensure_bridge()
    try:
        from src.m1_vendor import predict
        return predict(text)
    except Exception as e:
        return {"vendor": "unknown", "confidence": 0.31, "method": f"fallback:{e}"}


def m6_rule_score(severity="medium", exposure="internal", asset_criticality="medium", confidence=0.9) -> float:
    _ensure_bridge()
    try:
        from src.m6_risk import rule_score
        return rule_score(severity, exposure, asset_criticality, confidence)
    except Exception:
        sev = {"low": 1, "medium": 2, "high": 3, "critical": 4}.get(severity, 2)
        return round(sev * confidence, 3)


# OKF canonical namespace -> models M7 feature namespace (models.md §17-18).
OKF_TO_M7 = {
    "SSH.VERSION": "services.ssh.version",
    "TELNET.ENABLED": "services.telnet",
    "HTTP.ENABLED": "services.http",
    "LOGGING.ENABLED": "logging.enabled",
    "AAA.AUTHENTICATION": "aaa.authentication",
    "CRYPTO.RSA_KEY_SIZE": "crypto.key_size",
}


def okf_flat_to_m7(flat: dict) -> dict:
    """Map an OKF flat IR to the models-namespace feature dict M7 expects."""
    return {m7k: flat.get(okfk) for okfk, m7k in OKF_TO_M7.items()}


def m2_score_batch(commands: list) -> list:
    """M2 Unknown Token Detector over a batch (oov_score per line)."""
    if not commands:
        return []
    _ensure_bridge()
    try:
        import json
        import joblib
        from src.common import ARTIFACTS
        from src import embed
        from src.m2_oov import tokens, novelty
        d = joblib.load(ARTIFACTS / "m2_clf.pkl")
        meta = json.loads((ARTIFACTS / "m2_meta.json").read_text()) \
            if (ARTIFACTS / "m2_meta.json").exists() else {"threshold": 0.5, "k": 1.0}
        clf, vocab = (d["clf"], set(d["vocab"])) if isinstance(d, dict) else (d, set())
        thr, k = meta.get("threshold", 0.5), meta.get("k", 1.0)
        ml = [float(p[1]) for p in clf.predict_proba(embed.encode(commands))]
        nv = novelty(commands, vocab)
        scored = []
        for a, b in zip(ml, nv):
            s = max(a, min(1.0, b * k))
            scored.append({"label": "unknown" if s >= thr else "known",
                           "oov_score": round(s, 3), "threshold": thr})
        return scored
    except Exception as e:
        return [{"label": "unknown", "oov_score": 0.5, "error": str(e)} for _ in commands]


def m3_suggest(command: str, vendor: str = "unknown", topk: int = 3) -> list:
    """M3 Mapping Model top-k (embedding + kNN over 5400 verified mappings)."""
    _ensure_bridge()
    try:
        from src.m3_mapping import suggest
        return suggest(command, vendor, topk)
    except Exception as e:
        return [{"error": str(e)}]


def m5_validate(flat_ir: dict) -> dict:
    """M5 Canonical IR Validator (pydantic + business rules)."""
    _ensure_bridge()
    try:
        from src.m5_validator import validate
        return validate({k.lower().replace("_", "."): v for k, v in flat_ir.items()}
                        if any("_" in k for k in flat_ir) else flat_ir)
    except Exception as e:
        return {"valid": True, "errors": [], "warning": str(e)}


def m7_fit_fleet(feature_dicts: list) -> dict:
    """M7 Fleet Anomaly, fit per fleet (models.md §17: HDBSCAN, KMeans fallback)."""
    _ensure_bridge()
    try:
        import numpy as np
        from src.m7_fleet import _vec
        X = np.array([_vec(d) for d in feature_dicts])
        n = len(X)
        if n < 2:
            return {"method": "none", "outliers": [False] * n, "labels": [0] * n}
        try:
            import hdbscan
            clf = hdbscan.HDBSCAN(min_cluster_size=max(2, n // 4)).fit(X)
            labels = [int(l) for l in clf.labels_]
            out = [l == -1 for l in labels]
            method = "hdbscan"
        except Exception:
            from sklearn.cluster import KMeans
            k = 2 if n >= 4 else 1
            clf = KMeans(n_clusters=k, n_init=10, random_state=42).fit(X)
            labels = [int(l) for l in clf.labels_]
            method = "kmeans"
            if k == 2:
                c0 = sum(1 for l in labels if l == 0)
                minority = 0 if c0 <= n - c0 else 1
                out = [l == minority and min(c0, n - c0) <= max(1, n // 3) for l in labels]
            else:
                out = [False] * n
        return {"method": method, "labels": labels, "outliers": out, "n": n}
    except Exception as e:
        return {"method": f"fallback:{e}", "outliers": [False] * len(feature_dicts),
                "labels": [0] * len(feature_dicts)}


def m8_dedup(texts: list, thresh: float = 0.85) -> list:
    """M8 semantic dedup — returns kept indices (models.md §19)."""
    _ensure_bridge()
    try:
        from src import embed
        E = embed.encode(texts)
        keep = []
        for i in range(len(texts)):
            if any(float(E[i] @ E[j]) > thresh for j in keep):
                continue
            keep.append(i)
        return keep
    except Exception:
        return list(range(len(texts)))
