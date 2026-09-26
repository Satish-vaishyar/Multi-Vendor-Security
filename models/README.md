# SIH 26155 — Models (M1–M13) + Datasets
# Implements `docs/models.md`. ALL work lives in this folder only.

## Layout
```
models/
  README.md
  requirements.txt
  src/
    __init__.py
    common.py        # canonical properties (~120), vendor templates, helpers
    m1_vendor.py     # M1 Vendor Detector (rules + TF-IDF classifier)
    m2_oov.py        # M2 Unknown Token Detector (embedding + OOV classifier)
    m3_mapping.py    # M3 Config Mapping Model (embedding + kNN/centroid)
    m4_llm.py        # M4 LLM Config Parser (pretrained LLM wrapper, okf llm_gateway reuse)
    m5_validator.py  # M5 Canonical IR Validator (pydantic/schema)
    m6_risk.py       # M6 Risk Scoring (rules -> XGBoost)
    m7_fleet.py      # M7 Fleet Anomaly (HDBSCAN/KMeans w/ sklearn fallback)
    m8_similarity.py # M8 Semantic similarity / dedup (shared embedding backbone)
    m9_transformer.py# M9 Small Transformer baseline (torch tiny encoder)
    m10_qks.py       # M10 QKS quantum kernel classifier
    m11_vqc.py       # M11 VQC variational classifier
    m12_qaoa.py      # M12 QAOA remediation prioritizer
    m13_vqe.py       # M13 VQE weight optimizer
    evaluate_all.py  # unified evaluation -> evaluation/metrics.json
  scripts/
    build_datasets.py  # generates all datasets/* per models.md targets
    train_all.py       # trains M1,M2,M3,M6,M7,M9 + quantum demos, saves artifacts/*.pkl
  datasets/      # generated (gitignored large files, manifests kept)
  artifacts/     # trained models (*.pkl/json)
  evaluation/    # metrics.json
```

## Quickstart (Windows PowerShell)
```powershell
cd F:\Multi-vendor\models
pip install -r requirements.txt
python scripts\build_datasets.py --full   # ~3000 configs, 13k lines, 3-5k mappings, etc.
python scripts\train_all.py              # trains + evaluates
python -m src.evaluate_all                # re-print metrics
```

## Design notes (from docs/models.md)
- Layered: deterministic parsers win, AI fills gaps (§7 arch.md, §11-13 models.md).
- M10–M13 are RESEARCH ONLY, never dependencies of the auditor (§2, §39).
- Device-level splits (no line leakage) for M2/M3 (§5, §35).
- Canonical IR frozen at ~100-150 props before M3 training (§9).
