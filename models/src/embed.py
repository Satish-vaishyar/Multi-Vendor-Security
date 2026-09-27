"""Shared embedding backbone (M2/M3/M8): vendored MiniLM, else HF cache, else TF-IDF.

Load order (all offline, no network at runtime):
  1. models/artifacts/minilm/  — snapshot vendored by models/scripts/download_minilm.py
     during application setup (override path with MINILM_DIR).
  2. HuggingFace cache entry for sentence-transformers/all-MiniLM-L6-v2.
  3. TF-IDF fallback (char+word) — always available.
"""
from __future__ import annotations
import numpy as np
from pathlib import Path
import joblib
import os
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from src.common import ARTIFACTS

# Offline-first: never re-validate dozens of files over the network on every
# process start (that HEAD storm is what stalls the first API request for
# ~40 s). Override with HF_HUB_OFFLINE=0 to allow a fresh download.
os.environ.setdefault("HF_HUB_OFFLINE", "1")
os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")

MINILM_DIR = Path(os.environ.get("MINILM_DIR", str(ARTIFACTS / "minilm")))
MINILM_REPO = "sentence-transformers/all-MiniLM-L6-v2"
_MODEL_SOURCE = "tfidf"


def _snapshot_ok(d: Path) -> bool:
    return (d / "config.json").exists() and (any(d.glob("*.safetensors")) or any(d.glob("*.bin")))


_ST = None
def _try_minilm():
    global _ST, _MODEL_SOURCE
    try:
        from sentence_transformers import SentenceTransformer
        offline = os.environ.get("HF_HUB_OFFLINE", "1") == "1"
        if _snapshot_ok(MINILM_DIR):
            _ST = SentenceTransformer(str(MINILM_DIR), local_files_only=True)
            _MODEL_SOURCE = f"vendored:{MINILM_DIR}"
            return True
        _ST = SentenceTransformer(MINILM_REPO, local_files_only=offline)
        _MODEL_SOURCE = "hf-cache"
        return True
    except Exception:
        return False

_HAS_MINI = _try_minilm()
_VEC_PATH = ARTIFACTS / "emb_tfidf.pkl"


def fit_tfidf(texts: list[str]):
    from sklearn.feature_extraction.text import TfidfVectorizer
    v = TfidfVectorizer(max_features=3000, analyzer="word", ngram_range=(1, 2))
    v.fit(texts)
    ARTIFACTS.mkdir(exist_ok=True)
    joblib.dump(v, _VEC_PATH)
    return v


def encode(texts: list[str]) -> np.ndarray:
    if _HAS_MINI:
        return np.array(_ST.encode(texts, normalize_embeddings=True))
    try:
        v = joblib.load(_VEC_PATH)
    except Exception:
        fit_tfidf(texts)
        v = joblib.load(_VEC_PATH)
    from sklearn.preprocessing import normalize
    return normalize(v.transform(texts).toarray())
