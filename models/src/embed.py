"""Shared embedding backbone (M2/M3/M8): MiniLM if cached else TF-IDF char+word (offline)."""
from __future__ import annotations
import numpy as np
from pathlib import Path
import joblib
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from src.common import ARTIFACTS

_ST = None
def _try_minilm():
    global _ST
    try:
        from sentence_transformers import SentenceTransformer
        _ST = SentenceTransformer("all-MiniLM-L6-v2")
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
