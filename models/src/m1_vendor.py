"""M1 Vendor Detector: rules + TF-IDF classifier (models.md §3). No DNN initially."""
from __future__ import annotations
import json, re
from pathlib import Path
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from src.common import VENDOR_SIGNATURES, ARTIFACTS

VEC = ARTIFACTS / "m1_vec.pkl"
CLF = ARTIFACTS / "m1_clf.pkl"


def rule_scores(text: str) -> dict:
    t = text.lower()
    scores = {}
    for v, sigs in VENDOR_SIGNATURES.items():
        scores[v] = sum(1 for s in sigs if s in t)
    return scores


def rule_predict(text: str):
    s = rule_scores(text)
    best = max(s, key=s.get)
    tot = sum(s.values()) or 1
    conf = s[best] / tot if s[best] else 0.31
    if s[best] == 0:
        return "unknown", 0.31
    return best, round(min(0.99, 0.5 + conf / 2), 3)


def train(corpus_dir: Path):
    from pathlib import Path as P
    X, y = [], []
    for f in P(corpus_dir).rglob("*.txt"):
        vendor = f.parent.parent.name
        X.append(f.read_text(errors="ignore"))
        y.append(vendor)
    vec = TfidfVectorizer(max_features=2000, ngram_range=(1, 2))
    Xa = vec.fit_transform(X)
    clf = LogisticRegression(max_iter=500)
    clf.fit(Xa, y)
    ARTIFACTS.mkdir(exist_ok=True)
    joblib.dump(vec, VEC); joblib.dump(clf, CLF)
    pred = clf.predict(Xa)
    return {"acc": accuracy_score(y, pred), "f1": f1_score(y, pred, average="macro"), "n": len(y)}


def predict(text: str):
    vendor_r, conf_r = rule_predict(text)
    try:
        vec = joblib.load(VEC); clf = joblib.load(CLF)
        probs = clf.predict_proba(vec.transform([text]))[0]
        best = probs.argmax()
        vendor_m, conf_m = clf.classes_[best], float(probs[best])
        # hybrid: rules win on strong signature, else ML; low-conf ML -> unknown (safe routing)
        if conf_r > 0.75:
            return {"vendor": vendor_r, "confidence": conf_r, "method": "rules"}
        if conf_m < 0.5:
            return {"vendor": "unknown", "confidence": round(1 - conf_m, 3), "method": "ml-gated",
                    "platform": "unknown", "rule_vendor": vendor_r}
        return {"vendor": str(vendor_m), "confidence": round(conf_m, 3), "method": "ml",
                "platform": str(vendor_m), "rule_vendor": vendor_r}
    except Exception:
        return {"vendor": vendor_r, "confidence": conf_r, "method": "rules-only", "platform": vendor_r}
