"""M2 Unknown Token Detector + M8 similarity (embeddings, no fine-tune initially).

Hybrid (models.md §4: embedding + OOV classifier + threshold):
  score = max(ml_prob, novelty * K)   with (threshold, K) tuned on val for max F1.
  novelty = fraction of word-tokens never seen in TRAIN-known vocabulary.
  Novel tokens (hyperflux, neuro-route, cryptochamber...) flag unseen families
  that a linear probe on frozen embeddings misses.
"""
from __future__ import annotations
import csv, re, time
from pathlib import Path
import joblib, numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import precision_recall_fscore_support
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from src.common import ARTIFACTS
from src import embed

CLF = ARTIFACTS / "m2_clf.pkl"
META = ARTIFACTS / "m2_meta.json"
TOK = re.compile(r"[a-z0-9][a-z0-9\-_]*")


def tokens(s: str) -> list[str]:
    toks = TOK.findall(s.lower())
    return [t for t in toks if not t.isdigit()]


def _metrics(y_true, score, thr):
    pred = [1 if s >= thr else 0 for s in score]
    pr, rc, f1, _ = precision_recall_fscore_support(y_true, pred, average="binary", zero_division=0)
    known_idx = [i for i, y in enumerate(y_true) if y == 0]
    fpr = float(sum(pred[i] for i in known_idx) / max(1, len(known_idx)))
    cov = float(sum(pred) / max(1, len(pred)))
    unk_scores = [score[i] for i, y in enumerate(y_true) if y == 1]
    mean_unk = float(sum(unk_scores) / max(1, len(unk_scores)))
    return {"precision": round(pr, 3), "recall": round(rc, 3), "f1": round(f1, 3),
            "false_parse_rate": round(fpr, 3), "coverage": round(cov, 3),
            "mean_unknown_score": round(mean_unk, 3), "n": len(y_true), "threshold": thr}


def novelty(cmds: list[str], vocab: set[str]) -> list[float]:
    out = []
    for c in cmds:
        t = tokens(c)
        out.append(sum(1 for w in t if w not in vocab) / max(1, len(t)))
    return out


def train(csv_path: Path):
    import json
    t0 = time.time()
    rows = list(csv.DictReader(open(csv_path, encoding="utf-8")))
    def part(s): return [r for r in rows if r["split"] == s]
    tr, va, te = part("train"), part("val"), part("test")
    cmds = [r["command"] for r in tr]
    embed.fit_tfidf(cmds + [r["command"] for r in va] + [r["command"] for r in te])
    Xtr = embed.encode(cmds)
    ytr = [1 if r["label"] == "unknown" else 0 for r in tr]
    clf = LogisticRegression(max_iter=1000, class_weight="balanced").fit(Xtr, ytr)
    vocab = set()
    for r in tr:
        if r["label"] == "known":
            vocab.update(tokens(r["command"]))
    joblib.dump({"clf": clf, "vocab": sorted(vocab)}, CLF)

    def scores(split):
        ml = [float(p[1]) for p in clf.predict_proba(embed.encode([r["command"] for r in split]))]
        nv = novelty([r["command"] for r in split], vocab)
        y = [1 if r["label"] == "unknown" else 0 for r in split]
        return ml, nv, y

    ml_va, nv_va, y_va = scores(va)
    best, best_k, best_thr = (-1.0, 1.0, 0.5)
    for k in (0.5, 1.0, 1.5, 2.0):
        comb_va = [max(a, min(1.0, b * k)) for a, b in zip(ml_va, nv_va)]
        for thr in [round(x * 0.05, 2) for x in range(1, 20)]:
            f1 = _metrics(y_va, comb_va, thr)["f1"]
            if f1 > best:
                best, best_k, best_thr = f1, k, thr
    ARTIFACTS.mkdir(exist_ok=True)
    META.write_text(json.dumps({"threshold": best_thr, "k": best_k,
                                "train_time_s": round(time.time() - t0, 1)}))
    out = {"val": _metrics(y_va, [max(a, min(1.0, b * best_k)) for a, b in zip(ml_va, nv_va)], best_thr),
           "k": best_k}
    ml_te, nv_te, y_te = scores(te)
    comb_te = [max(a, min(1.0, b * best_k)) for a, b in zip(ml_te, nv_te)]
    out["test"] = _metrics(y_te, comb_te, best_thr)
    out["train_time_s"] = round(time.time() - t0, 1)
    un = [(r, s) for r, s in zip(te, comb_te) if r["config"].startswith("synthetic-")
          and any(h in r["config"] for h in ("neuro-route", "malformed"))]
    if un:
        out["unseen_family"] = {"n": len(un),
                                "recall": round(sum(1 for _, s in un if s >= best_thr) / len(un), 3)}
    return out


def predict(command: str):
    import json
    d = joblib.load(CLF)
    meta = json.loads(META.read_text()) if META.exists() else {"threshold": 0.5, "k": 1.0}
    clf, vocab = (d["clf"], set(d["vocab"])) if isinstance(d, dict) else (d, set())
    v = embed.encode([command])
    ml = float(clf.predict_proba(v)[0][1])
    t = tokens(command)
    nv = sum(1 for w in t if w not in vocab) / max(1, len(t))
    s = max(ml, min(1.0, nv * meta.get("k", 1.0)))
    thr = meta.get("threshold", 0.5)
    return {"label": "unknown" if s >= thr else "known", "oov_score": round(s, 3),
            "ml": round(ml, 3), "novelty": round(nv, 3), "threshold": thr}
