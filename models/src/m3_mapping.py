"""M3 Mapping Model (most important): embedding + kNN/centroid + human loop."""
from __future__ import annotations
import json
from pathlib import Path
import joblib, numpy as np
from sklearn.neighbors import NearestNeighbors
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from src.common import ARTIFACTS
from src import embed

IDX = ARTIFACTS / "m3_index.pkl"


def train(jsonl: Path):
    import time
    t0 = time.time()
    recs = [json.loads(l) for l in open(jsonl, encoding="utf-8")]
    # hold out unseen_vendor commands: filter vendor==unknown proprietary? use 90/10 by command hash
    tr = [r for i, r in enumerate(recs) if i % 10 != 0]
    te = [r for i, r in enumerate(recs) if i % 10 == 0]
    cmds = [r["command"] for r in tr]
    embed.fit_tfidf(cmds + [r["command"] for r in te])
    X = embed.encode(cmds)
    nn = NearestNeighbors(n_neighbors=3, metric="cosine").fit(X)
    ARTIFACTS.mkdir(exist_ok=True)
    joblib.dump({"nn": nn, "recs": tr}, IDX)
    # top-1/top-3/MRR eval
    Xt = embed.encode([r["command"] for r in te])
    _, idx = nn.kneighbors(Xt)
    top1 = top3 = 0
    rr = 0.0
    for i, r in enumerate(te):
        preds = [tr[j]["canonical_path"] for j in idx[i]]
        if preds[0] == r["canonical_path"]:
            top1 += 1
        if r["canonical_path"] in preds:
            top3 += 1
            rr += 1.0 / (preds.index(r["canonical_path"]) + 1)
    n = max(1, len(te))
    return {"n_train": len(tr), "n_test": len(te),
            "top1": round(top1 / n, 3), "top3": round(top3 / n, 3),
            "mrr": round(rr / n, 3), "train_time_s": round(time.time() - t0, 1)}


def suggest(command: str, vendor: str = "unknown", topk: int = 3):
    d = joblib.load(IDX)
    nn, recs = d["nn"], d["recs"]
    v = embed.encode([command])
    dist, idx = nn.kneighbors(v, n_neighbors=topk)
    out = []
    for dist_i, j in zip(dist[0], idx[0]):
        r = recs[j]
        out.append({"canonical_property": r["canonical_path"], "value": r["canonical_value"],
                    "confidence": round(float(1 - dist_i), 3), "vendor": r["vendor"],
                    "evidence": r["command"]})
    return out


def approve(vendor, platform, pattern, prop, value, jsonl: Path):
    """Human approval -> registry update -> new training sample (learning loop §10)."""
    rec = {"vendor": vendor, "platform": platform, "version": "1.x", "command": pattern,
           "context": [pattern], "canonical_path": prop, "canonical_value": value,
           "category": prop.split(".")[0], "confidence": 1.0, "source": "manual_verified",
           "label_source": "expert_verified"}
    with open(jsonl, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec) + "\n")
    return {"registry_updated": True, "mapping": rec}
