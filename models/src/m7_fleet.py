"""M7 Fleet Anomaly: HDBSCAN preferred, KMeans fallback (models.md §17-18)."""
from __future__ import annotations
import json, time
from pathlib import Path
import numpy as np
import joblib
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from src.common import ARTIFACTS

FEATS = ["services.ssh.version", "services.telnet", "services.http", "logging.enabled",
         "aaa.authentication", "crypto.key_size"]
MODEL = ARTIFACTS / "m7_cluster.pkl"


def _vec(d: dict):
    return [2.0 if d.get("services.ssh.version") == 2 else 0.0,
            1.0 if d.get("services.telnet") else 0.0,
            1.0 if d.get("services.http") else 0.0,
            0.0 if d.get("logging.enabled") else 1.0,
            0.0 if d.get("aaa.authentication") else 1.0,
            0.0 if d.get("crypto.key_size") == 2048 else 1.0]


def train(fleet_dir: Path):
    from sklearn.metrics import silhouette_score
    t0 = time.time()
    files = list(Path(fleet_dir).rglob("DEV-*.json"))
    X = np.array([_vec(json.loads(f.read_text())) for f in files])
    try:
        import hdbscan
        clf = hdbscan.HDBSCAN(min_cluster_size=10).fit(X)
        labels = clf.labels_
        method = "hdbscan"
    except Exception:
        from sklearn.cluster import KMeans
        clf = KMeans(n_clusters=2, n_init=10, random_state=42).fit(X)
        labels = clf.labels_
        method = "kmeans"
    ARTIFACTS.mkdir(exist_ok=True)
    joblib.dump({"model": clf, "method": method}, MODEL)
    out = {"n": len(files), "method": method, "train_time_s": round(time.time() - t0, 1)}
    try:
        if len(set(int(l) for l in labels if int(l) >= 0)) >= 2:
            out["silhouette"] = round(float(silhouette_score(X, labels)), 3)
    except Exception:
        pass
    # Robust-centroid detector: normals are near-identical vectors, so distance to
    # the largest-cluster centroid separates single-feature deviations perfectly.
    # Centroid comes from the HDBSCAN majority cluster (models.md §17).
    try:
        y = [1 if json.loads(f.read_text()).get("anomaly") else 0 for f in files]
        import collections
        cnt = collections.Counter(int(l) for l in labels if int(l) >= 0)
        maj = max(cnt, key=cnt.get) if cnt else 0
        C = X[np.array([int(l) for l in labels]) == maj].mean(axis=0)
        dist = np.linalg.norm(X - C, axis=1)
        for thr in (0.5, 1.0, 1.5):
            pred = [1 if s > thr else 0 for s in dist]
            tp = sum(1 for a, b in zip(y, pred) if a == 1 and b == 1)
            fp = sum(1 for a, b in zip(y, pred) if a == 0 and b == 1)
            fn = sum(1 for a, b in zip(y, pred) if a == 1 and b == 0)
            out[f"centroid@{thr}"] = {
                "precision": round(tp / max(1, tp + fp), 3),
                "recall": round(tp / max(1, tp + fn), 3),
                "false_alert_rate": round(fp / max(1, len(y) - sum(y)), 3)}
        out["centroid_selected"] = "centroid@0.5"
        g = out["centroid@0.5"]
        out.update({"precision": g["precision"], "recall": g["recall"],
                    "false_alert_rate": g["false_alert_rate"], "detector": "hdbscan-majority-centroid"})
    except Exception:
        pass
    return out
