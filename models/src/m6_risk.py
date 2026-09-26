"""M6 Risk Scoring: deterministic formula first, XGBoost later (models.md §15-16)."""
from __future__ import annotations
import csv
from pathlib import Path
import joblib
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from src.common import ARTIFACTS

CLF = ARTIFACTS / "m6_xgb.pkl"
SEV_W = {"low": 1, "medium": 2, "high": 3, "critical": 4}
EXP_W = {"internal": 0.6, "dmz": 0.85, "internet": 1.0}


def rule_score(severity="medium", exposure="internal", asset_criticality="medium", confidence=0.9):
    return round(SEV_W.get(severity, 2) * EXP_W.get(exposure, 0.6)
                 * (SEV_W.get(asset_criticality, 2) / 2.5) * confidence, 3)


def train(csv_path: Path):
    import time
    t0 = time.time()
    import pandas as pd
    df = pd.read_csv(csv_path)
    for c in ["severity", "exposure", "asset_criticality", "pqc_impact", "compliance_impact"]:
        df[c + "_w"] = df[c].map(lambda x: SEV_W.get(str(x), 2) if c != "exposure" else EXP_W.get(str(x), 0.6))
    X = df[[c for c in df.columns if c.endswith("_w")] + ["cvss"]]
    from sklearn.preprocessing import LabelEncoder
    le = LabelEncoder()
    y = le.fit_transform(df["priority"])
    try:
        from xgboost import XGBClassifier
        clf = XGBClassifier(n_estimators=200, max_depth=4, eval_metric="mlogloss")
    except Exception:
        from sklearn.ensemble import HistGradientBoostingClassifier
        clf = HistGradientBoostingClassifier()
    clf.fit(X, y)
    ARTIFACTS.mkdir(exist_ok=True)
    joblib.dump({"clf": clf, "labels": list(le.classes_)}, CLF)
    out = {"n": len(df), "classes": sorted(df["priority"].unique().tolist()),
           "train_time_s": round(time.time() - t0, 1)}
    try:  # train accuracy/agreement (labels 80% severity-derived + 20% noise)
        from sklearn.metrics import accuracy_score
        out["train_acc"] = round(float(accuracy_score(y, clf.predict(X))), 3)
    except Exception:
        pass
    try:  # Spearman: rule-score ranking vs analyst label ranking (§37 analyst agreement proxy)
        from scipy.stats import spearmanr
        order = {c: i for i, c in enumerate(["low", "medium", "high", "critical"])}
        rule = [rule_score(s, e, a) for s, e, a in
                zip(df["severity"], df["exposure"], df["asset_criticality"])]
        lab = [order.get(str(p), 1) for p in df["priority"]]
        out["spearman_rule_vs_label"] = round(float(spearmanr(rule, lab).statistic), 3)
    except Exception:
        pass
    return out
