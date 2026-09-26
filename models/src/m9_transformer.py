"""M9 Small Transformer baseline: MiniLM/BERT-style encoder + classification head.
Trained on mapping dataset AFTER M3 works (models.md §20). Torch tiny transformer."""
from __future__ import annotations
import json, time
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from src.common import ARTIFACTS

MODEL = ARTIFACTS / "m9_transformer.pt"


def train(jsonl: Path, epochs: int = 12):
    import torch, torch.nn as nn
    t0 = time.time()
    from sklearn.feature_extraction.text import HashingVectorizer
    recs = [json.loads(l) for l in open(jsonl, encoding="utf-8")]
    labels = sorted(set(r["canonical_path"] for r in recs))
    li = {l: i for i, l in enumerate(labels)}
    vec = HashingVectorizer(n_features=1024, alternate_sign=False)
    X = torch.tensor(vec.transform([r["command"] for r in recs]).toarray(), dtype=torch.float32)
    y = torch.tensor([li[r["canonical_path"]] for r in recs])
    # 80/20 split by index (deterministic)
    n_tr = int(len(recs) * 0.8)
    Xtr, ytr, Xte, yte = X[:n_tr], y[:n_tr], X[n_tr:], y[n_tr:]

    class Tiny(nn.Module):
        def __init__(self, d_in, d_m=128, n_cls=10):
            super().__init__()
            self.proj = nn.Linear(d_in, d_m)
            self.enc = nn.TransformerEncoder(
                nn.TransformerEncoderLayer(d_model=d_m, nhead=4, dim_feedforward=256,
                                           batch_first=True), num_layers=2)
            self.head = nn.Linear(d_m, n_cls)

        def forward(self, x):
            h = self.proj(x).unsqueeze(1)
            h = self.enc(h).squeeze(1)
            return self.head(h)

    net = Tiny(X.shape[1], n_cls=len(labels))
    opt = torch.optim.Adam(net.parameters(), lr=2e-3)
    loss_fn = nn.CrossEntropyLoss()
    net.train()
    for _ in range(epochs):
        opt.zero_grad()
        loss = loss_fn(net(Xtr), ytr)
        loss.backward(); opt.step()
    ARTIFACTS.mkdir(exist_ok=True)
    torch.save({"state": net.state_dict(), "labels": labels, "d_in": X.shape[1]}, MODEL)
    net.eval()
    with torch.no_grad():
        tr_acc = (net(Xtr).argmax(1) == ytr).float().mean().item()
        te_acc = (net(Xte).argmax(1) == yte).float().mean().item()
    # kNN-vs-transformer delta (M3 test top-1 loaded if present)
    m3_top1 = None
    try:
        m3_top1 = json.loads((ARTIFACTS.parent / "evaluation" / "metrics.json").read_text())["M3_mapping"]["top1"]
    except Exception:
        pass
    out = {"n": len(recs), "classes": len(labels), "epochs": epochs,
           "train_acc": round(tr_acc, 3), "test_acc": round(te_acc, 3),
           "train_time_s": round(time.time() - t0, 1)}
    if m3_top1 is not None:
        out["knn_top1"] = m3_top1
        out["delta_vs_knn"] = round(te_acc - m3_top1, 3)
    return out
