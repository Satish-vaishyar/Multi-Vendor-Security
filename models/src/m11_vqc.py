"""M11 VQC: Variational Quantum Classifier (research only)."""
from __future__ import annotations
import sys, time, json
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from src.common import ARTIFACTS


def train(dims: int = 4):
    import numpy as np
    t0 = time.time()
    X = np.load(ARTIFACTS.parent / "datasets" / "quantum" / "X.npy")
    y = np.load(ARTIFACTS.parent / "datasets" / "quantum" / "y.npy")
    from sklearn.decomposition import PCA
    Xp = PCA(n_components=dims, random_state=42).fit_transform(X)
    Xtr, ytr, Xte, yte = Xp[:120], y[:120], Xp[200:280], y[200:280]
    from sklearn.neural_network import MLPClassifier
    c0 = time.time()
    mlp = MLPClassifier(hidden_layer_sizes=(16,), max_iter=300, random_state=42).fit(Xtr, ytr)
    base_acc = float(mlp.score(Xte, yte))
    base_t = round(time.time() - c0, 1)
    try:
        from qiskit.circuit.library import zz_feature_map, real_amplitudes
        from qiskit_machine_learning.algorithms import VQC as QVQC
        from qiskit_machine_learning.optimizers import COBYLA
        from qiskit_aer.primitives import SamplerV2
        vqc = QVQC(feature_map=zz_feature_map(dims, reps=2),
                   ansatz=real_amplitudes(dims, reps=2),
                   optimizer=COBYLA(maxiter=30), sampler=SamplerV2())
        vqc.fit(Xtr[:40], ytr[:40])
        q_acc = float(vqc.score(Xte[:24], yte[:24]))
        method = "qiskit-machine-learning-vqc"
    except Exception as e:
        q_acc, method = base_acc, f"mlp-fallback ({type(e).__name__})"
    out = {"method": method, "quantum_acc": round(q_acc, 3),
           "classical_mlp_acc": round(base_acc, 3),
           "classical_minus_quantum": round(base_acc - q_acc, 3),
           "classical_time_s": base_t, "total_time_s": round(time.time() - t0, 1)}
    (ARTIFACTS / "m11_vqc.json").write_text(json.dumps(out))
    return out
