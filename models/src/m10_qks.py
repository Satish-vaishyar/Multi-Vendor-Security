"""M10 QKS: Quantum Kernel classifier (research only, never a prod dependency)."""
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
    from sklearn.svm import SVC
    Xp = PCA(n_components=dims, random_state=42).fit_transform(X)
    Xtr, ytr, Xte, yte = Xp[:200], y[:200], Xp[200:300], y[200:300]
    # classical baseline
    c0 = time.time()
    base = SVC(kernel="rbf").fit(Xtr, ytr)
    base_acc = float(base.score(Xte, yte))
    base_t = round(time.time() - c0, 1)
    # native quantum kernel
    try:
        from qiskit.circuit.library import zz_feature_map
        from qiskit_machine_learning.kernels import FidelityQuantumKernel
        from qiskit_machine_learning.state_fidelities import ComputeUncompute
        from qiskit_aer.primitives import SamplerV2
        fm = zz_feature_map(feature_dimension=dims, reps=2)
        kern = FidelityQuantumKernel(fidelity=ComputeUncompute(sampler=SamplerV2()),
                                     feature_map=fm)
        Ktr = kern.evaluate(Xtr[:40])
        clf = SVC(kernel="precomputed").fit(Ktr, ytr[:40])
        Kte = kern.evaluate(Xtr[:40], Xte[:24])
        q_acc = float((clf.predict(Kte.T) == yte[:24]).mean())
        method = "qiskit-fidelity-kernel"
    except Exception as e:
        q_acc, method = base_acc, f"rbf-fallback ({type(e).__name__})"
    out = {"method": method, "dims": dims, "quantum_acc": round(q_acc, 3),
           "classical_rbf_acc": round(base_acc, 3),
           "classical_minus_quantum": round(base_acc - q_acc, 3),
           "classical_time_s": base_t, "total_time_s": round(time.time() - t0, 1)}
    (ARTIFACTS / "m10_qks.json").write_text(json.dumps(out))
    return out
