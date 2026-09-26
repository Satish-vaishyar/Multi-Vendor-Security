"""M13 VQE: weight optimizer for risk weights (research demo)."""
from __future__ import annotations
import sys, time, json
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from src.common import ARTIFACTS


def optimize():
    import numpy as np
    t0 = time.time()
    Q = np.array([[2.0, 0.3, 0.1], [0.3, 1.5, 0.2], [0.1, 0.2, 1.0]])
    expert = [0.4, 0.35, 0.25]
    def cost(w):
        w = np.array(w) / (sum(w) or 1)
        return float(w @ Q @ w)
    try:
        from qiskit_algorithms.minimum_eigensolvers import VQE
        from qiskit_algorithms.optimizers import COBYLA
        from qiskit.circuit.library import real_amplitudes
        from qiskit.quantum_info import SparsePauliOp
        from qiskit_aer.primitives import EstimatorV2
        ham = SparsePauliOp.from_list([("IIZ", Q[0, 0]), ("IZI", Q[1, 1]), ("ZII", Q[2, 2])])
        vqe = VQE(estimator=EstimatorV2(), ansatz=real_amplitudes(3, reps=2),
                  optimizer=COBYLA(maxiter=30))
        res = vqe.compute_minimum_eigenvalue(ham)
        raw = list(res.optimal_point[:3]) if res.optimal_point is not None else expert
        w = [round(float(abs(v)), 3) for v in raw]
        s = sum(w) or 1
        w = [round(v / s, 3) for v in w]
        method = "qiskit-vqe"
    except Exception as e:
        w, method = expert, f"expert-fallback ({type(e).__name__})"
    out = {"method": method, "weights": {"severity": w[0], "exposure": w[1], "criticality": w[2]},
           "cost_vqe": round(cost(w), 4), "cost_expert": round(cost(expert), 4),
           "time_s": round(time.time() - t0, 1)}
    (ARTIFACTS / "m13_vqe.json").write_text(json.dumps(out))
    return out
