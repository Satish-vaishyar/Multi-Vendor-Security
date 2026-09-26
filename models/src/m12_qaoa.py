"""M12 QAOA: remediation-prioritization optimizer (research demo)."""
from __future__ import annotations
import sys, time, json
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from src.common import ARTIFACTS


def _classical(costs, values, budget):
    n = len(costs)
    dp = [[0] * (budget + 1) for _ in range(n + 1)]
    for i in range(1, n + 1):
        for b in range(budget + 1):
            dp[i][b] = dp[i - 1][b]
            if costs[i - 1] <= b:
                dp[i][b] = max(dp[i][b], dp[i - 1][b - costs[i - 1]] + values[i - 1])
    sel, b = [0] * n, budget
    for i in range(n, 0, -1):
        if dp[i][b] != dp[i - 1][b]:
            sel[i - 1] = 1
            b -= costs[i - 1]
    return sel, dp[n][budget]


def _quantum(costs, values, budget):
    """Native QAOA: QP -> QUBO -> Ising, QAOAAnsatz (decomposed) + COBYLA,
    most-sampled bitstring read out via SamplerV2, mapped back with interpret."""
    import numpy as np
    from qiskit_optimization import QuadraticProgram
    from qiskit_optimization.converters import QuadraticProgramToQubo
    from qiskit.circuit.library import QAOAAnsatz
    from qiskit_algorithms.optimizers import COBYLA
    from qiskit_algorithms.minimum_eigensolvers import VQE
    # NOTE: Aer primitives reject the PauliEvolution instruction inside QAOAAnsatz;
    # use exact reference statevector primitives (8-qubit demo: trivial cost).
    from qiskit.primitives import StatevectorEstimator, StatevectorSampler
    n = len(costs)
    qp = QuadraticProgram()
    for i in range(n):
        qp.binary_var(f"x{i}")
    qp.maximize(linear={f"x{i}": values[i] for i in range(n)})
    qp.linear_constraint(linear={f"x{i}": costs[i] for i in range(n)}, sense="<=", rhs=budget)
    conv = QuadraticProgramToQubo()
    qubo = conv.convert(qp)
    qubit_op, _offset = qubo.to_ising()
    ansatz = QAOAAnsatz(cost_operator=qubit_op, reps=1).decompose()
    vqe = VQE(estimator=StatevectorEstimator(), ansatz=ansatz, optimizer=COBYLA(maxiter=30))
    res = vqe.compute_minimum_eigenvalue(qubit_op)
    bound = ansatz.assign_parameters(res.optimal_point)
    bound.measure_all()
    job = StatevectorSampler().run([bound], shots=1024)
    counts = job.result()[0].data.meas.get_counts()
    bitstr = max(counts, key=counts.get)
    var_order = qubo.variables_index  # name -> qubit index (incl. slack vars)
    order = sorted(var_order, key=var_order.get)
    sel_qubo = [0] * len(order)
    for qi in range(len(order)):
        sel_qubo[qi] = int(bitstr[len(bitstr) - 1 - qi])
    sel = [int(v) for v in conv.interpret(np.array(sel_qubo))]
    return sel


def optimize(costs=(3, 2, 4, 1, 5), values=(8, 5, 9, 3, 10), budget: int = 7,
             restarts: int = 3):
    t0 = time.time()
    sel_c, classical_value = _classical(costs, values, budget)
    try:
        best, method = None, "qiskit-qaoa"
        for _ in range(max(1, restarts)):
            try:
                sel = _quantum(costs, values, budget)
            except Exception:
                continue
            if sum(c for c, s in zip(costs, sel) if s) > budget:
                continue
            v = sum(v for v, s in zip(values, sel) if s)
            if best is None or v > best[0]:
                best = (v, sel)
        if best is None:
            sel, method = sel_c, "qiskit-qaoa (infeasible->classical)"
        else:
            sel = best[1]
    except Exception as e:
        sel, method = sel_c, f"dp-fallback ({type(e).__name__})"
    out = {"method": method, "selected": sel,
           "value": sum(v for v, s in zip(values, sel) if s),
           "cost": sum(c for c, s in zip(costs, sel) if s),
           "classical_optimum": classical_value,
           "gap_to_optimum": classical_value - sum(v for v, s in zip(values, sel) if s),
           "time_s": round(time.time() - t0, 1)}
    (ARTIFACTS / "m12_qaoa.json").write_text(json.dumps(out))
    return out
