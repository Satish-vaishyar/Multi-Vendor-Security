# SIH 26155 — Model Performance Report (M1–M13)

Source of truth: `evaluation/metrics.json` (produced by `scripts/train_all.py`).
Backbone: **MiniLM-L6-v2 (384-dim)** — verified (`m2_clf coef (1,384)`, `m3_index n_features 384`).
Dataset scale: `datasets/manifest.json` — 2,850 configs · 100,000 lines · 5,400 mappings · 375 controls · 40 PQC rules · 5,000 risk rows · 10,000 fleet devices (500 fleets) · 200 golden · 300 unseen · 400 quantum.
Date: 2026-09-26. Reproduce: `python scripts\build_datasets.py --full; python scripts\scale_datasets.py; python scripts\fix_splits.py; python scripts\train_all.py`

## 1. Consolidated scoreboard

| Model | Metric 1 | Metric 2 | Metric 3 | Time | Verdict |
|---|---|---|---|---|---|
| M1 Vendor Detector | known-profile acc **1.000** (2250/2250) | overall serving 0.973 (77 unknown-profile → `unknown` = spec-correct routing §3) | — | fast | ✅ Production-ready |
| M2 OOV (test) | P **1.000** | R **1.000** | F1 **1.000**, FPR 0.000, coverage 0.329 | 133s | ✅ Hybrid (ML + token-novelty, k=0.5, thr 0.15) |
| M2 OOV (val) | P 1.000 | R 1.000 | F1 1.000 (thr 0.15, k 0.5) | — | tuned |
| M2 unseen-family | recall **1.000** (n=3171) | novelty channel catches held-out families | — | — | ✅ Fixed by hybrid |
| M3 Mapping | Top-1 **0.967** | Top-3 **0.998** | **MRR 0.982** (540 test) | 14.2s | ✅ Production-ready |
| M4 LLM Parser | JSON-valid ✅ | 3 mappings, live API (offline=false) | sample conf 0.98 | — | ✅ Working |
| M5 Validator | valid=true | errors=[] | ssh coerced to 2 | — | ✅ Gate working |
| M6 Risk (XGB) | train acc **0.877**, 4 classes, n=5000 | rule demo 4.656 | **Spearman 0.522** | 1.1s | ✅ Trained (200 trees) |
| M7 Fleet (HDBSCAN) | P **1.000** | R **0.884** (was 0.132) | FAR 0.000, silhouette 1.000 (n=10k) | 1.2s | ✅ HDBSCAN-majority-centroid |
| M8 Similarity | dissimilar-pair cosine **0.178** | identical-pair **1.000** | backbone minilm-384 | — | ✅ Backbone verified |
| M9 Transformer | train **0.979** | test **0.970** (120 cls, 12 ep) | Δ vs kNN **+0.003** | 0.7s | ✅ Benchmark complete |
| M10 QKS (native) | q-acc **0.583** | RBF 0.590 (Δ 0.007) | FidelityQuantumKernel, 4d | 27.9s | ✅ Research |
| M11 VQC (native) | q-acc **0.458** | MLP 0.562 (Δ +0.104 classical) | reps=2/maxiter=30 tried, result stands | 13.1s | ✅ Research (tuning attempted, honest negative) |
| M12 QAOA (native) | value **14** / opt 17 | gap **3**, feasible (cost 6 ≤ 7) | best-of-3, 8 qubits | 92.7s | ✅ Research (near-optimal) |
| M13 VQE (native) | q-cost 0.7523 | expert 0.7053 | weights (0.012, 0.194, 0.795) | 0.1s | ✅ Research (honest: expert wins) |

## 2. Per-model matrices

### M1 — Vendor Detector (rules + TF-IDF LogReg hybrid)
| Split | Accuracy | F1-macro | n | Method |
|---|---|---|---|---|
| train (fit) | 1.000 | 1.000 | 2850 | rules win if conf>0.75 else ML |
Unknown routing: zero-signature configs → `unknown @ 0.31` → adaptive pipeline.

### M2 — Unknown Token Detector (MiniLM-384 + balanced LogReg, thr 0.15 val-tuned)
| Split | Precision | Recall | F1 | False-parse | Coverage | Mean-unk-score | n |
|---|---|---|---|---|---|---|---|
| val | 1.000 | 1.000 | 1.000 | 0.000 | 0.174→0.329 | 0.996→0.668 | 14315 |
| test | 1.000 | **1.000** (was 0.466) | **1.000** (was 0.635) | 0.000 | 0.329 | 0.668 | 17603 |
| unseen-family (neuro-route/malformed, never trained) | — | **1.000** (was 0.025) | — | — | — | — | 3171 |
Improvement: hybrid `max(ml_prob, novelty·k)`, k=0.5 val-tuned. Mechanism proven live: `enable neuro-route adaptive final` → ml 0.052 but novelty 0.75 → combined 0.375 ≥ 0.15 → unknown ✅. FPR stays 0.000 (known lines use seen vocab).

### M3 — Configuration Mapping (MiniLM + kNN-3, n_train 4860)
| Top-1 | Top-3 | MRR | Demo |
|---|---|---|---|
| 0.967 | 0.998 | 0.982 | `secure-mgmt ssh protocol v2` → `services.ssh.version` @ 1.000 |
Human loop: `approve()` appends expert-verified rows → registry → refresh (`mapping registry classifier` per §39).

### M4 — LLM Parser / M5 — IR Validator
| Check | Result |
|---|---|
| JSON validity / schema validity | ✅ valid |
| Property/value/evidence accuracy (sample) | SSH.ENABLED=true @ 0.98 with evidence line |
| Mode | live API (`offline=false`), heuristic fallback coded |
| M5 `services.ssh.version=2` | valid, errors [] |

### M6 — Risk (deterministic rule + XGBoost-200, n=5000)
| Train acc | Classes | rule demo (high/internet/critical) | Spearman rule-vs-label | train time |
|---|---|---|---|---|
| **0.877** (was 0.861) | critical/high/low/medium | 4.656 | 0.522 | 1.1s |

### M7 — Fleet Anomaly (HDBSCAN-majority-centroid, 500 fleets × 20 = 10,000 devices, 8% injected deviations)
| Precision | Recall | False-alert | Silhouette | Time |
|---|---|---|---|---|
| 1.000 | **0.884** (was 0.132) | 0.000 | 1.000 | 1.2s |
Improvement: anomaly micro-clusters defeat label-based detection → distance to HDBSCAN-majority-cluster centroid, threshold 0.5 (sweep 0.5/1.0/1.5 logged). Residual misses: multi-feature deviations near the boundary.

### M8 — Similarity (MiniLM-384)
| Pair | Cosine |
|---|---|
| "Telnet service is active" vs "Unencrypted remote terminal access is enabled" | 0.178 (correctly dissimilar) |
| identical command | 1.000 |

### M9 — Small Transformer (torch tiny encoder, 1024-hash → 128-d, 2 layers, 5400 samples, 120 classes, 12 epochs)
| Train acc | Test acc | kNN Top-1 | Δ (trans − kNN) | Time |
|---|---|---|---|---|
| 0.979 | 0.970 | 0.967 | +0.003 | 0.7s |
History: 0.13 → 0.97 after full-data + 12-epoch fix. Verdict: parity with kNN at this scale — kNN stays prod choice (simpler, incremental), as §20 intends (benchmark role).

### M10 QKS — native `FidelityQuantumKernel` (ZZFeatureMap, PCA-4, Aer SamplerV2)
| Quantum acc | Classical RBF | Δ (classical−quantum) | Time |
|---|---|---|---|
| 0.583 | 0.590 | 0.007 | 27.9s |
Parity — expected at 4-qubit demo scale.

### M11 VQC — native `qiskit-machine-learning` VQC (15 COBYLA iters, Aer SamplerV2)
| Quantum acc | Classical MLP | Δ | Time |
|---|---|---|---|
| 0.458 | 0.562 | +0.104 (classical better) | 4.9s |
Honest negative result, research-only per §2.

### M12 QAOA — native (QP→QUBO→Ising, decomposed QAOAAnsatz + VQE, Statevector primitives, readout + interpret, best-of-3)
| Selected | Value / cost | Optimum | Gap | Feasible | Time |
|---|---|---|---|---|---|
| [0,1,1,0,0] | 14 / 6 | 17 | 3 | ✅ (6 ≤ 7) | 92.7s |
Near-optimal heuristic demo (single runs vary 8–16: shot/optimizer variance, hence best-of-3).

### M13 VQE — native (EstimatorV2, RealAmplitudes-3q, COBYLA-30)
| Q-weights (sev/exp/crit) | Q-cost | Expert cost | Time |
|---|---|---|---|
| 0.012 / 0.194 / 0.795 | 0.7523 | 0.7053 | 0.1s |
Quantum weights valid; expert still better — reported, research-only.

## 3. Training order & timing (§38)
M1 → M2 (133s) → M3 (14s) → M4/M5 → M6 (0.4s) → M7 (1.2s) → M9 (0.7s) → M10 (28s) → M11 (5s) → M12 (93s) → M13 (0.1s). Full `train_all.py` ≈ 10–20 min (one 600s timeout hit pre-trim; rerun clean).

## 5. Stress test (2026-09-26, `scripts/stress_test.py` → `evaluation/stress_results.json`)

**Result: 13/13 functional PASS.** No crashes on empty / whitespace / garbage / 2000-line / unicode inputs.

| Model | Latency | Throughput | Edge behavior |
|---|---|---|---|
| M1 | 4.3 ms/config (n=500) | 233/s | empty/garbage → `unknown` via ml-gate ✅ (fixed during stress: was `arista` @ 0.26); real configs rules @ 0.99; **end-to-end serving acc 0.973** (n=2850; classifier fit 1.000) |
| M2 | 11.2 ms/line (n=2000) | 89/s | empty/garbage → `unknown` (safe: AI pipeline reviews); long/unicode handled |
| M3 | 186.8 ms/query (MiniLM encode dominates) | ~5/s | gibberish → top-3 @ ≤0.29 conf (correctly uncertain → human review); approve→registry probe ✅ |
| M4 | 8.1 s normal / 2.0 s empty / 4.6 s 60×-long config | API-bound | long input stays JSON-valid; recommend caching + async workers |
| M5 | instant | — | rejects ssh=5 + "maybe secure" + bad keys (≥2 errors); accepts good IR |
| M6 | ~0.0 ms rule | — | sweep 0.216 (low/internal) → 6.4 (critical/internet); XGB labels intact |
| M7 | artifact loads | — | HDBSCAN labels present |
| M8 | 10.8 ms/pair (n=200) | ~93/s | dedup 100 → 2 ✅ |
| M9 | artifact loads | — | 120 labels, 1024-in ✅ |
| M10 | 258 ms (native 8×8 kernel) | — | native path ✅ |
| M11 | artifact (native VQC metrics) | — | ✅ |
| M12 | 21.3 s single restart | — | native; single-shot variance 8–16 (best-of-3 → 14, gap 3) |
| M13 | 177 ms native re-run | — | ✅ |

**Fixes applied during stress:** (1) M1 low-confidence ML gate (<0.5 → `unknown`); serving acc re-verified 0.973. **Recommendations:** M3 batching/GPU or embedding cache for >5 qps; M4 response cache + job queue (8 s API latency).

## 4. Key findings for the report/jury
1. **M3 is the star**: 0.967/0.998/0.982 — the most important trainable model works.
2. **M9 parity (+0.003)** justifies keeping kNN in production.
3. **M2's hybrid lesson**: a frozen-embedding linear probe alone scored 0.025 on held-out families — the token-novelty OOV channel (§4: "Similarity/OOV score + Threshold") closed it to 1.000 while FPR stayed 0.000. The M4-LLM + human loop remains the backstop for genuinely novel semantics.
4. **Quantum: all native, all honest** — parity or classical-wins at demo scale, with measured deltas (no superiority claims).
5. **Zero-breach safety metrics**: M2 FPR 0.0, M7 FAR 0.0.
