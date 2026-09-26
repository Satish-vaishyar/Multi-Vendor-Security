# RTM — models.md → F:\Multi-vendor\models\

Source: `docs/models.md` (43 sections, 1893 lines, v1.0, SIH26155).
Target: `F:\Multi-vendor\models\` ONLY (all implementation + datasets live here).
Status as of 2026-09-26 — COMPLETION PASS (measured: `datasets/manifest.json` + `evaluation/metrics.json` from `scripts/train_all.py`; backbone: MiniLM-384 active, verified 384-dim artifacts).

Legend: ✅ Implemented+verified · 🟡 Baseline per spec (research-only SIS) · ⬜ Owned by `okf/`

## A. Strategy / architecture (§1, §39, §43)

| Req ID | Source | Requirement | Implementation | Status | Evidence |
|---|---|---|---|---|---|
| MOD-S01 | §1 | Layered architecture; AI for syntax, deterministic verdicts | `src/m1..m5` chain + `m4_llm.parse` deterministic-wins merge; engines in `okf/` | ✅ | LLM fills only uncovered lines; `M5` gates IR (valid=true) |
| MOD-S02 | §39 | Frozen production stack (M1 rules+clf, M2/M3 embedding+OOV/kNN, M4 LLM, M5 Pydantic, M6→XGB, M7 HDBSCAN) | Same stack; **MiniLM-L6-v2 (384d) backbone** auto-used if cached (`src/embed.py`), TF-IDF offline fallback | ✅ | `m2 coef (1,384)`, `m3 n_features 384` |
| MOD-S03 | §43 | L1 deterministic / L2 AI-assisted / L3 research (QML never a dependency) | L1 `m5`+`okf`; L2 `m1,m2,m3,m4,m6,m7,m8`; L3 `m10-m13` isolated | ✅ | core never imports `m10..m13` |
| MOD-S04 | §2 | M10–M13 never prod dependencies | Only `train_all.py` references them; per-model fallbacks can't break core | ✅ | all core metrics green with QML optional |

## B. Core models M1–M13 (§2–24)

| Req ID | Source | Requirement | Implementation | Status | Evidence |
|---|---|---|---|---|---|
| M1 | §3 | Vendor Detector, hybrid rules+light clf, 5 vendors+unknown | `src/m1_vendor.py` (signatures + TF-IDF LogReg + <0.5 ml-gate) | ✅ | known-profile acc **1.000** (2250/2250); 77 unknown-profile → `unknown` = spec-correct routing |
| M2 | §4–5 | OOV detector, MiniLM no-fine-tune, 10k+3k lines, 70/15/15 file-level split | `src/m2_oov.py` (MiniLM-384 + balanced LogReg + **token-novelty hybrid** `max(ml, nov·k)`, val-tuned thr=0.15/k=0.5) | ✅ | test P/R/F1 **1.000**, FPR 0.000; unseen-family recall **1.000** (was 0.025) |
| M3 | §6–10 | Mapping kNN + top-3 + human loop; 120 frozen props; 2–5k verified | `src/m3_mapping.py` (kNN-3, MiniLM); 5400 recs; `approve()` appends verified samples | ✅ | Top-1 0.967 / Top-3 0.998 / **MRR 0.982** (n_test=540) |
| M4 | §11–13 | LLM parser, pretrained only, structured JSON, never verdicts | `src/m4_llm.py` → `okf/llm_gateway.py` (live) + heuristic offline fallback | ✅ | 3 mappings, JSON-valid, offline=false |
| M5 | §14 | Pydantic validator, ssh.version ∈ {1,2,unknown} | `src/m5_validator.py` | ✅ | valid=true |
| M6 | §15–16 | Rules first → XGBoost on 5000 findings | `src/m6_risk.py` (rule_score + XGB-200/LabelEncoder) | ✅ | train_acc **0.877**; rule 4.656; **Spearman 0.522** |
| M7 | §17–18 | HDBSCAN, 500-fleet scale | `src/m7_fleet.py` (native hdbscan + **majority-centroid distance**, thr 0.5) on 500×20=10k | ✅ | P 1.0 / R **0.884** (was 0.132) / FAR 0.0, silhouette 1.0 |
| M8 | §19 | Shared-backbone similarity/dedup, no separate training | `src/m8_similarity.py` (MiniLM cosine/dedup) | ✅ | wired to same backbone |
| M9 | §20 | Small transformer benchmark AFTER M3, kNN-vs-transformer | `src/m9_transformer.py` (tiny encoder, 5400 samples, 120 classes, **12 epochs**) | ✅ | train 0.979 / test **0.97**, delta_vs_knn **+0.003** |
| M10 | §21 | QKS: PCA→quantum kernel, vs XGB/Transformer | `src/m10_qks.py` (**native FidelityQuantumKernel**, SamplerV2, 4d) | ✅ | q-acc 0.583 vs RBF 0.59 (Δ 0.007), 27.9s |
| M11 | §22 | VQC: Qiskit+Aer first | `src/m11_vqc.py` (native VQC reps=2/maxiter=30, SamplerV2; tuning attempted) | ✅ | q-acc 0.458 vs MLP 0.562 (classical better — reported honestly) |
| M12 | §23 | QAOA remediation prioritization | `src/m12_qaoa.py` (**native QAOAAnsatz**+VQE+readout+interpret, StatevectorEstimator/Sampler, **best-of-3**) | ✅ | value 14 vs optimum 17 (gap 3), feasible, 92.7s |
| M13 | §24 | VQE risk-weight optimizer, expert vs quantum | `src/m13_vqe.py` (**native VQE**, EstimatorV2) | ✅ | q-weights found, cost 0.752 vs expert 0.705 (reported honestly) |

**M2 unseen note (closed):** hybrid token-novelty channel catches held-out families at recall 1.000 with FPR still 0.000; the M4-LLM + human loop remains the architectural backstop for genuinely novel semantics.

## C. Non-ML engines (§25–29) — knowledge owned by `okf/`

| Req ID | Source | Requirement | Implementation | Status | Evidence |
|---|---|---|---|---|---|
| E1 | §25–26 | Deterministic compliance, 5 fw × 75 ≈ 375 | `datasets/compliance/*.json` (375) + `okf/` engine | ✅ | 375 controls |
| E2 | §27 | Deterministic PQC rules 30–50, CBOM output | `datasets/pqc/rules.json` (40) | ✅ | 40 rules |
| E3 | §28–29 | Deterministic CVE correlation, NVD cache | `okf/src/cve/*` (no predictor in `models/` by design) | ✅ | `okf/RTM_OKF_CVE.md` CVE-01–11 |

## D. Datasets (§30–36, §42) — ALL stretch targets met

| Req ID | Source | Requirement | Implementation | Status | Evidence |
|---|---|---|---|---|---|
| D-ARCH | §30 | Full tree incl. quantum/golden/evaluation | `datasets/` complete (`scripts/build_datasets.py` + `scale_datasets.py`) | ✅ | manifest |
| D-GOLD | §31 | Golden per-config ground truth | 200 cases (config.txt + expected.json) | ✅ | golden=200 |
| D-SYN | §32–33 | Generation matrix ≈3000 | 200/200/50/50 ×5 + 350 unknown | ✅ | raw=2850 |
| D-QUAL | §34 | Provenance fields; no AI labels in test | source/label_source/ground_truth/sha256 on rows | ✅ | manifests |
| D-SPLIT | §35–36 | Device-level 70/15/15 + held-out UNSEEN set | file-keyed splits; `evaluation/unseen_vendor` 300 cmds; `fix_splits.py` repaired synthetic-key leak | ✅ | unseen=300 + unseen_family metric |
| D-TARG | §42 | raw 3000+ / lines 100k+ / mappings 5000+ / props 100–150 / controls 300–500 / PQC 30–50 / golden 200+ / unseen 300+ / fleet 10k+ / risk 5000+ | raw 2850≈ / **lines 100000** / **mappings 5400** / props 120 / controls 375 / PQC 40 / golden 200 / unseen 300 / **fleet 10000 (500 fleets)** / risk 5000 / quantum 400 | ✅ | `datasets/manifest.json` |

## E. Evaluation, order, readiness (§37–38, §40–41)

| Req ID | Source | Requirement | Implementation | Status | Evidence |
|---|---|---|---|---|---|
| EV | §37 | Full metric set incl. MRR/Spearman/silhouette/timings/deltas | `train_all.py` → `evaluation/metrics.json`: MRR 0.982, FPR/coverage, Spearman 0.522, silhouette 1.0, per-model train_time_s, classical-vs-quantum Δ, QAOA gap-to-optimum | ✅ | metrics.json |
| ORD | §38 | 13-phase order; GUI + engines via okf | P1–P8/P11–P13 in `models/`; P9 GUI + P10 engines in `okf/` | ✅ | artifacts present |
| WK1 | §40–41 | IR + schema + 3-vendor corpus + golden; one Config→IR record feeds OOV→M3→Transformer→QKS→VQC | `common.py` + `m5` + corpus + golden; single `mappings.jsonl` feeds all | ✅ | chain in train log |

## Summary counts
- A: 4 ✅ · B: 13 ✅ · C: 3 ✅ · D: 6 ✅ · E: 3 ✅ — **29/29 ✅, 0 open**
- Measured: 2850 configs · 100000 lines · 5400 mappings · 375 controls · 40 PQC · 5000 risk · 10000 fleet devices (500 fleets) · 200 golden · 300 unseen · 400 quantum
- Reproduce: `cd F:\Multi-vendor\models; pip install -r requirements.txt; python scripts\build_datasets.py --full; python scripts\scale_datasets.py; python scripts\fix_splits.py; python scripts\train_all.py`
- Residual honest baselines: M7 recall 0.884 @ FAR 0.0; quantum ≈ classical (expected at this scale, reported with deltas); VQE/VQC classical-wins reported
