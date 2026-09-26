"""M8 Semantic similarity / dedup — same backbone as M2/M3 (models.md §19)."""
from __future__ import annotations
import numpy as np
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from src import embed


def cosine(a: str, b: str) -> float:
    E = embed.encode([a, b])
    return float(E[0] @ E[1])


def dedup(findings: list[str], thresh: float = 0.85):
    E = embed.encode(findings)
    keep, seen = [], []
    for i, f in enumerate(findings):
        if any(float(E[i] @ E[j]) > thresh for j in seen):
            continue
        seen.append(i); keep.append(f)
    return keep
