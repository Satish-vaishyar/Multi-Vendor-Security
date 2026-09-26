"""Unified evaluation -> evaluation/metrics.json (models.md §37)."""
from __future__ import annotations
import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from src.common import EVAL


def write(metrics: dict):
    EVAL.mkdir(exist_ok=True)
    (EVAL / "metrics.json").write_text(json.dumps(metrics, indent=1))
    print(json.dumps(metrics, indent=1))


if __name__ == "__main__":
    p = EVAL / "metrics.json"
    print(p.read_text() if p.exists() else '{"status": "no metrics yet, run scripts/train_all.py"}')
