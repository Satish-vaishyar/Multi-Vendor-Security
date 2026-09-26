"""Fix unknown_token splits: synthetic extras shared one config key ('synthetic') so
device-level splitting dumped them all into test (M2 test recall 0.29 artifact).

Fix (honest, per models.md §35-36):
- synthetic rows get unique config ids per template family;
- families 0-3 (hyperflux, quantum-shield, fluxrouter, cryptochamber) distribute 70/15/15;
- families 4-5 (neuro-route, malformed) stay ALL in test = true unseen-family set (§36).
Idempotent.
"""
from __future__ import annotations
import csv, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

P = Path(__file__).parent.parent / "datasets" / "unknown_token" / "lines.csv"

FAMS = ["hyperflux", "quantum-shield", "fluxrouter", "cryptochamber", "neuro-route", "malformed"]
HELD = {"neuro-route", "malformed"}


def fam_of(cmd: str) -> str:
    low = cmd.lower()
    for f in FAMS:
        if f in low:
            return f
    return "other"


def main():
    rows = list(csv.DictReader(open(P, encoding="utf-8")))
    changed = sum(1 for r in rows if r["config"].startswith("synthetic-"))
    if changed > 100:
        print("already fixed")
        return
    counters: dict[str, int] = {}
    for r in rows:
        if r["config"] != "synthetic":
            continue
        f = fam_of(r["command"])
        i = counters.get(f, 0)
        counters[f] = i + 1
        r["config"] = f"synthetic-{f}-{i:05d}"
        if f in HELD:
            r["split"] = "test"
        else:
            m = i % 20
            r["split"] = "train" if m < 14 else ("val" if m < 17 else "test")
    with open(P, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["command", "vendor", "platform", "context", "label", "config", "split"])
        w.writeheader(); w.writerows(rows)
    from collections import Counter
    print(Counter((r["split"], r["label"]) for r in rows if r["config"].startswith("synthetic-")))
    print("fixed", sum(counters.values()), "synthetic rows")


if __name__ == "__main__":
    main()
