"""Golden dataset builder: for each sampled corpus config, store expected IR seed.

Golden = raw config + expected vendor/profile + expected canonical IR fragment.
Full IR expectations are produced by running the deterministic registry
(the registry IS the ground truth for known vendors) — unknown lines recorded
separately for the adaptive-loop test (arch Test 4/5).

Usage: python scripts/generate_golden.py --corpus data/corpus --out data/golden --max 60
"""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from src.knowledge_extras import MappingRegistry


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default="data/corpus")
    ap.add_argument("--out", default="data/golden")
    ap.add_argument("--max", type=int, default=60)
    a = ap.parse_args()
    maps = MappingRegistry().load()
    corpus = Path(a.corpus)
    manifest = json.loads((corpus / "manifest.json").read_text(encoding="utf-8"))
    out = Path(a.out)
    n = 0
    for item in manifest["items"][:a.max]:
        cfg = (corpus / item["file"]).read_text(encoding="utf-8")
        det = maps.to_canonical_ir(cfg, vendor=item["vendor"] if item["vendor"] != "unknown" else "cisco")
        d = out / item["vendor"] / item["profile"]
        d.mkdir(parents=True, exist_ok=True)
        stem = Path(item["file"]).stem
        (d / f"{stem}.txt").write_text(cfg, encoding="utf-8")
        (d / f"{stem}.expected.json").write_text(json.dumps({
            "expected_vendor": item["vendor"], "expected_profile": item["profile"],
            "expected_ir": det["ir"], "provenance": det["provenance"]}, indent=1), encoding="utf-8")
        n += 1
    print(json.dumps({"golden_cases": n, "out": str(out)}))


if __name__ == "__main__":
    main()
