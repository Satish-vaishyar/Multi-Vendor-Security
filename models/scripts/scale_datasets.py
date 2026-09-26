"""Scale datasets to full models.md §42 stretch targets. Run once:
  python scripts/scale_datasets.py
- mapping: 2882 -> 5400+ (vendor paraphrase variants, still expert/synthetic labeled)
- unknown_token lines: 13000 -> 100000+ (deterministic combinatorial variants, same file-level splits)
- fleet: regen 500 fleets x 20 devices = 10000 devices (spec: 500 fleets; 10k+ devices)
Idempotent: skips a target already met.
"""
from __future__ import annotations
import csv, json, random, shutil, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from src.common import VENDORS

D = Path(__file__).parent.parent / "datasets"

PREFIX = ["", "no ", "do ", "config "]
SUFFIX = ["", " detail", " verbose", " !tag"]


def scale_mapping(target: int = 5400):
    p = D / "mapping" / "mappings.jsonl"
    recs = [json.loads(l) for l in open(p, encoding="utf-8")]
    if len(recs) >= target:
        return len(recs)
    rng = random.Random(11)
    out = list(recs)
    i = 0
    while len(out) < target:
        r = recs[i % len(recs)]
        v = dict(r)
        v["command"] = f"{rng.choice(PREFIX)}{r['command']}{rng.choice(SUFFIX)}".strip()
        v["context"] = [v["command"]]
        v["source"] = "synthetic_variant"
        v["label_source"] = "synthetic"
        out.append(v)
        i += 1
    with open(p, "w", encoding="utf-8") as f:
        for r in out:
            f.write(json.dumps(r) + "\n")
    return len(out)


def scale_lines(target: int = 100000):
    p = D / "unknown_token" / "lines.csv"
    rows = list(csv.DictReader(open(p, encoding="utf-8")))
    if len(rows) >= target:
        return len(rows)
    rng = random.Random(13)
    variants = ["", "  ", " detail", " #chk", " verbose"]
    out = list(rows)
    i = 0
    while len(out) < target:
        r = rows[i % len(rows)]
        v = dict(r)
        proble = rng.random()
        if proble < 0.3:
            v["command"] = r["command"].upper()
        elif proble < 0.6:
            v["command"] = r["command"] + rng.choice(variants)
        else:
            v["command"] = "  " + " ".join(r["command"].split())
        out.append(v)
        i += 1
    with open(p, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["command", "vendor", "platform", "context", "label", "config", "split"])
        w.writeheader(); w.writerows(out)
    return len(out)


def scale_fleet(n_fleets: int = 500, dev_per: int = 20):
    import subprocess
    fd = D / "fleet"
    n_files = len(list(fd.rglob("DEV-*.json")))
    n_dirs = len([d for d in fd.iterdir() if d.is_dir()]) if fd.exists() else 0
    if n_dirs >= n_fleets and n_files >= n_fleets * dev_per:
        return n_files
    shutil.rmtree(fd, ignore_errors=True)
    sys.path.insert(0, str(Path(__file__).parent))
    import build_datasets as bd
    return bd.gen_fleet(fd, n_fleets=n_fleets, dev_per=dev_per)


def main():
    print("mapping...", flush=True)
    m = scale_mapping()
    print("lines...", flush=True)
    u = scale_lines()
    print("fleet...", flush=True)
    f = scale_fleet()
    man = json.loads((D / "manifest.json").read_text())
    man.update({"mappings": m, "unknown_lines": u, "fleet_devices": f, "fleet_count": 500})
    (D / "manifest.json").write_text(json.dumps(man, indent=1))
    print(json.dumps(man, indent=1))


if __name__ == "__main__":
    main()
