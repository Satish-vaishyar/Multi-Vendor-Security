"""Fleet generator for anomaly detection (OKF-D3 / models M7).

Builds N fleets of M devices from secure baselines, injects controlled
deviations (telnet on, logging off, weak ssh, public snmp, http on, no acl),
writes data/fleets/fleet_XXX/{manifest, devices/*.json(IR)} + deviation labels.

Usage: python scripts/generate_fleet.py --fleets 5 --devices 20 --out data/fleets
"""
from __future__ import annotations
import argparse
import json
import random
from pathlib import Path

BASELINE = {"SSH.VERSION": 2, "TELNET.ENABLED": False, "HTTP.ENABLED": False,
            "SNMP.COMMUNITY_PUBLIC": False, "SNMP.VERSION": 3,
            "LOGGING.ENABLED": True, "LOGGING.REMOTE_SERVER": True,
            "NTP.ENABLED": True, "AAA.AUTHENTICATION": True,
            "ACL.MGMT_RESTRICTED": True, "CRYPTO.WEAK_ALGO": False,
            "SERVICE.PASSWORD_ENCRYPTION": True}
DEVIATIONS = {"telnet": {"TELNET.ENABLED": True}, "no-log": {"LOGGING.ENABLED": False},
              "weak-ssh": {"SSH.VERSION": 1}, "public-snmp": {"SNMP.COMMUNITY_PUBLIC": True},
              "http": {"HTTP.ENABLED": True}, "no-acl": {"ACL.MGMT_RESTRICTED": False},
              "weak-crypto": {"CRYPTO.WEAK_ALGO": True}}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fleets", type=int, default=5)
    ap.add_argument("--devices", type=int, default=20)
    ap.add_argument("--out", default="data/fleets")
    ap.add_argument("--seed", type=int, default=7)
    a = ap.parse_args()
    rng = random.Random(a.seed)
    out = Path(a.out)
    for fi in range(a.fleets):
        fd = out / f"fleet_{fi:03d}"
        (fd / "devices").mkdir(parents=True, exist_ok=True)
        devs = []
        for di in range(a.devices):
            ir = dict(BASELINE)
            label = "normal"
            if rng.random() < 0.12:  # ~12% deviants
                name = rng.choice(list(DEVIATIONS))
                ir.update(DEVIATIONS[name])
                label = f"anomaly:{name}"
            devs.append({"device_id": f"DEV-{fi:03d}-{di:03d}", "label": label, "ir": ir})
            (fd / "devices" / f"DEV-{fi:03d}-{di:03d}.json").write_text(
                json.dumps(devs[-1], indent=1), encoding="utf-8")
        (fd / "manifest.json").write_text(json.dumps(
            {"fleet": fi, "devices": len(devs),
             "anomalies": sum(1 for d in devs if d["label"] != "normal")}, indent=1), encoding="utf-8")
    print(json.dumps({"fleets": a.fleets, "devices_each": a.devices, "out": str(out)}))


if __name__ == "__main__":
    main()
