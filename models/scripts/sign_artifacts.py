"""Write models/artifacts/ARTIFACTS.sha256.json (hashes, plus HMAC when
ARTIFACT_SIGNING_KEY is set). Run after (re)training; commit the manifest
through code review. Never run it on artifacts you did not produce yourself.

    python models/scripts/sign_artifacts.py
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from artifact_guard import write_manifest  # noqa: E402

if __name__ == "__main__":
    m = write_manifest(ROOT / "artifacts")
    print(f"signed {len(m['files'])} artifacts" + (" (HMAC)" if m.get("hmac") else " (hash only)"))
    for name, digest in m["files"].items():
        print(f"  {digest[:16]}  {name}")
