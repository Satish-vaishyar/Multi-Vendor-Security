"""Setup-time download: vendor the MiniLM embedding weights into the repo.

Run once during application setup (needs network). After that the backend
loads the model from this local snapshot on every start — no HuggingFace
traffic, no per-request cold-start stall.

    python models/scripts/download_minilm.py

Target: models/artifacts/minilm/ (gitignored, machine-local).
Override: MINILM_DIR env var.
"""
from __future__ import annotations
import os
import sys
from pathlib import Path

REPO_ID = "sentence-transformers/all-MiniLM-L6-v2"
DEFAULT_DIR = Path(__file__).parent.parent / "artifacts" / "minilm"


def main() -> int:
    dest = Path(os.environ.get("MINILM_DIR", str(DEFAULT_DIR)))
    if (dest / "config.json").exists() and any(dest.glob("*.safetensors")) | any(dest.glob("*.bin")):
        print(f"MiniLM already vendored at {dest} — skipping download.")
    else:
        print(f"Downloading {REPO_ID} -> {dest} ...")
        from huggingface_hub import snapshot_download
        snapshot_download(repo_id=REPO_ID, local_dir=str(dest))
        print("Download complete.")
    # Verify the snapshot actually loads.
    sys.path.insert(0, str(Path(__file__).parent.parent))
    os.environ.setdefault("HF_HUB_OFFLINE", "1")
    os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")
    from sentence_transformers import SentenceTransformer
    m = SentenceTransformer(str(dest), local_files_only=True)
    v = m.encode(["setup verification"], normalize_embeddings=True)
    print(f"Verified: snapshot loads, embedding dim={v.shape[1]}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
