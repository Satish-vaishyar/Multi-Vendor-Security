"""Integrity gate for serialized ML artifacts (pickle/joblib).

``joblib.load`` executes code embedded in the file, so a tampered artifact is a
remote-code-execution primitive. Every load in this project goes through
``load_verified`` which checks the file's SHA-256 against a manifest
(``artifacts/ARTIFACTS.sha256.json``), optionally authenticated with an HMAC
(``ARTIFACT_SIGNING_KEY``).

Policy (``ARTIFACT_VERIFY``):
  strict  - missing manifest / unknown file / hash mismatch -> refuse (default when ENV=production)
  warn    - log the problem and load anyway (default otherwise)
  off     - skip (never use in production)

Re-generate after intentionally retraining:  python models/scripts/sign_artifacts.py
"""
from __future__ import annotations
import hashlib
import hmac
import json
import logging
import os
from pathlib import Path
from typing import Any, Dict

log = logging.getLogger("artifact_guard")

MANIFEST_NAME = "ARTIFACTS.sha256.json"


class ArtifactIntegrityError(RuntimeError):
    pass


def _mode() -> str:
    explicit = os.getenv("ARTIFACT_VERIFY", "").strip().lower()
    if explicit in ("strict", "warn", "off"):
        return explicit
    return "strict" if os.getenv("ENV", "development").lower() == "production" else "warn"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _canonical(files: Dict[str, str]) -> bytes:
    return json.dumps(files, sort_keys=True, separators=(",", ":")).encode()


def _sign(files: Dict[str, str], key: str) -> str:
    return hmac.new(key.encode(), _canonical(files), hashlib.sha256).hexdigest()


def write_manifest(artifacts_dir: Path) -> Dict[str, Any]:
    """Hash every .pkl/.joblib in ``artifacts_dir`` and write the manifest."""
    files = {p.name: sha256_file(p) for p in sorted(artifacts_dir.glob("*"))
             if p.suffix in (".pkl", ".joblib")}
    manifest: Dict[str, Any] = {"algorithm": "sha256", "files": files}
    key = os.getenv("ARTIFACT_SIGNING_KEY", "")
    if key:
        manifest["hmac"] = _sign(files, key)
    (artifacts_dir / MANIFEST_NAME).write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def verify(path: Path) -> None:
    """Raise ArtifactIntegrityError (strict) or log (warn) when ``path`` is untrusted."""
    mode = _mode()
    if mode == "off":
        return
    path = Path(path)
    problem = ""
    mpath = path.parent / MANIFEST_NAME
    if not mpath.exists():
        problem = f"manifest {MANIFEST_NAME} missing next to {path.name}"
    else:
        try:
            manifest = json.loads(mpath.read_text(encoding="utf-8"))
            files = manifest.get("files", {})
            key = os.getenv("ARTIFACT_SIGNING_KEY", "")
            if key:
                if not manifest.get("hmac") or not hmac.compare_digest(
                        manifest["hmac"], _sign(files, key)):
                    problem = "manifest signature invalid"
            elif mode == "strict" and os.getenv("ENV", "").lower() == "production":
                log.warning("ARTIFACT_SIGNING_KEY not set: manifest is hash-only (not authenticated)")
            if not problem:
                expected = files.get(path.name)
                if not expected:
                    problem = f"{path.name} not listed in manifest"
                elif not hmac.compare_digest(expected, sha256_file(path)):
                    problem = f"{path.name} hash mismatch (file modified)"
        except (ValueError, OSError) as e:
            problem = f"manifest unreadable: {e}"
    if problem:
        if mode == "strict":
            raise ArtifactIntegrityError(f"refusing to load artifact: {problem}")
        log.warning("artifact integrity: %s (ARTIFACT_VERIFY=warn)", problem)


def load_verified(path: Path):
    """``joblib.load`` after an integrity check."""
    import joblib
    verify(Path(path))
    return joblib.load(path)
