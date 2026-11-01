"""Safe intake of untrusted uploads (RTM S05; CM-061, CM-062, CM-100, CM-101, CM-107).

Accepts a single file or a zip / tar / tar.gz archive and writes its members into a private directory. Nothing is ever
executed. The archive is hostile by assumption:
  * paths are validated before anything is written (zip-slip, absolute, drive-letter, backslash, NUL, dot-dot)
  * links, devices and nested archives are rejected, never followed
  * sizes are counted from the bytes actually read, not from attacker-controlled headers (decompression bombs)
  * credential files, Terraform state/plugin caches and executables are refused (state only with an explicit opt-in)
"""
from __future__ import annotations

import hashlib
import io
import posixpath
import stat
import tarfile
import zipfile
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, List, Optional, cast


class IntakeError(Exception):
    """The whole upload is refused (limit exceeded or malformed archive)."""


@dataclass(frozen=True)
class Limits:
    max_compressed: int = 50 * 1024 * 1024
    max_expanded: int = 200 * 1024 * 1024
    max_member: int = 20 * 1024 * 1024
    max_files: int = 2000
    max_depth: int = 12
    max_path_len: int = 240
    max_ratio: int = 200          # expanded bytes per compressed byte (archives only)
    max_rejected: int = 500       # report at most this many rejections; the rest are only counted


@dataclass
class Extracted:
    path: str           # relative, posix, sanitised
    size: int
    sha256: str


@dataclass
class Rejected:
    path: str
    reason: str


@dataclass
class IntakeResult:
    kind: str                                   # "file" | "zip" | "tar"
    files: List[Extracted] = field(default_factory=list)
    rejected: List[Rejected] = field(default_factory=list)
    rejected_overflow: int = 0                  # rejections beyond Limits.max_rejected
    expanded_bytes: int = 0


_SECRET_NAMES = {"credentials", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", ".netrc", ".npmrc", ".pypirc",
                 ".git-credentials", "service-account.json"}
_SECRET_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".ppk")
_STATE_SUFFIXES = (".tfstate", ".tfstate.backup")
_ARCHIVE_SUFFIXES = (".zip", ".tar", ".tgz", ".gz", ".bz2", ".xz", ".7z", ".rar", ".jar", ".war")
_BINARY_MAGIC = (b"\x7fELF", b"MZ", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe")


def detect_kind(data: bytes) -> str:
    if data[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
        return "zip"
    if data[:2] == b"\x1f\x8b" or data[:3] == b"BZh" or data[:6] == b"\xfd7zXZ\x00":
        return "tar"
    if data[257:262] == b"ustar":
        return "tar"
    return "file"


def sanitize_member_path(name: str, limits: Limits) -> str:
    """Return a safe relative posix path or raise ValueError describing why the member must be refused."""
    if any(ord(c) < 32 for c in name):
        raise ValueError("control character in path")
    if "\\" in name:
        raise ValueError("backslash in path")
    if name.startswith("/") or (len(name) > 1 and name[1] == ":"):
        raise ValueError("absolute path")
    parts = [p for p in posixpath.normpath(name).split("/") if p not in ("", ".")]
    if not parts or ".." in parts:
        raise ValueError("path traversal")
    if len(parts) > limits.max_depth:
        raise ValueError("path too deep")
    clean = "/".join(parts)
    if len(clean) > limits.max_path_len:
        raise ValueError("path too long")
    return clean


def classify_name(path: str, allow_state: bool) -> Optional[str]:
    """Reason a file name is refused as ordinary config, or None."""
    lower = path.lower()
    base = posixpath.basename(lower)
    segments = lower.split("/")
    if ".terraform" in segments or ".git" in segments:
        return "provider cache / VCS metadata is not accepted"
    if lower.endswith(_STATE_SUFFIXES) and not allow_state:
        return "Terraform state may contain secrets; explicit opt-in required"
    if base in _SECRET_NAMES or lower.endswith(_SECRET_SUFFIXES) or base.startswith(".env"):
        return "looks like a credential file"
    if lower.endswith(_ARCHIVE_SUFFIXES):
        return "nested archives are not accepted"
    return None


def _content_problem(head: bytes) -> Optional[str]:
    if head.startswith(_BINARY_MAGIC):
        return "executable / binary content"
    if detect_kind(head) != "file":
        return "nested archives are not accepted"
    if b"\x00" in head:
        return "binary content"
    return None


class _Writer:
    def __init__(self, dest: Path, limits: Limits, allow_state: bool):
        self.dest, self.limits, self.allow_state = dest.resolve(), limits, allow_state
        self.result = IntakeResult(kind="file")
        self.count = 0
        self.declared = 0

    def reject(self, path: str, reason: str) -> None:
        if len(self.result.rejected) < self.limits.max_rejected:
            self.result.rejected.append(Rejected(path, reason))
        else:
            self.result.rejected_overflow += 1

    def tick(self, declared_size: int) -> None:
        """Account for EVERY archive member (files, directories, links, devices) before looking at it."""
        self.count += 1
        self.declared += declared_size
        if self.count > self.limits.max_files:
            raise IntakeError("too many files")
        if self.declared > self.limits.max_expanded:
            raise IntakeError("expanded size limit exceeded")

    def add(self, name: str, reader, declared: Optional[int] = None) -> None:
        lim = self.limits
        try:
            rel = sanitize_member_path(name, lim)
        except ValueError as e:
            shown = name[:120].encode("ascii", "replace").decode()
            self.reject(shown, str(e))
            return
        why = classify_name(rel, self.allow_state)
        if why:
            self.reject(rel, why)
            return
        if declared is not None and declared > lim.max_member:
            self.reject(rel, "member too large")
            return
        target = (self.dest / rel).resolve()
        if self.dest not in target.parents:       # pragma: no cover - sanitize_member_path makes this unreachable
            raise IntakeError("path escapes destination")
        data = reader(lim.max_member + 1)
        if len(data) > lim.max_member:
            self.reject(rel, "member too large")
            return
        self.result.expanded_bytes += len(data)
        if self.result.expanded_bytes > lim.max_expanded:
            raise IntakeError("expanded size limit exceeded")
        problem = _content_problem(data[:4096])
        if problem:
            self.reject(rel, problem)
            return
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        self.result.files.append(Extracted(rel, len(data), hashlib.sha256(data).hexdigest()))


def _zip(data: bytes, w: _Writer) -> None:
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as e:
        raise IntakeError(f"malformed zip: {e}")
    with zf:
        infos = zf.infolist()
        if len(infos) > w.limits.max_files:
            raise IntakeError("too many files")
        if sum(i.file_size for i in infos) > w.limits.max_expanded:
            raise IntakeError("expanded size limit exceeded")
        for info in infos:
            w.tick(info.file_size)
            if info.is_dir():
                continue
            kind = stat.S_IFMT(info.external_attr >> 16)         # 0 when the archiver recorded no file type
            if kind not in (0, stat.S_IFREG):
                w.reject(info.filename[:120], "link or special file")
                continue
            if info.flag_bits & 0x1:
                w.reject(info.filename[:120], "encrypted member")
                continue
            try:
                with zf.open(info) as fh:
                    w.add(info.filename, fh.read, declared=info.file_size)
            except (zipfile.BadZipFile, zlib.error, NotImplementedError, RuntimeError) as e:
                raise IntakeError(f"malformed zip member: {e}")


def _tar(data: bytes, w: _Writer) -> None:
    try:
        tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:*")
    except (tarfile.TarError, EOFError, OSError) as e:
        raise IntakeError(f"malformed tar: {e}")
    with tf:
        try:
            for m in tf:
                tf.members = []                      # tarfile caches every member it has seen; do not let that grow
                w.tick(m.size)
                if m.isdir():
                    continue
                if not m.isreg():
                    w.reject(m.name[:120], "link or special file")
                    continue
                w.add(m.name, cast(IO[bytes], tf.extractfile(m)).read, declared=m.size)
        except (tarfile.TarError, EOFError, OSError) as e:
            raise IntakeError(f"malformed tar: {e}")


def ingest(data: bytes, filename: str, dest: Path, limits: Limits = Limits(), allow_state: bool = False) -> IntakeResult:
    """Validate and write an upload into `dest` (a private, empty, per-scan directory)."""
    if not data:
        raise IntakeError("empty upload")
    if len(data) > limits.max_compressed:
        raise IntakeError("upload too large")
    dest.mkdir(parents=True, exist_ok=True)
    w = _Writer(dest, limits, allow_state)
    kind = detect_kind(data)
    w.result.kind = kind
    if kind == "zip":
        _zip(data, w)
    elif kind == "tar":
        _tar(data, w)
    else:
        name = posixpath.basename(filename.replace("\\", "/")) or "upload"
        w.add(name, io.BytesIO(data).read)
    if kind != "file" and w.result.expanded_bytes > limits.max_ratio * len(data):
        raise IntakeError("compression ratio too high")
    return w.result
