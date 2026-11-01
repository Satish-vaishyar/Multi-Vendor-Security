import io
import random
import tarfile
import zipfile

import pytest

from cloud import intake
from cloud.intake import IntakeError, Limits, ingest, sanitize_member_path


def make_zip(members, symlink=None, encrypted=None):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in members.items():
            zf.writestr(name, content)
        if symlink:
            zi = zipfile.ZipInfo(symlink)
            zi.create_system = 3
            zi.external_attr = (0o120777 << 16)
            zf.writestr(zi, "/etc/passwd")
    data = buf.getvalue()
    if encrypted:                       # flip the "encrypted" flag bit in the central directory entry
        idx = data.rfind(b"PK\x01\x02")
        data = data[:idx + 8] + bytes([data[idx + 8] | 1]) + data[idx + 9:]
    return data


def make_tar(members, gz=False, extra=None):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz" if gz else "w") as tf:
        for name, content in members.items():
            ti = tarfile.TarInfo(name)
            ti.size = len(content)
            tf.addfile(ti, io.BytesIO(content))
        for ti in extra or []:
            tf.addfile(ti)
    return buf.getvalue()


def test_single_file_is_accepted(tmp_path):
    r = ingest(b'resource "aws_s3_bucket" "b" {}\n', "main.tf", tmp_path / "w")
    assert r.kind == "file" and [f.path for f in r.files] == ["main.tf"]
    assert (tmp_path / "w" / "main.tf").read_text().startswith("resource")
    assert r.files[0].sha256 and r.files[0].size == 32


def test_single_file_name_is_reduced_to_basename(tmp_path):
    r = ingest(b"x: 1\n", "..\\..\\evil\\a.yaml", tmp_path / "w")
    assert [f.path for f in r.files] == ["a.yaml"]
    r2 = ingest(b"x: 1\n", "", tmp_path / "w2")
    assert [f.path for f in r2.files] == ["upload"]


def test_zip_and_tar_members_are_extracted(tmp_path):
    z = ingest(make_zip({"a/main.tf": "x", "b.yaml": "y: 1"}), "p.zip", tmp_path / "z")
    assert z.kind == "zip" and sorted(f.path for f in z.files) == ["a/main.tf", "b.yaml"]
    t = ingest(make_tar({"a/main.tf": b"x"}, gz=True), "p.tgz", tmp_path / "t")
    assert t.kind == "tar" and [f.path for f in t.files] == ["a/main.tf"]
    t2 = ingest(make_tar({"m.tf": b"x"}), "p.tar", tmp_path / "t2")
    assert t2.kind == "tar" and [f.path for f in t2.files] == ["m.tf"]


@pytest.mark.parametrize("name,reason", [
    ("../evil.tf", "path traversal"),
    ("a/../../evil.tf", "path traversal"),
    ("/etc/passwd", "absolute path"),
    ("C:/Windows/x.tf", "absolute path"),
    ("a\\b.tf", "backslash in path"),
    ("", "path traversal"),
    ("./", "path traversal"),
])
def test_hostile_paths_are_rejected_not_written(tmp_path, name, reason):
    r = ingest(make_tar({name: b"x", "ok.tf": b"y"}), "p.tar", tmp_path / "w")
    assert [f.path for f in r.files] == ["ok.tf"]
    assert r.rejected[0].reason == reason
    assert not (tmp_path / "evil.tf").exists()


def test_zip_slip_cannot_write_outside_destination(tmp_path):
    r = ingest(make_zip({"../escape.tf": "x", "ok.tf": "y"}), "p.zip", tmp_path / "w")
    assert [f.path for f in r.files] == ["ok.tf"] and not (tmp_path / "escape.tf").exists()


def test_control_characters_are_rejected_by_the_sanitiser():
    # tar/zip headers are C strings, so a NUL cannot arrive through an archive; other control characters can.
    for bad in ("a\x00b.tf", "a\nb.tf", "a\x1fb.tf"):
        with pytest.raises(ValueError, match="control character"):
            sanitize_member_path(bad, Limits())


def test_depth_and_length_limits():
    lim = Limits(max_depth=3, max_path_len=20)
    with pytest.raises(ValueError, match="too deep"):
        sanitize_member_path("a/b/c/d.tf", lim)
    with pytest.raises(ValueError, match="too long"):
        sanitize_member_path("averyveryverylongname.tf", lim)
    assert sanitize_member_path("./a//b/./c.tf", lim) == "a/b/c.tf"


def test_links_and_special_files_are_never_followed(tmp_path):
    link = tarfile.TarInfo("link.tf")
    link.type = tarfile.SYMTYPE
    link.linkname = "/etc/passwd"
    r = ingest(make_tar({"ok.tf": b"x"}, extra=[link]), "p.tar", tmp_path / "w")
    assert [f.path for f in r.files] == ["ok.tf"] and r.rejected[0].reason == "link or special file"
    rz = ingest(make_zip({"ok.tf": "x"}, symlink="evil.tf"), "p.zip", tmp_path / "z")
    assert [f.path for f in rz.files] == ["ok.tf"] and rz.rejected[0].reason == "link or special file"


def test_directory_entries_are_skipped(tmp_path):
    d = tarfile.TarInfo("dir")
    d.type = tarfile.DIRTYPE
    r = ingest(make_tar({"dir/a.tf": b"x"}, extra=[d]), "p.tar", tmp_path / "w")
    assert [f.path for f in r.files] == ["dir/a.tf"]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("folder/", "")
        zf.writestr("folder/a.tf", "x")
    assert [f.path for f in ingest(buf.getvalue(), "p.zip", tmp_path / "z").files] == ["folder/a.tf"]


def test_encrypted_zip_member_is_rejected(tmp_path):
    r = ingest(make_zip({"a.tf": "x"}, encrypted=True), "p.zip", tmp_path / "w")
    assert r.files == [] and r.rejected[0].reason == "encrypted member"


@pytest.mark.parametrize("name", [
    ".terraform/providers/x.tf", "a/.git/config", "prod.tfstate", "x.tfstate.backup", "id_rsa", ".env", ".env.prod",
    "key.pem", "cert.pfx", "credentials", "nested.zip", "bundle.tgz"])
def test_sensitive_and_unsupported_names_are_refused(tmp_path, name):
    r = ingest(make_zip({name: "data", "ok.tf": "x"}), "p.zip", tmp_path / "w")
    assert [f.path for f in r.files] == ["ok.tf"] and len(r.rejected) == 1


def test_state_file_requires_explicit_opt_in(tmp_path):
    data = make_zip({"a.tfstate": '{"version": 4}'})
    assert ingest(data, "p.zip", tmp_path / "off").files == []
    assert [f.path for f in ingest(data, "p.zip", tmp_path / "on", allow_state=True).files] == ["a.tfstate"]


def test_binary_and_nested_archive_content_is_refused(tmp_path):
    r = ingest(make_zip({"a.tf": b"\x7fELF" + b"\x00" * 50, "b.tf": b"MZ\x90\x00", "c.tf": b"a\x00b",
                         "d.txt": make_zip({"x": "y"}), "ok.tf": "x"}), "p.zip", tmp_path / "w")
    assert [f.path for f in r.files] == ["ok.tf"]
    assert {x.reason for x in r.rejected} == {"executable / binary content", "binary content",
                                              "nested archives are not accepted"}


def test_oversized_member_is_refused_by_header_and_by_real_size(tmp_path):
    lim = Limits(max_member=10)
    assert ingest(make_zip({"big.tf": "x" * 50, "ok.tf": "y"}), "p.zip", tmp_path / "a", lim).rejected[0].reason == "member too large"
    w = intake._Writer(tmp_path / "w", lim, False)
    w.add("lie.tf", io.BytesIO(b"x" * 50).read, declared=None)
    assert w.result.rejected[0].reason == "member too large"


def test_decompression_bomb_is_refused(tmp_path):
    bomb = make_zip({"big.tf": "A" * (3 * 1024 * 1024)})
    with pytest.raises(IntakeError, match="compression ratio"):
        ingest(bomb, "bomb.zip", tmp_path / "w", Limits(max_ratio=50))
    with pytest.raises(IntakeError, match="expanded size"):
        ingest(bomb, "bomb.zip", tmp_path / "w2", Limits(max_expanded=1024 * 1024))
    tbomb = make_tar({"a.tf": b"A" * 4000, "b.tf": b"A" * 4000}, gz=True)
    with pytest.raises(IntakeError, match="expanded size"):
        ingest(tbomb, "t.tgz", tmp_path / "w3", Limits(max_expanded=5000))


def test_too_many_files_and_too_large_upload(tmp_path):
    many = {f"f{i}.tf": "x" for i in range(5)}
    with pytest.raises(IntakeError, match="too many files"):
        ingest(make_zip(many), "p.zip", tmp_path / "a", Limits(max_files=3))
    with pytest.raises(IntakeError, match="too many files"):
        ingest(make_tar({k: b"x" for k in many}), "p.tar", tmp_path / "b", Limits(max_files=3))
    big = intake.Limits(max_compressed=10)
    with pytest.raises(IntakeError, match="upload too large"):
        ingest(b"x" * 11, "a.tf", tmp_path / "c", big)


def test_empty_and_malformed_uploads(tmp_path):
    with pytest.raises(IntakeError, match="empty"):
        ingest(b"", "a.tf", tmp_path / "w")
    with pytest.raises(IntakeError, match="malformed zip"):
        ingest(b"PK\x03\x04" + b"garbage" * 10, "a.zip", tmp_path / "z")
    with pytest.raises(IntakeError, match="malformed tar"):
        ingest(b"\x1f\x8b" + b"not really gzip", "a.tgz", tmp_path / "t")
    truncated = make_tar({"a.tf": random.Random(1).randbytes(4000)}, gz=True)[:-40]
    with pytest.raises(IntakeError, match="malformed tar"):
        ingest(truncated, "a.tgz", tmp_path / "t2")


def test_corrupt_zip_member_is_a_malformed_upload(tmp_path):
    data = bytearray(make_zip({"a.tf": "hello world " * 100}))
    data[34:54] = bytes([255]) * 20                # damage the deflate stream right after the local header
    with pytest.raises(IntakeError, match="malformed zip"):
        ingest(bytes(data), "a.zip", tmp_path / "w")


def test_detect_kind():
    assert intake.detect_kind(b"PK\x05\x06") == "zip"
    assert intake.detect_kind(b"\x1f\x8b") == "tar" and intake.detect_kind(b"BZh9") == "tar"
    assert intake.detect_kind(b"\xfd7zXZ\x00") == "tar"
    assert intake.detect_kind(b"x" * 257 + b"ustar") == "tar"
    assert intake.detect_kind(b"plain text") == "file"


def test_tar_directories_and_links_count_against_the_file_limit(tmp_path):
    entries = []
    for i in range(6):
        d = tarfile.TarInfo(f"d{i}")
        d.type = tarfile.DIRTYPE
        entries.append(d)
    with pytest.raises(IntakeError, match="too many files"):
        ingest(make_tar({"a.tf": b"x"}, extra=entries), "p.tar", tmp_path / "w", Limits(max_files=4))
    links = []
    for i in range(6):
        link = tarfile.TarInfo(f"l{i}")
        link.type = tarfile.SYMTYPE
        link.linkname = "x"
        links.append(link)
    with pytest.raises(IntakeError, match="too many files"):
        ingest(make_tar({}, extra=links), "p.tar", tmp_path / "w2", Limits(max_files=4))


def test_zip_directories_count_against_the_file_limit(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for i in range(6):
            zf.writestr(f"d{i}/", "")
    with pytest.raises(IntakeError, match="too many files"):
        ingest(buf.getvalue(), "p.zip", tmp_path / "w", Limits(max_files=4))


def test_declared_tar_sizes_are_accounted_even_for_skipped_members(tmp_path):
    big = tarfile.TarInfo("huge.zip")             # refused by name, but its declared size still counts
    big.size = 900
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        tf.addfile(big, io.BytesIO(b"z" * 900))
    with pytest.raises(IntakeError, match="expanded size"):
        ingest(buf.getvalue(), "p.tar", tmp_path / "w", Limits(max_expanded=500, max_member=1000))


def test_rejection_list_is_capped_and_overflow_counted(tmp_path):
    members = {f"a{i}.pem": b"x" for i in range(10)}
    r = ingest(make_tar(members), "p.tar", tmp_path / "w", Limits(max_rejected=3))
    assert len(r.rejected) == 3 and r.rejected_overflow == 7 and r.files == []


def test_real_bytes_are_enforced_when_headers_understate_the_size(tmp_path):
    w = intake._Writer(tmp_path / "w", Limits(max_expanded=100, max_member=1000), False)
    w.add("a.tf", io.BytesIO(b"x" * 80).read, declared=1)
    with pytest.raises(IntakeError, match="expanded size"):
        w.add("b.tf", io.BytesIO(b"x" * 80).read, declared=1)
