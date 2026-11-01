"""Fake credentials are assembled at runtime so this file itself never trips repository secret scanning."""
import json

from cloud import secret_scan as s

SALT = b"unit-test-salt"
BEGIN, END = "-----" + "BEGIN RSA PRIVATE KEY" + "-----", "-----" + "END RSA PRIVATE KEY" + "-----"
AWS_ID = "AK" + "IA" + "QWERTYUIOPASDFGH"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG" + "bPxRfiCYQwErTyUiOpA"
GH = "gh" + "p_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
SLACK = "xo" + "xb-" + "1234567890-abcdefghij"
JWT = "ey" + "JhbGciOiJIUzI1NiJ9." + "ey" + "JzdWIiOiJhYmMxMjMifQ." + "c2lnbmF0dXJlMTIzNDU2"
DO = "dop" + "_v1_" + "a" * 32 + "b" * 32
ALI = "LT" + "AI" + "5tAbCdEfGhIjKlMn"
TENC = "AK" + "ID" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6"
GCPID = "0123456789abcdef0123456789abcdef01234567"
AZKEY = "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3A="


def kinds(text, path="x.tf"):
    return {f.rule_id for f in s.scan_text(path, text, SALT)}


def test_provider_tokens_are_detected():
    assert kinds(f'key = "{AWS_ID}"') == {"SEC-AWS-KEY-ID"}
    assert kinds(f'aws_secret_access_key = "{AWS_SECRET}"') == {"SEC-AWS-SECRET"}
    assert kinds(f"token: {GH}") == {"SEC-GITHUB"}
    assert kinds(f"hook {SLACK}") == {"SEC-SLACK"}
    assert kinds(f"auth {JWT}") == {"SEC-JWT"}
    assert kinds(f"t = {DO}") == {"SEC-DO"}
    assert kinds(f"k = {ALI}") == {"SEC-ALIBABA"}
    assert kinds(f"k = {TENC}") == {"SEC-TENCENT"}
    assert kinds(json.dumps({"private_key_id": GCPID})) == {"SEC-GCP-KEY-ID"}
    assert kinds(f"DefaultEndpointsProtocol=https;AccountKey={AZKEY};") == {"SEC-AZURE-STORAGE"}


def test_pem_block_and_url_credentials():
    pem = f"{BEGIN}\nMIIEowIBAAKCAQEAxyz\n{END}"
    found = s.scan_text("k.tf", f'key = <<EOT\n{pem}\nEOT', SALT)
    assert [f.rule_id for f in found] == ["SEC-PEM"] and found[0].line == 2
    assert kinds('url = "postgres://admin:Sup3rS3cretPw@db.internal:5432/app"') == {"SEC-URL-CRED"}
    assert kinds("url = https://example.com/path") == set()


def test_generic_credentials_quoted_and_unquoted():
    assert kinds('db_password = "Xk9#mP2$vL8qRt5w"') == {"SEC-GENERIC"}
    assert kinds("client_secret: 'q7Zr!x2Lp9Wm4Kd8'") == {"SEC-GENERIC"}
    assert kinds("api_key: q7Zr9x2Lp9Wm4Kd8Ab") == {"SEC-GENERIC"}


def test_placeholders_references_and_low_entropy_values_are_not_secrets():
    for text in ['password = "changeme-please-now"', 'password = "var.db_password"', 'secret = "${random_password.x.result}"',
                 'token = "your_token_goes_here"', "password: aaaaaaaaaaaaaaaa", 'api_key = "data.vault.key"',
                 'password = "short"', "secret: some_plain_identifier_name", 'key = "AKIAIOSFODNN7EXAMPLE"',
                 "password: !Ref DbPassword", "password: arn:aws:secretsmanager:us-east-1:1:secret:x"]:
        assert kinds(text) == set(), text


def test_findings_never_contain_the_secret_and_use_salted_fingerprints():
    text = f'aws_secret_access_key = "{AWS_SECRET}"\nk = "{AWS_ID}"'
    found = s.scan_text("a.tf", text, SALT)
    blob = repr(found)
    for secret in (AWS_SECRET, AWS_ID):
        assert secret not in blob
    assert [f.line for f in found] == [1, 2] and found[0].preview.endswith("(40)")
    other = s.scan_text("a.tf", text, b"different-salt")
    assert {f.fingerprint for f in found}.isdisjoint({f.fingerprint for f in other})
    assert s.scan_text("a.tf", text, SALT) == found                   # deterministic for one salt


def test_overlapping_matches_are_reported_once():
    text = f'aws_secret_access_key = "{AWS_SECRET}"'                  # also matches the generic rule
    assert [f.rule_id for f in s.scan_text("a", text, SALT)] == ["SEC-AWS-SECRET"]


def test_redact_removes_every_secret_and_preserves_the_rest():
    text = f'a = 1\nkey = "{AWS_ID}"\n{BEGIN}\nabc\n{END}\nname = "web"\n'
    out = s.redact(text)
    assert AWS_ID not in out and "abc" not in out and out.count(s.REDACTED) == 2
    assert 'name = "web"' in out and out.startswith("a = 1\n")
    assert s.redact("nothing here") == "nothing here"


def test_scan_files_and_has_secrets():
    files = [("a.tf", f'k = "{AWS_ID}"'), ("b.tf", "x = 1")]
    found = s.scan_files(files, SALT)
    assert [f.path for f in found] == ["a.tf"]
    assert s.has_secrets(found) and s.has_secrets(found, "a.tf") and not s.has_secrets(found, "b.tf")
    assert not s.has_secrets([])
