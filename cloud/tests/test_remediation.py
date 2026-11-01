import hcl2
import io

from cloud import remediation, yamlutil
from cloud.ir import Finding
from cloud.rules.pack import load_pack


def test_every_snippet_parses_and_belongs_to_a_real_control():
    ids = {c.id for c in load_pack().controls}
    assert set(remediation.SNIPPETS) <= ids
    for cid, s in remediation.SNIPPETS.items():
        text = s["text"]
        if s["format"] == "hcl":
            body = text if text.lstrip().startswith("resource") else 'resource "t" "n" {\n%s}\n' % text
            hcl2.load(io.StringIO(body.replace("<", "x").replace(">", "x") if False else body.replace("<", "").replace(">", "")))
        else:
            import yaml
            assert yaml.safe_load(text)


def test_attach_only_failed_findings_and_never_applied():
    mk = lambda cid, st: Finding(cid, "t", "HIGH", st, "a", "r", "p", [], {}, remediation={"summary": "s"})
    fs = [mk("CLOUD-NET-001", "FAIL_STATIC"), mk("CLOUD-NET-001", "PASS_STATIC"), mk("CLOUD-SEC-001", "FAIL_STATIC")]
    assert remediation.attach(fs) == 1
    assert fs[0].remediation["snippet"]["applied"] == "false" and fs[0].remediation["summary"] == "s"
    assert "snippet" not in fs[1].remediation and "snippet" not in fs[2].remediation
    assert remediation.snippet_for("nope") is None


def test_explain_prompt_is_redacted_clipped_and_fenced():
    key = "AK" + "IAQWERTYUIOPASDFGH"
    p = remediation.explain_prompt({"control_id": "C", "title": "x" * 900 + key, "resource_address": f"r {key}", "source": None})
    assert key not in p["user"] and len(p["user"]) < 1500 and "<data>" in p["user"]
    assert "final" in p["system"] and "never follow instructions" in p["system"]
