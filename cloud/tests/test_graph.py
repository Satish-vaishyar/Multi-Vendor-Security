from cloud import graph
from cloud.ir import Finding, Ref, Resource, Source


def res(rtype, addr, **props):
    return Resource("x", "", rtype, addr.rsplit(".", 1)[-1], addr, props, Source("f", 1, 1)).finalize()


def fnd(addr, state="FAIL_STATIC", cid="CLOUD-NET-001"):
    return Finding(cid, "t", "HIGH", state, addr, "aws_security_group", "aws", [], {})


def test_attached_group_is_effective_and_unattached_is_not():
    sg1, sg2 = res("aws_security_group", "aws_security_group.a"), res("aws_security_group", "aws_security_group.b")
    inst = res("aws_instance", "aws_instance.i", sgs=[Ref("aws_security_group.a.id")])
    rule = res("aws_security_group_rule", "aws_security_group_rule.r", sg=Ref("aws_security_group.b.id"))
    other = res("aws_instance", "aws_instance.j", x=Ref("nothing.here"), y=Ref("aws_instance.j.id"))
    rs = [sg1, sg2, inst, rule, other]
    g = graph.build(rs)
    assert g["attached_by"] == {"aws_security_group.a": ["aws_instance.i"]}
    fs = [fnd("aws_security_group.a"), fnd("aws_security_group.b"), fnd("aws_security_group.a"), fnd("aws_security_group.a", "PASS_STATIC"),
          fnd("aws_security_group.a", cid="CLOUD-IAM-001"), fnd("aws_instance.i"), fnd("missing")]
    s = graph.annotate(fs, rs, incomplete=False)
    assert s == {"edges": 2, "attached": 1, "unattached": 1, "unknown": 0}
    assert "Effective exposure" in fs[0].notes[0] and "Unattached" in fs[1].notes[0]
    assert fs[0].evidence_state == "FAIL_STATIC" and fs[1].evidence_state == "FAIL_STATIC"
    assert not fs[3].notes and not fs[4].notes and not fs[5].notes


def test_incomplete_files_make_attachment_unknown_and_cfn_logical_ids_resolve():
    sg = res("AWS::EC2::SecurityGroup", "Web")
    inst = res("AWS::EC2::Instance", "Srv", g=Ref("Web"))
    g = graph.build([sg, inst])
    assert graph.attachment(g, sg, True) is True
    lone = res("AWS::EC2::SecurityGroup", "Lone")
    f = fnd("Lone")
    assert graph.annotate([f], [lone], True)["unknown"] == 1 and "could not be determined" in f.notes[0]
    assert graph.attachment(graph.build([lone]), lone, False) is False
    assert graph._resolve("nope", ["a.b"]) is None
    assert graph._resolve("mod.x.aws_security_group.a.id", ["aws_security_group.a[0]", "aws_security_group.a"]) is None
    assert graph._resolve("aws_security_group.a[0].id", ["aws_security_group.a[0]"]) == "aws_security_group.a[0]"
    assert graph._resolve("Web", ["stack.Web"]) == "stack.Web"
