import json

from cloud.ir import Ref, Unknown
from cloud.parsers.cloudformation import parse_cloudformation

CFN = """\
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  Env: {Type: String, Default: prod}
  Cidr: {Type: String}
Mappings:
  Ports: {web: {http: 80}}
Resources:
  PublicBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Sub '${Env}-bucket-${AWS::Region}'
      PublicAccessBlockConfiguration:
        BlockPublicAcls: false
        IgnorePublicAcls: false
  OpenSsh:
    Type: AWS::EC2::SecurityGroup
    DependsOn: PublicBucket
    Properties:
      GroupDescription: !Join ['-', [sg, !Ref Env]]
      VpcId: vpc-0123456789abcdef0
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: !FindInMap [Ports, web, http]
          ToPort: 22
          CidrIp: !Ref Cidr
  Cond:
    Type: AWS::SNS::Topic
    Condition: IsProd
    Properties:
      TopicName: !If [IsProd, a, b]
      Ref1: !Ref PublicBucket
      Arn: !GetAtt PublicBucket.Arn
      Arn2: !GetAtt [PublicBucket, Arn]
      Sel: !Select [1, [a, b]]
      Missing: !Ref Nope
  Nested:
    Type: AWS::CloudFormation::Stack
    Properties:
      TemplateURL: https://example.com/child.yaml
"""


def test_cloudformation_fixture_resources_and_intrinsics():
    r = parse_cloudformation("aws.yaml", CFN)
    assert r.errors == []
    bucket, sg, cond, nested = r.resources
    assert (bucket.provider, bucket.service, bucket.resource_type) == ("aws", "s3", "AWS::S3::Bucket")
    assert bucket.properties["PublicAccessBlockConfiguration"]["BlockPublicAcls"] is False
    assert isinstance(bucket.properties["BucketName"], Unknown)               # AWS::Region is not known offline
    assert sg.properties["GroupDescription"] == "sg-prod"
    ingress = sg.properties["SecurityGroupIngress"][0]
    assert ingress["FromPort"] == 80 and isinstance(ingress["CidrIp"], Unknown)  # Cidr has no default
    assert "SecurityGroupIngress[0].CidrIp" in sg.unknown_fields
    assert {"type": "DEPENDS_ON", "field": "DependsOn", "target": "PublicBucket"} in sg.relationships
    assert (bucket.source.file, bucket.source.line_start, bucket.source.format) == ("aws.yaml", 8, "cloudformation")
    assert cond.confidence == 0.5 and "conditional resource" in cond.notes[0]
    assert isinstance(cond.properties["TopicName"], Unknown) and cond.properties["Ref1"] == Ref("PublicBucket")
    assert cond.properties["Arn"] == Ref("PublicBucket.Arn") == cond.properties["Arn2"] and cond.properties["Sel"] == "b"
    assert isinstance(cond.properties["Missing"], Unknown)
    assert r.unresolved_modules[0]["module"] == "Nested" and "not fetched" in r.unresolved_modules[0]["reason"]


def test_cloudformation_json_input_and_sam():
    doc = {"Transform": "AWS::Serverless-2016-10-31", "Resources": {
        "Fn": {"Type": "AWS::Serverless::Function", "Properties": {"Handler": "app.handler"}},
        "Q": {"Type": "Alexa::ASK::Skill", "Properties": {}}}}
    r = parse_cloudformation("t.json", json.dumps(doc))
    fn, skill = r.resources
    assert fn.source.format == "cloudformation_sam" and "transform not expanded" in fn.notes[0]
    assert skill.provider == "aws" and r.errors == []


def test_cloudformation_sub_forms_and_edge_cases():
    t = """\
Parameters:
  P: {Type: String, Default: x}
  Q: {Type: String}
Resources:
  A:
    Type: AWS::SQS::Queue
    Properties:
      S1: !Sub ['${P}-${Local}', {Local: l}]
      S2: !Sub '${A}-${A.Arn}'
      S7: !Sub '${A.Arn}'
      S3: !Sub '${Q}'
      S4: !Sub '${P}'
      S5: !Sub '${Pseudo}'
      S6: !Sub [1]
      J1: !Join [',', [a, !Ref Q]]
      J2: !Join [1]
      Sel1: !Select [9, [a]]
      Sel2: !Select [x, [a]]
      Map1: !FindInMap [Nope, a, b]
      Map2: !FindInMap [a]
      B64: !Base64 hello
      Imp: !ImportValue other
      BadRef: {Ref: [1]}
      BadAt: !GetAtt 5
      Plain: {a: 1}
"""
    p = parse_cloudformation("q.yaml", t).resources[0].properties
    assert p["S1"] == "x-l" and p["S4"] == "x" and p["B64"] == "hello" and p["Plain"] == {"a": 1}
    for k in ("S2", "S7", "S3", "S5", "S6", "J1", "J2", "Sel1", "Sel2", "Map1", "Map2", "Imp", "BadRef", "BadAt"):
        assert isinstance(p[k], Unknown), k


def test_cloudformation_errors_are_reported_not_raised():
    assert parse_cloudformation("a.yaml", "a: [unclosed").errors[0]["error"].startswith("invalid template")
    assert parse_cloudformation("a.yaml", "- 1").errors[0]["error"] == "no Resources section"
    assert parse_cloudformation("a.yaml", "Resources: {}").resources == []
    r = parse_cloudformation("a.yaml", "Resources:\n  Bad: {Properties: {}}\n  AlsoBad: str\n  Ok: {Type: Foo::Bar::Baz}\n")
    assert len(r.errors) == 2 and r.resources[0].provider == "foo"
    scalar_props = parse_cloudformation("a.yaml", "Resources:\n  X: {Type: AWS::X::Y, Properties: !Ref Nope}\n")
    assert scalar_props.resources[0].properties == {"value": Unknown("pseudo parameter or unknown reference", "Nope")}
    notype = parse_cloudformation("a.yaml", "Resources:\n  X: {Type: Lonely}\n").resources[0]
    assert notype.service == "" and notype.provider == "lonely"
    depends = parse_cloudformation("a.yaml", "Resources:\n  A: {Type: AWS::S3::Bucket}\n  B: {Type: AWS::S3::Bucket, DependsOn: [A, 5]}\n")
    assert depends.resources[1].relationships == [{"type": "DEPENDS_ON", "field": "DependsOn", "target": "A"}]
