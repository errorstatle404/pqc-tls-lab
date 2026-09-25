"""AWS collectors against moto (a local fake of the AWS APIs), and the CLI end to end."""
import json
import os

import boto3
import pytest
from moto import mock_aws

from conftest import load
from pqcinv import aws_collect, cli, transports

REGION = "us-east-1"


@pytest.fixture
def aws(monkeypatch):
    for k in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SECURITY_TOKEN", "AWS_SESSION_TOKEN"):
        monkeypatch.setenv(k, "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    with mock_aws():
        yield boto3.Session(region_name=REGION)


def build_lab(s):
    """A miniature of deploy/aws: server + scanner, private DNS, internal ALB, KMS keys, ACM cert."""
    ec2 = s.client("ec2")
    vpc = ec2.create_vpc(CidrBlock="10.42.0.0/16")["Vpc"]["VpcId"]
    subnets = [ec2.create_subnet(VpcId=vpc, CidrBlock=f"10.42.{i}.0/24", AvailabilityZone=f"{REGION}{az}")
               ["Subnet"]["SubnetId"] for i, az in ((0, "a"), (1, "b"))]
    sg_server = ec2.create_security_group(GroupName="server", Description="s", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=sg_server, IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 8443, "ToPort": 8446, "IpRanges": [{"CidrIp": "10.42.0.0/16"}]}])
    sg_scanner = ec2.create_security_group(GroupName="scanner", Description="s", VpcId=vpc)["GroupId"]
    ami = ec2.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]
    server = ec2.run_instances(ImageId=ami, MinCount=1, MaxCount=1, SubnetId=subnets[0],
                               SecurityGroupIds=[sg_server],
                               TagSpecifications=[{"ResourceType": "instance",
                                                   "Tags": [{"Key": "Name", "Value": "pqc-tls-lab-server"}]}]
                               )["Instances"][0]
    ec2.run_instances(ImageId=ami, MinCount=1, MaxCount=1, SubnetId=subnets[1], SecurityGroupIds=[sg_scanner])

    r53 = s.client("route53")
    zone = r53.create_hosted_zone(Name="lab.internal", CallerReference="x", VPC={"VPCRegion": REGION, "VPCId": vpc},
                                  HostedZoneConfig={"PrivateZone": True, "Comment": ""})["HostedZone"]["Id"]
    r53.change_resource_record_sets(HostedZoneId=zone, ChangeBatch={"Changes": [{"Action": "CREATE",
        "ResourceRecordSet": {"Name": "pqc-server.lab.internal", "Type": "A", "TTL": 60,
                              "ResourceRecords": [{"Value": server["PrivateIpAddress"]}]}}]})

    kms = s.client("kms")
    k = kms.create_key(KeySpec="ECC_NIST_P256", KeyUsage="SIGN_VERIFY")["KeyMetadata"]["KeyId"]
    kms.create_alias(AliasName="alias/pqc-tls-lab-sign-ecdsa", TargetKeyId=k)

    elb = s.client("elbv2")
    lb = elb.create_load_balancer(Name="pqc-tls-lab-alb", Subnets=subnets, Scheme="internal",
                                  Type="application")["LoadBalancers"][0]
    cert = s.client("acm").request_certificate(DomainName="alb.lab.internal")["CertificateArn"]
    for port, policy in ((443, "ELBSecurityPolicy-2016-08"), (8443, "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09")):
        elb.create_listener(LoadBalancerArn=lb["LoadBalancerArn"], Protocol="HTTPS", Port=port, SslPolicy=policy,
                            Certificates=[{"CertificateArn": cert}],
                            DefaultActions=[{"Type": "fixed-response", "FixedResponseConfig": {
                                "StatusCode": "200", "ContentType": "text/plain", "MessageBody": "ok"}}])
    return lb


def test_collect_finds_every_tls_endpoint(aws):
    lb = build_lab(aws)
    inv = aws_collect.collect(aws, REGION)
    assert inv["errors"] == []
    assert inv["account"] == "123456789012"
    targets = {t.endpoint: t for t in aws_collect.targets_from_inventory(inv)}
    # Server ports come from its security group; the host name comes from the private zone.
    for p in (8443, 8444, 8445, 8446):
        assert targets[f"pqc-server.lab.internal:{p}"].source == "ec2"
    assert f"{lb['DNSName']}:443" in targets and f"{lb['DNSName']}:8443" in targets
    assert len(targets) == 6   # the scanner has no inbound rules, so nothing to probe there
    policies = {li["Port"]: li["Policy"]["SslProtocols"] for li in inv["load_balancers"][0]["Listeners"]}
    assert "TLSv1" in policies[443] and "TLSv1.3" in policies[8443]
    assert [k["KeySpec"] for k in inv["kms_keys"]] == ["ECC_NIST_P256"]
    assert inv["kms_keys"][0]["Aliases"] == ["alias/pqc-tls-lab-sign-ecdsa"]


def test_acm_is_asked_for_every_key_type(aws):
    """ACM hides EC and larger RSA certificates unless the request asks for them."""
    calls = []
    real = aws.client

    def spy(name, **kw):
        c = real(name, **kw)
        if name == "acm":
            c.meta.events.register("provide-client-params.acm.ListCertificates",
                                   lambda params, **_: calls.append(params))
        return c

    aws.client = spy
    aws_collect.collect_acm(aws, REGION)
    assert "EC_prime256v1" in calls[0]["Includes"]["keyTypes"]


def test_local_command_end_to_end(tmp_path, monkeypatch):
    """The full `pqcinv local` pipeline on a recorded run: report, CBOM, CSV, 8/8."""
    class Recorded:
        where = "recorded fixture"

        def run(self, script, timeout=0):
            assert script.count("### PROBE") == 24
            return load("lab-local.txt")

    monkeypatch.setattr(transports, "docker_compose", lambda *a, **k: Recorded())
    monkeypatch.setattr(cli.shutil, "which", lambda _: "/usr/bin/docker")
    assert cli.main(["local", "--out", str(tmp_path)]) == 0
    report = (tmp_path / "report.md").read_text()
    assert "8/8 checks (100%)" in report and "Silent downgrade" in report
    data = json.loads((tmp_path / "inventory.json").read_text())
    assert data["score"]["passed"] == 8
    assert json.loads((tmp_path / "cbom.json").read_text())["specVersion"] == "1.6"
    assert (tmp_path / "findings.csv").read_text().startswith("severity,id,")
    assert os.path.exists(tmp_path / "raw-probes.txt")


def test_aws_command_api_only(aws, tmp_path):
    """`pqcinv aws --via none`: configuration findings without any network probe."""
    build_lab(aws)
    assert cli.main(["aws", "--via", "none", "--tf-dir", "", "--region", REGION, "--out", str(tmp_path)]) == 0
    data = json.loads((tmp_path / "inventory.json").read_text())
    found = {(f["id"], f["asset"]) for f in data["findings"]}
    assert ("ELB-POLICY-NO-PQ", "pqc-tls-lab-alb:443") in found
    assert ("ELB-OLD-TLS", "pqc-tls-lab-alb:443") in found
    assert not any(a.endswith(":8443") for i, a in found if i.startswith("ELB-"))
    assert ("KMS-CLASSICAL-SIGNING", "alias/pqc-tls-lab-sign-ecdsa") in found
    assert "### Load balancer listeners" in (tmp_path / "report.md").read_text()


def test_ssm_transport_round_trip(aws, monkeypatch):
    """Script up through S3, command through SSM, output back through S3 (SSM itself is faked)."""
    from datetime import datetime, timezone

    class FixedNow(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime(2026, 9, 25, 12, 0, 0, tzinfo=timezone.utc)

    monkeypatch.setattr(transports, "datetime", FixedNow)
    monkeypatch.setattr(transports.time, "sleep", lambda _: None)
    s3 = aws.client("s3")
    s3.create_bucket(Bucket="lab-bucket")
    # What the scanner would upload after running the probe:
    s3.put_object(Bucket="lab-bucket", Key="results/inventory/20260925T120000Z/raw-probes.txt",
                  Body=load("lab-local.txt").encode())
    ec2 = aws.client("ec2")
    ami = ec2.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]
    iid = ec2.run_instances(ImageId=ami, MinCount=1, MaxCount=1)["Instances"][0]["InstanceId"]

    t = transports.SsmTransport(aws, REGION, iid, "lab-bucket")
    out = t.run("echo hi\n")
    assert "### DONE" in out
    job = s3.get_object(Bucket="lab-bucket", Key="inventory-jobs/20260925T120000Z/probe.sh")["Body"].read()
    assert job == b"echo hi\n"
    cmds = aws.client("ssm").list_commands()["Commands"][0]["Parameters"]["commands"]
    assert any("docker exec -i pqc-client sh -s" in c for c in cmds)
