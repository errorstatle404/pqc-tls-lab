"""Offline tests. The probe fixture is real output from scripts/probe.sh run against the lab's nginx
config (OpenSSL 3.5.4 / nginx 1.28.0) plus a TLS 1.0-1.2 RSA endpoint and a closed port.
AWS is simulated with moto, so no credentials are needed.

    cd inventory && python -m pytest -q
"""
from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

import pytest

from cryptoinv import aws_collect, cbom, findings, probes, score
from cryptoinv.__main__ import main

HERE = Path(__file__).parent
FIX = HERE / "fixtures" / "probe-local"
NOW = dt.datetime(2026, 9, 25, tzinfo=dt.timezone.utc)  # fixed clock: fixture legacy cert expires 2026-10-14


@pytest.fixture(scope="module")
def eps():
    e, _ = probes.load(FIX)
    return {x.label: x for x in e}


# ---------------- network posture ----------------
@pytest.mark.parametrize("label,posture,default_group", [
    ("lab-classical", "none", "x25519"),
    ("lab-hybrid", "not-enforced", "X25519MLKEM768"),
    ("lab-hybrid-strict", "enforced", "X25519MLKEM768"),
    ("lab-pq-only", "pq-only", None),
    ("legacy", "no-tls13", None),
    ("closed-port", "unreachable", None),
])
def test_posture(eps, label, posture, default_group):
    assert eps[label].pq_kex == posture
    assert eps[label].default_group == default_group


def test_strict_endpoint_used_hello_retry(eps):
    hs = eps["lab-hybrid-strict"].hs("classical-first")
    assert hs.ok and hs.hrr and hs.group == "X25519MLKEM768"
    # ...while the non-strict endpoint silently took the classical share
    hs = eps["lab-hybrid"].hs("classical-first")
    assert hs.ok and not hs.hrr and hs.group == "x25519"


def test_versions_and_certs(eps):
    assert eps["legacy"].legacy_versions == ["tls1", "tls1_1"]
    assert eps["legacy"].tls12 and not eps["lab-hybrid"].tls12
    assert eps["lab-pq-only"].pq_auth == "resistant"
    assert eps["lab-hybrid"].pq_auth == "vulnerable"
    assert eps["lab-pq-only"].chain_bytes > 10 * eps["lab-hybrid"].chain_bytes


def test_network_findings(eps):
    fs = findings.network_findings(list(eps.values()), now=NOW)
    got = {(f.id, f.asset.split(":")[-1]) for f in fs}
    assert ("PQC-KEX-NONE", "8444") in got
    assert ("PQC-KEX-NOT-ENFORCED", "8443") in got
    assert ("PQC-KEX-NO-FALLBACK", "8445") in got
    assert ("PQC-KEX-NO-TLS13", "8447") in got
    assert ("TLS-LEGACY-VERSION", "8447") in got
    assert ("CERT-EXPIRING", "8447") in got
    assert not any(a == "8446" and i.startswith("PQC-KEX") for i, a in got), "strict endpoint is compliant"
    assert not any(a == "8449" for _, a in got), "unreachable endpoints produce no findings"


# ---------------- scoring ----------------
def test_ground_truth_score(eps):
    gt = json.loads((HERE.parent / "ground-truth-local.json").read_text())
    checks, acc = score.score(gt, list(eps.values()))
    assert acc == 1.0 and len(checks) == 8


def test_score_detects_mismatch(eps):
    gt = {"endpoints": [{"host": "pqc-server", "port": 8443, "expected_posture": "enforced"},
                        {"host": "nowhere", "port": 1, "expected_posture": "none"}]}
    checks, acc = score.score(gt, list(eps.values()))
    assert acc == 0.0 and [c.field for c in checks] == ["pq_kex", "discovered"]


# ---------------- CBOM ----------------
def test_cbom_is_valid_cyclonedx_16(eps):
    bom = cbom.build(list(eps.values()), None, {"when": "x"})
    assert cbom.validate(json.dumps(bom)) is None
    refs = {c["bom-ref"] for c in bom["components"]}
    assert "crypto/algorithm/X25519MLKEM768" in refs and "crypto/algorithm/ML-DSA-65" in refs
    # every reference points at a component that exists
    for c in bom["components"]:
        cp = c["cryptoProperties"]
        for r in cp.get("protocolProperties", {}).get("cryptoRefArray", []):
            assert r in refs
        cert = cp.get("certificateProperties", {})
        for k in ("signatureAlgorithmRef", "subjectPublicKeyRef"):
            if k in cert:
                assert cert[k] in refs


def test_cbom_validator_rejects_garbage():
    assert cbom.validate(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [{"type": "nope"}]}))


# ---------------- AWS (moto) ----------------
def _self_signed_ec():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    k = ec.generate_private_key(ec.SECP256R1())
    n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "alb.lab.internal")])
    now = dt.datetime.now(dt.timezone.utc)
    c = (x509.CertificateBuilder().subject_name(n).issuer_name(n).public_key(k.public_key()).serial_number(7)
         .not_valid_before(now).not_valid_after(now + dt.timedelta(days=90))
         .add_extension(x509.SubjectAlternativeName([x509.DNSName("alb.lab.internal")]), False)
         .sign(k, hashes.SHA256()))
    return (c.public_bytes(serialization.Encoding.PEM),
            k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))


@pytest.fixture
def aws_lab(monkeypatch):
    moto = pytest.importorskip("moto")
    import boto3
    for k, v in {"AWS_ACCESS_KEY_ID": "test", "AWS_SECRET_ACCESS_KEY": "test", "AWS_DEFAULT_REGION": "us-east-1"}.items():
        monkeypatch.setenv(k, v)
    with moto.mock_aws():
        r = "us-east-1"
        ec2 = boto3.client("ec2", region_name=r)
        vpc = ec2.create_vpc(CidrBlock="10.42.0.0/16")["Vpc"]["VpcId"]
        s1 = ec2.create_subnet(VpcId=vpc, CidrBlock="10.42.0.0/24", AvailabilityZone="us-east-1a")["Subnet"]["SubnetId"]
        s2 = ec2.create_subnet(VpcId=vpc, CidrBlock="10.42.1.0/24", AvailabilityZone="us-east-1b")["Subnet"]["SubnetId"]
        sg = ec2.create_security_group(GroupName="server", Description="lab", VpcId=vpc)["GroupId"]
        ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 8443, "ToPort": 8446, "IpRanges": [{"CidrIp": "10.42.0.0/16"}]},
            {"IpProtocol": "tcp", "FromPort": 1024, "ToPort": 65535, "IpRanges": [{"CidrIp": "10.42.0.0/16"}]}])
        ami = ec2.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]
        inst = ec2.run_instances(ImageId=ami, MinCount=1, MaxCount=1, SubnetId=s1, SecurityGroupIds=[sg],
                                 TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": "pqc-tls-lab-server"}]}])
        ip = inst["Instances"][0]["PrivateIpAddress"]
        r53 = boto3.client("route53", region_name=r)
        zone = r53.create_hosted_zone(Name="lab.internal", CallerReference="x", HostedZoneConfig={"PrivateZone": True},
                                      VPC={"VPCRegion": r, "VPCId": vpc})["HostedZone"]["Id"]
        r53.change_resource_record_sets(HostedZoneId=zone, ChangeBatch={"Changes": [{"Action": "CREATE", "ResourceRecordSet": {
            "Name": "pqc-server.lab.internal", "Type": "A", "TTL": 60, "ResourceRecords": [{"Value": ip}]}}]})
        cert, key = _self_signed_ec()
        arn = boto3.client("acm", region_name=r).import_certificate(Certificate=cert, PrivateKey=key)["CertificateArn"]
        elb = boto3.client("elbv2", region_name=r)
        lb = elb.create_load_balancer(Name="pqc-tls-lab-alb", Subnets=[s1, s2], Scheme="internal", Type="application")["LoadBalancers"][0]
        tg = elb.create_target_group(Name="tg", Protocol="HTTPS", Port=8444, VpcId=vpc)["TargetGroups"][0]["TargetGroupArn"]
        for port, pol in ((443, "ELBSecurityPolicy-2016-08"), (9443, "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09")):
            elb.create_listener(LoadBalancerArn=lb["LoadBalancerArn"], Protocol="HTTPS", Port=port, SslPolicy=pol,
                                Certificates=[{"CertificateArn": arn}], DefaultActions=[{"Type": "forward", "TargetGroupArn": tg}])
        kms = boto3.client("kms", region_name=r)
        kms.create_key(KeySpec="RSA_3072", KeyUsage="SIGN_VERIFY", Description="classical signing key")
        kms.create_key(KeySpec="SYMMETRIC_DEFAULT", KeyUsage="ENCRYPT_DECRYPT")
        yield boto3.Session(region_name=r), lb["DNSName"]


def test_aws_collect(aws_lab):
    session, lb_dns = aws_lab
    data = aws_collect.collect(session, "us-east-1")
    assert data["errors"] == []
    assert data["acm_certificates"][0]["KeyAlgorithm"] == "EC_prime256v1"
    targets = {(t["host"], t["port"]) for t in data["targets"]}
    # EC2 ports come from the security group, named via the private hosted zone; the wide 1024-65535
    # rule contributes only well-known TLS ports, not 64k probes.
    assert {("pqc-server.lab.internal", p) for p in (8443, 8444, 8445, 8446)} <= targets
    assert ("pqc-server.lab.internal", 9443) in targets
    assert (lb_dns, 443) in targets and (lb_dns, 9443) in targets
    assert len(targets) < 20
    fs = findings.aws_findings(data, now=NOW)
    ids = [f.id for f in fs]
    assert ids.count("AWS-ELB-NO-PQ-POLICY") == 1        # only the 443 listener
    assert "AWS-ELB-LEGACY-TLS" in ids                   # 2016-08 allows TLS 1.0/1.1
    assert "AWS-KMS-CLASSICAL-ASYMMETRIC" in ids and "AWS-ACM-CLASSICAL" in ids
    bom = cbom.build([], data, {})
    assert cbom.validate(json.dumps(bom)) is None


def test_ml_dsa_kms_key_is_resistant():
    data = {"kms_keys": [
        {"KeyId": "1", "Arn": "a1", "Aliases": [], "KeySpec": "ML_DSA_65", "KeyUsage": "SIGN_VERIFY",
         "KeyManager": "CUSTOMER", "KeyState": "Enabled"},
        {"KeyId": "2", "Arn": "a2", "Aliases": ["alias/old"], "KeySpec": "RSA_3072", "KeyUsage": "SIGN_VERIFY",
         "KeyManager": "CUSTOMER", "KeyState": "Enabled"}]}
    f = [x for x in findings.aws_findings(data, now=NOW) if x.id == "AWS-KMS-CLASSICAL-ASYMMETRIC"]
    assert len(f) == 1 and "alias/old" in f[0].evidence and "ML_DSA" not in f[0].evidence.split("offers")[0]
    bom = cbom.build([], data, {})
    assert cbom.validate(json.dumps(bom)) is None


def test_cross_check_pq_policy_not_observed(eps):
    ep = eps["lab-classical"]  # pretend this classical endpoint sits behind a listener with a PQ policy
    data = {"elbv2": {"load_balancers": [{"LoadBalancerName": "lb", "Type": "application", "Scheme": "internal",
                                          "DNSName": "lb", "Listeners": [{"ListenerArn": "L1", "Port": 443, "Protocol": "HTTPS",
                                                                          "SslPolicy": "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09"}]}],
                      "ssl_policies": {}},
            "targets": [{"host": "lb", "port": 443, "label": ep.label, "source": {"kind": "elbv2-listener", "id": "L1"}}]}
    ids = [f.id for f in findings.aws_findings(data, {ep.label: ep}, now=NOW)]
    assert "XCHECK-PQ-POLICY-NOT-OBSERVED" in ids and "AWS-ELB-NO-PQ-POLICY" not in ids


# ---------------- CLI end to end ----------------
def test_cli_report(tmp_path):
    rc = main(["report", "--probes", str(FIX), "--ground-truth", str(HERE.parent / "ground-truth-local.json"),
               "--out", str(tmp_path)])
    assert rc == 0
    for f in ("report.md", "cbom.json", "findings.json", "findings.csv"):
        assert (tmp_path / f).stat().st_size > 0
    md = (tmp_path / "report.md").read_text()
    assert "8/8 checks (100%)" in md and "hybrid, not enforced" in md
