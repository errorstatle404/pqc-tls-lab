from conftest import assess_fixture
from pqcinv import classify, probe


def ids(assessment):
    return {f.id for f in assessment.findings}


def test_lab_endpoints_are_classified(lab):
    assert lab["pqc-server:8443"].classification == "hybrid-downgradable"
    assert lab["pqc-server:8444"].classification == "classical"
    assert lab["pqc-server:8445"].classification == "pq-only"
    assert lab["pqc-server:8446"].classification == "hybrid-enforced"
    assert lab["pqc-server:8446"].hrr_for_hybrid


def test_findings_match_the_risk(lab):
    assert "TLS-NO-PQ" in ids(lab["pqc-server:8444"])
    assert "TLS-PQ-DOWNGRADE" in ids(lab["pqc-server:8443"])
    assert "TLS-PQ-ONLY-INTEROP" in ids(lab["pqc-server:8445"])
    strict = lab["pqc-server:8446"]
    assert not [f for f in strict.findings if f.severity in ("high", "medium", "low")]
    assert "CERT-PQ" in ids(lab["pqc-server:8445"])


def test_tls12_and_unreachable():
    scan = assess_fixture("scan-tls12-dns.txt")
    assert "TLS-TLS12-ACCEPTED" in ids(scan["pqc-server:9443"])
    dead = scan["nosuch.invalid:443"]
    assert dead.classification == "unreachable" and dead.default_outcome == "dns_failure"


def _r(profile, ok, group="", hrr=False):
    return probe.ProbeResult("h", 443, profile, ok=ok, protocol="TLSv1.3" if ok else "", group=group, hrr=hrr,
                             error="" if ok else "handshake_failure")


def test_hybrid_supported_but_not_preferred():
    # Server lists X25519 before X25519MLKEM768: a browser offering both gets classical.
    res = {"pq-default": _r("pq-default", True, "X25519"), "hybrid-late": _r("hybrid-late", True, "X25519"),
           "classical": _r("classical", True, "X25519"), "hybrid-only": _r("hybrid-only", True, "X25519MLKEM768"),
           "pq-only": _r("pq-only", False), "tls12": _r("tls12", False)}
    a = classify.assess_endpoint(probe.Target("h", 443), res)
    assert a.classification == "hybrid-not-preferred" and "TLS-PQ-NOT-PREFERRED" in ids(a)


def test_kms_key_findings():
    f = lambda spec, usage: classify.kms_key_findings({"KeySpec": spec, "KeyUsage": usage, "Arn": "arn"})  # noqa: E731
    assert [x.id for x in f("ML_DSA_65", "SIGN_VERIFY")] == ["KMS-PQ-KEY"]
    assert [x.severity for x in f("ECC_NIST_P256", "SIGN_VERIFY")] == ["low"]
    assert [x.severity for x in f("RSA_2048", "ENCRYPT_DECRYPT")] == ["medium"]
    assert f("SYMMETRIC_DEFAULT", "ENCRYPT_DECRYPT") == []


def test_load_balancer_policy_findings():
    legacy = classify.elb_listener_findings(
        "lab-alb", {"Port": 443, "SslPolicy": "ELBSecurityPolicy-2016-08"},
        {"SslProtocols": ["TLSv1", "TLSv1.1", "TLSv1.2"]})
    assert {f.id for f in legacy} == {"ELB-POLICY-NO-PQ", "ELB-OLD-TLS"}
    pq = classify.elb_listener_findings(
        "lab-alb", {"Port": 8443, "SslPolicy": "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09"},
        {"SslProtocols": ["TLSv1.3", "TLSv1.2"]})
    assert pq == []
