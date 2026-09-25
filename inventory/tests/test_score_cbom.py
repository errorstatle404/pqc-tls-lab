import json
import os

from pqcinv import cbom, score

TRUTH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ground_truth", "local.json")

AWS_INV = {
    "region": "us-east-1", "account": "123456789012", "errors": [], "load_balancers": [], "cloudfront": [],
    "instances": [],
    "kms_keys": [
        {"KeyId": "k1", "Arn": "arn:aws:kms:us-east-1:123456789012:key/k1", "KeySpec": "ML_DSA_65",
         "KeyUsage": "SIGN_VERIFY", "KeyManager": "CUSTOMER", "KeyState": "Enabled",
         "CreationDate": "2026-09-25T10:00:00+00:00", "Aliases": ["alias/pqc-tls-lab-sign-mldsa"]},
        {"KeyId": "k2", "Arn": "arn:aws:kms:us-east-1:123456789012:key/k2", "KeySpec": "ECC_NIST_P256",
         "KeyUsage": "SIGN_VERIFY", "KeyManager": "CUSTOMER", "KeyState": "PendingDeletion",
         "CreationDate": "2026-09-25T10:00:00+00:00", "Aliases": ["alias/pqc-tls-lab-sign-ecdsa"]},
    ],
    "acm_certificates": [
        {"CertificateArn": "arn:aws:acm:us-east-1:123456789012:certificate/c1", "DomainName": "alb.lab.internal",
         "KeyAlgorithm": "EC-prime256v1", "SignatureAlgorithm": "SHA256WITHECDSA", "Type": "IMPORTED",
         "NotBefore": "2026-09-25T10:00:00+00:00", "NotAfter": "2026-12-24T10:00:00+00:00", "InUseBy": ["arn:lb"]},
    ],
}


def test_local_lab_scores_8_of_8(lab):
    with open(TRUTH) as f:
        truth = json.load(f)
    s = score.score(list(lab.values()), truth)
    assert (s["passed"], s["total"]) == (8, 8)


def test_score_wildcards_kms_and_missing_endpoints(lab):
    truth = {"host": "pqc-server",
             "endpoints": {"8443": {"inventory_class": "hybrid"}, "9999": {"inventory_class": "classical"}},
             "kms_keys": {"alias/pqc-tls-lab-sign-mldsa": {"key_spec": "ML_DSA_65", "quantum_safe": True},
                          "alias/pqc-tls-lab-sign-ecdsa": {"key_spec": "ECC_NIST_P256", "quantum_safe": False}}}
    s = score.score(list(lab.values()), truth, AWS_INV)
    by = {c["asset"]: c["pass"] for c in s["checks"]}
    assert by["pqc-server:8443"] is True          # "hybrid" accepts hybrid-downgradable
    assert by["pqc-server:9999"] is False         # not probed = fail, never a silent pass
    assert by["alias/pqc-tls-lab-sign-mldsa"] and by["alias/pqc-tls-lab-sign-ecdsa"]


def test_classical_wildcard_for_default_client(lab):
    truth = {"host": "pqc-server", "endpoints": {"8444": {"expected_default_client": "classical"},
                                                 "8443": {"expected_default_client": "classical"}}}
    by = {c["asset"]: c["pass"] for c in score.score(list(lab.values()), truth)["checks"]}
    assert by == {"pqc-server:8443": False, "pqc-server:8444": True}


def test_cbom_is_valid_cyclonedx_1_6(lab):
    bom = cbom.build_cbom(list(lab.values()), AWS_INV, "test")
    assert cbom.validate(bom) == []
    refs = {c["bom-ref"] for c in bom["components"]}
    for d in bom["dependencies"]:
        assert d["ref"] in refs and set(d["dependsOn"]) <= refs
    names = {c["name"] for c in bom["components"]}
    assert {"X25519MLKEM768", "ML-KEM-1024", "ML-DSA-65", "ECDSA P-256", "X25519"} <= names


def test_cbom_records_quantum_status_and_kms_keys(lab):
    bom = cbom.build_cbom(list(lab.values()), AWS_INV, "test")
    comps = {c["bom-ref"]: c for c in bom["components"]}
    mlkem = comps["crypto/algorithm/x25519mlkem768"]
    assert mlkem["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"] == 3
    assert {"name": "pqcinv:quantum-status", "value": "pq"} in mlkem["properties"]
    proto = comps["crypto/protocol/tls/pqc-server:8443"]
    assert {"name": "pqcinv:classification", "value": "hybrid-downgradable"} in proto["properties"]
    key = comps["crypto/key/kms/k2"]["cryptoProperties"]["relatedCryptoMaterialProperties"]
    assert key["type"] == "private-key" and key["state"] == "deactivated"
