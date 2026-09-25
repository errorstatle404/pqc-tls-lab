import subprocess

import pytest

from conftest import load
from pqcinv import probe


def results_by(name):
    _, results = probe.parse_output(load(name))
    return {(r.host, r.port, r.profile): r for r in results}


def test_parses_every_probe_and_the_client_version():
    version, results = probe.parse_output(load("lab-local.txt"))
    assert version.startswith("OpenSSL 3.5")
    assert probe.openssl_supports_pq(version)
    assert len(results) == 4 * len(probe.PROFILES)


def test_negotiated_groups_hrr_and_failures():
    r = results_by("lab-local.txt")
    assert r[("pqc-server", 8443, "pq-default")].group == "X25519MLKEM768"
    # The silent downgrade: hybrid-capable client leading with X25519 gets X25519, no retry.
    late = r[("pqc-server", 8443, "hybrid-late")]
    assert late.ok and late.group == "X25519" and not late.hrr
    # The strict endpoint asks for the hybrid share with a HelloRetryRequest.
    strict = r[("pqc-server", 8446, "hybrid-late")]
    assert strict.ok and strict.group == "X25519MLKEM768" and strict.hrr
    fail = r[("pqc-server", 8445, "pq-default")]
    assert not fail.ok and fail.error == "handshake_failure"


def test_certificate_chain_details():
    r = results_by("lab-local.txt")[("pqc-server", 8445, "pq-only")]
    assert r.group == "MLKEM1024" and r.peer_sig == "mldsa65"
    assert [c.depth for c in r.chain] == [0, 1]
    assert r.chain[0].key.startswith("ML-DSA-65") and r.chain[0].sigalg == "ML-DSA-65"
    assert r.chain[0].not_after.endswith("GMT")
    assert r.bytes_read > 10000  # the ML-DSA chain is big


def test_tls12_and_dns_failure():
    r = results_by("scan-tls12-dns.txt")
    t12 = r[("pqc-server", 9443, "tls12")]
    assert t12.ok and t12.protocol == "TLSv1.2" and t12.group == "X25519"
    assert r[("nosuch.invalid", 443, "pq-default")].error == "dns_failure"


def test_timeout_is_reported():
    _, [r] = probe.parse_output("### PROBE 1 10.0.0.9 443 pq-default\nConnecting to 10.0.0.9\n### END 1\n")
    assert not r.ok and r.error == "timeout_or_no_response"


def test_targets_are_validated_before_they_reach_a_shell():
    assert probe.parse_target("kms.us-east-1.amazonaws.com KMS") == probe.Target(
        "kms.us-east-1.amazonaws.com", 443, "manual", "KMS")
    assert probe.parse_target("10.42.0.10:8446").port == 8446
    for bad in ("host;rm -rf /:443", "$(id):443", "a|b:443", "host:99999", "`id`"):
        with pytest.raises(ValueError):
            probe.parse_target(bad)
    with pytest.raises(ValueError):
        probe.build_script([probe.Target("x';id;'", 443)])


def test_generated_script_is_valid_posix_shell():
    script = probe.build_script([probe.Target("pqc-server", 8443), probe.Target("10.0.0.1", 443)])
    assert "-servername 10.0.0.1" not in script          # no SNI for IP addresses
    assert script.count("### PROBE") == 2 * len(probe.PROFILES)
    subprocess.run(["sh", "-n"], input=script, text=True, check=True)
