"""Turn raw probe results and AWS configuration into classifications and findings."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

from . import algorithms
from .probe import ProbeResult, Target

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}

# Endpoint classes, from best to worst for a harvest-now-decrypt-later threat model.
CLASSES = {
    "hybrid-enforced": "Hybrid PQ key exchange, enforced for every hybrid-capable client (HelloRetryRequest)",
    "hybrid-downgradable": "Hybrid PQ key exchange for clients that lead with it; silently classical for hybrid-capable clients that don't",
    "hybrid-not-preferred": "Supports hybrid PQ, but picks classical even when the client offers hybrid first",
    "pq-only": "Pure post-quantum; classical and today's default clients cannot connect",
    "classical": "No post-quantum key exchange for any client",
    "unreachable": "Could not complete any handshake",
}


@dataclass
class Finding:
    id: str
    severity: str               # high | medium | low | info
    asset: str                  # endpoint, ARN or name
    asset_type: str             # tls-endpoint | kms-key | acm-certificate | load-balancer | cloudfront
    title: str
    detail: str
    recommendation: str
    evidence: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class EndpointAssessment:
    target: Target
    results: dict                       # profile id -> ProbeResult
    classification: str = "unreachable"
    default_group: str = ""             # what the pq-default client negotiated ("" = failed)
    default_outcome: str = ""           # group name or "handshake_failure"
    supports_tls12: bool = False
    hrr_for_hybrid: bool = False
    chain: list = field(default_factory=list)
    findings: list = field(default_factory=list)

    @property
    def endpoint(self) -> str:
        return self.target.endpoint


def assess_endpoint(target: Target, results: dict) -> EndpointAssessment:
    a = EndpointAssessment(target=target, results=results)
    get = lambda pid: results.get(pid) or ProbeResult(target.host, target.port, pid)  # noqa: E731
    default, late, classical = get("pq-default"), get("hybrid-late"), get("classical")
    hybrid_only, pq_only, tls12 = get("hybrid-only"), get("pq-only"), get("tls12")

    a.default_group = default.group if default.ok else ""
    a.default_outcome = default.group if default.ok else (default.error or "handshake_failure")
    a.supports_tls12 = tls12.ok and tls12.protocol == "TLSv1.2"
    a.hrr_for_hybrid = late.ok and late.hrr and late.pq
    for r in (default, classical, late, hybrid_only, pq_only, tls12):
        if r.ok and r.chain:
            a.chain = r.chain
            break

    any_ok = any(r.ok for r in results.values())
    supports_pq = any(r.pq for r in results.values())

    if not any_ok:
        a.classification = "unreachable"
    elif not supports_pq:
        a.classification = "classical"
    elif not default.ok and not classical.ok:
        a.classification = "pq-only"
    elif default.ok and not default.pq:
        a.classification = "hybrid-not-preferred"
    elif late.ok and not late.pq:
        a.classification = "hybrid-downgradable"
    else:
        # The hybrid-capable client that leads with X25519 either got hybrid (via
        # HelloRetryRequest) or was refused; either way it was not silently downgraded.
        a.classification = "hybrid-enforced"

    a.findings = _endpoint_findings(a, default, late, classical, pq_only)
    return a


def _endpoint_findings(a: EndpointAssessment, default, late, classical, pq_only) -> list:
    t, out = a.target, []
    ev = {"classification": a.classification,
          "negotiated": {pid: (r.group if r.ok else f"failed: {r.error}") for pid, r in a.results.items()}}

    def add(fid, sev, title, detail, rec):
        out.append(Finding(fid, sev, t.endpoint, "tls-endpoint", title, detail, rec, ev))

    c = a.classification
    if c == "unreachable":
        err = default.error or "no response"
        add("TLS-UNREACHABLE", "info", "Endpoint could not be probed",
            f"No client profile completed a handshake ({err}).",
            "Check that the probe can reach this endpoint (security groups, DNS), then rerun.")
        return out
    if c == "classical":
        add("TLS-NO-PQ", "high", "No post-quantum key exchange",
            f"Every client negotiated a classical group (default client: {algorithms.display(a.default_group)}). "
            "Traffic recorded today can be decrypted once a large quantum computer exists "
            "(harvest now, decrypt later).",
            "Enable the hybrid group X25519MLKEM768 (on AWS load balancers: a *-PQ-* security policy; "
            "on OpenSSL 3.5 servers: add X25519MLKEM768 to the group list), keeping X25519 as fallback.")
    elif c == "hybrid-not-preferred":
        add("TLS-PQ-NOT-PREFERRED", "high", "Hybrid supported but not preferred",
            f"A client offering X25519MLKEM768 first still got {algorithms.display(a.default_group)}. "
            "Clients only get PQ protection if they offer nothing else.",
            "Put X25519MLKEM768 first in the server's group preference.")
    elif c == "hybrid-downgradable":
        add("TLS-PQ-DOWNGRADE", "medium", "Silent downgrade to classical key exchange",
            f"A client that supports X25519MLKEM768 but sends an X25519 key share first got "
            f"{algorithms.display(late.group) if late.ok else 'no connection'}, with no HelloRetryRequest. "
            "Browsers that send a hybrid share first are protected; other hybrid-capable clients silently are not.",
            "Make the server insist on hybrid when the client supports it. On OpenSSL 3.5 use a separate "
            "preference tuple: X25519MLKEM768/X25519:prime256v1 (costs one extra round trip for those clients).")
    elif c == "pq-only":
        add("TLS-PQ-ONLY-INTEROP", "medium", "Pure post-quantum endpoint rejects today's clients",
            "Classical clients and current default clients (hybrid) cannot connect; only pure ML-KEM clients can.",
            "Use a hybrid group (X25519MLKEM768) with classical fallback unless every client is known to support pure ML-KEM.")
    if a.supports_tls12:
        add("TLS-TLS12-ACCEPTED", "low", "TLS 1.2 still accepted",
            "Post-quantum key exchange exists only in TLS 1.3, so every TLS 1.2 connection is classical.",
            "Plan to require TLS 1.3 once clients allow it.")
    if a.chain:
        leaf = a.chain[0]
        leaf_q = algorithms.quantum_status(leaf.key)
        if leaf_q == "vulnerable":
            add("CERT-CLASSICAL", "info", "Certificate uses a quantum-vulnerable key",
                f"Leaf key {algorithms.display(leaf.key) or leaf.key}, signed with {leaf.sigalg}. Authentication is only at risk once a quantum computer "
                "exists (there is no harvest-now risk), so this is a planning item, not urgent.",
                "Track ML-DSA certificate support in your CA and clients; plan the switch.")
        elif leaf_q == "pq":
            add("CERT-PQ", "info", "Post-quantum certificate",
                f"Leaf key {algorithms.display(leaf.key) or leaf.key}. Browsers and public CAs do not support ML-DSA certificates yet.",
                "Keep a classical certificate for general clients.")
    return out


# ------------------------------- AWS configuration findings -------------------------------


def kms_key_findings(key: dict) -> list:
    spec, usage, arn = key.get("KeySpec", ""), key.get("KeyUsage", ""), key.get("Arn", key.get("KeyId", ""))
    alias = ", ".join(key.get("Aliases", [])) or arn
    ev = {"KeySpec": spec, "KeyUsage": usage, "KeyManager": key.get("KeyManager"), "KeyState": key.get("KeyState")}
    q = algorithms.quantum_status(spec)
    if q == "pq":
        return [Finding("KMS-PQ-KEY", "info", alias, "kms-key", f"Post-quantum KMS key ({spec})",
                        "ML-DSA signing key: quantum-safe signatures.", "None.", ev)]
    if q != "vulnerable":
        return []
    if usage in ("ENCRYPT_DECRYPT", "KEY_AGREEMENT"):
        return [Finding("KMS-CLASSICAL-ENCRYPTION", "medium", alias, "kms-key",
                        f"Quantum-vulnerable {usage.lower().replace('_', '/')} key ({spec})",
                        "Data encrypted or keys agreed with this key today can be recovered later by a "
                        "quantum attacker who records the ciphertext (harvest now, decrypt later).",
                        "Prefer symmetric KMS keys (AES-256) for encryption; replace RSA/ECC encryption and "
                        "key-agreement keys where the data must stay secret for years.", ev)]
    return [Finding("KMS-CLASSICAL-SIGNING", "low", alias, "kms-key",
                    f"Quantum-vulnerable signing key ({spec})",
                    "Signatures made with this key could be forged by a future quantum computer. "
                    "Matters most for long-lived signatures (firmware, documents, root keys).",
                    "For new long-lived signing use cases, create an ML_DSA_65 key.", ev)]


def acm_certificate_findings(cert: dict) -> list:
    algo, domain = cert.get("KeyAlgorithm", ""), cert.get("DomainName", cert.get("CertificateArn", ""))
    ev = {k: cert.get(k) for k in ("KeyAlgorithm", "Type", "NotAfter", "InUseBy") if cert.get(k) is not None}
    if algorithms.quantum_status(algo) == "vulnerable":
        return [Finding("ACM-CLASSICAL-CERT", "info", domain, "acm-certificate",
                        f"Certificate key is quantum-vulnerable ({algo})",
                        "Expected today: no public CA issues ML-DSA certificates yet. Listed so it is in the "
                        "inventory when that changes.",
                        "No action now; track ACM support for ML-DSA certificates.", ev)]
    return []


def elb_listener_findings(lb_name: str, listener: dict, policy: dict | None) -> list:
    out = []
    name = policy_name = listener.get("SslPolicy", "")
    asset = f"{lb_name}:{listener.get('Port')}"
    protocols = (policy or {}).get("SslProtocols", [])
    ev = {"SslPolicy": policy_name, "SslProtocols": protocols}
    if not _elb_policy_is_pq(name):
        out.append(Finding("ELB-POLICY-NO-PQ", "high", asset, "load-balancer",
                           f"Listener policy {name} has no post-quantum key exchange",
                           "Only the *-PQ-* security policies enable hybrid ML-KEM key exchange on AWS load balancers.",
                           "Switch to ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09 (or the TLS13-1-3 PQ policy "
                           "if every client supports TLS 1.3).", ev))
    old = [p for p in protocols if p in ("TLSv1", "TLSv1.1", "SSLv3")]
    if old:
        out.append(Finding("ELB-OLD-TLS", "medium", asset, "load-balancer",
                           f"Listener allows {', '.join(old)}",
                           "TLS 1.0 and 1.1 are deprecated (RFC 8996) and have no post-quantum option.",
                           "Use a TLS13-1-2 or TLS13-1-3 security policy.", ev))
    return out


def _elb_policy_is_pq(name: str) -> bool:
    return "-PQ-" in name.upper() + "-"


def cloudfront_findings(dist: dict) -> list:
    # CloudFront enables hybrid PQ for viewer connections on every security policy (Sept 2025).
    min_proto = dist.get("MinimumProtocolVersion", "")
    asset = dist.get("DomainName", dist.get("Id", ""))
    if min_proto in ("SSLv3", "TLSv1", "TLSv1_2016", "TLSv1.1_2016"):
        return [Finding("CF-OLD-TLS", "medium", asset, "cloudfront",
                        f"Distribution allows old TLS versions ({min_proto})",
                        "TLS 1.0/1.1 connections cannot use post-quantum key exchange.",
                        "Use TLSv1.2_2021 or TLS1.3_2025.", {"MinimumProtocolVersion": min_proto})]
    return []


def sort_findings(findings: list) -> list:
    return sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.asset, f.id))
