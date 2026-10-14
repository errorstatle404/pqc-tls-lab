"""Turn inventory data into prioritized findings.

Severity reflects post-quantum migration priority plus conventional TLS hygiene:
  high     exposed today or blocks PQ entirely (no PQ key exchange on TLS 1.3, TLS 1.0/1.1, expired cert,
           a config that claims PQ while connections are classical)
  medium   PQ present but weak in practice (hybrid not enforced, PQ-only breaking clients,
           AWS resources on non-PQ TLS policies, certificates expiring within 30 days)
  low      planned migration items (TLS 1.2 still accepted, classical asymmetric KMS keys)
  info     expected today but belongs in the migration inventory (classical certificate signatures)
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone

from . import algorithms
from .probes import Endpoint

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}

# CloudFront viewer policies older than TLSv1.2_2021 still allow weak or legacy settings.
CLOUDFRONT_WEAK = {"SSLv3", "TLSv1", "TLSv1_2016", "TLSv1.1_2016", "TLSv1.2_2018", "TLSv1.2_2019"}


@dataclass
class Finding:
    id: str
    severity: str
    title: str
    asset: str
    evidence: str
    fix: str
    source: str  # network | aws-config | cross-check
    refs: list[str] = field(default_factory=list)

    def dict(self) -> dict:
        return asdict(self)


def _fmt_date(d: datetime | None) -> str:
    return d.strftime("%Y-%m-%d") if d else "?"


def network_findings(eps: list[Endpoint], now: datetime | None = None) -> list[Finding]:
    now = now or datetime.now(timezone.utc)
    out: list[Finding] = []
    for ep in eps:
        a = f"{ep.host}:{ep.port}"
        if not ep.reachable:
            continue
        k = ep.pq_kex
        if k == "no-tls13":
            out.append(Finding(
                "PQC-KEX-NO-TLS13", "high", "No TLS 1.3, so no post-quantum key exchange is possible", a,
                "Every TLS 1.3 client profile failed; the server only negotiated older versions "
                f"({', '.join(algorithms.VERSION_LABEL[v] for v in ('tls1_2', 'tls1_1', 'tls1') if ep.versions.get(v, (False,))[0]) or 'none'}).",
                "Enable TLS 1.3, then a hybrid group such as X25519MLKEM768 (OpenSSL 3.5+, or an AWS "
                "*-PQ-* security policy on load balancers).", "network"))
        elif k == "none":
            out.append(Finding(
                "PQC-KEX-NONE", "high", "No post-quantum key exchange (harvest-now-decrypt-later exposure)", a,
                f"Hybrid-only and ML-KEM-only clients were refused; a modern client negotiated "
                f"{ep.default_group}. Recorded traffic could be decrypted by a future quantum computer.",
                "Offer X25519MLKEM768 first in the server's group list (nginx: ssl_ecdh_curve "
                "X25519MLKEM768/X25519:prime256v1 with OpenSSL 3.5+).", "network"))
        elif k == "not-enforced":
            cf = ep.hs("classical-first")
            out.append(Finding(
                "PQC-KEX-NOT-ENFORCED", "medium", "Hybrid PQ supported but not enforced (silent classical fallback)", a,
                f"A client that supports X25519MLKEM768 but sends an X25519 key share first got "
                f"{cf.group if cf else '?'} with no HelloRetryRequest. The configuration looks post-quantum; "
                "these sessions are not.",
                "Put the hybrid group in its own preference tuple so the server requests it: "
                "ssl_ecdh_curve X25519MLKEM768/X25519:prime256v1 (OpenSSL 3.5 syntax). Costs one round trip "
                "only for clients that did not send a hybrid share.", "network"))
        elif k == "pq-only":
            out.append(Finding(
                "PQC-KEX-NO-FALLBACK", "medium", "Post-quantum only: classical clients are refused", a,
                "The classical-only and default client profiles failed; only ML-KEM succeeded.",
                "Unless every client is known to support ML-KEM, offer a hybrid group with classical fallback.",
                "network"))

        if ep.legacy_versions:
            out.append(Finding(
                "TLS-LEGACY-VERSION", "high", "TLS 1.0/1.1 accepted", a,
                "Accepted: " + ", ".join(algorithms.VERSION_LABEL[v] for v in ep.legacy_versions) +
                ". Both versions are deprecated (RFC 8996).",
                "Disable TLS 1.0 and 1.1.", "network"))
        if ep.tls12 and ep.tls13:
            out.append(Finding(
                "TLS-12-ACCEPTED", "low", "TLS 1.2 still accepted (always classical key exchange)", a,
                f"TLS 1.2 handshake succeeded with {ep.versions['tls1_2'][1]}. Hybrid ML-KEM groups are "
                "defined for TLS 1.3 only, so any client that falls back to TLS 1.2 gets classical key exchange.",
                "Plan to require TLS 1.3 once client support allows.", "network"))

        leaf = ep.leaf
        if leaf:
            key = algorithms.cert_key(leaf.key_alg, leaf.key_bits)
            sig = algorithms.signature(leaf.sig_alg)
            if leaf.not_after and leaf.not_after < now:
                out.append(Finding("CERT-EXPIRED", "high", "Certificate expired", a,
                                   f"Leaf certificate expired {_fmt_date(leaf.not_after)}.", "Renew it.", "network"))
            elif leaf.not_after and leaf.not_after < now + timedelta(days=30):
                out.append(Finding("CERT-EXPIRING", "medium", "Certificate expires within 30 days", a,
                                   f"Leaf certificate expires {_fmt_date(leaf.not_after)}.",
                                   "Renew or confirm auto-renewal.", "network"))
            if key.ref.startswith("RSA-") and 0 < key.classical_bits < 112:
                out.append(Finding("CERT-WEAK-KEY", "high", "Certificate key below 2048-bit RSA", a,
                                   f"Leaf key {key.ref}.", "Reissue with at least RSA-2048 or ECDSA P-256.", "network"))
            if sig.ref.endswith("SHA1"):
                out.append(Finding("CERT-SHA1", "high", "Certificate signed with SHA-1", a,
                                   f"Leaf signature {leaf.sig_alg}.", "Reissue with SHA-256 or stronger.", "network"))
            if key.quantum == "vulnerable":
                out.append(Finding(
                    "PQC-AUTH-CLASSICAL", "info", "Certificate uses a quantum-vulnerable key", a,
                    f"Leaf key {key.ref}, signature {sig.ref}. Expected today (public CAs and browsers do not "
                    "yet support ML-DSA certificates), but it is a future migration item.",
                    "Track for migration to ML-DSA (or composite) certificates once your CA and clients support them.",
                    "network"))
    return out


def aws_findings(aws: dict, eps_by_label: dict[str, Endpoint] | None = None,
                 now: datetime | None = None) -> list[Finding]:
    now = now or datetime.now(timezone.utc)
    eps_by_label = eps_by_label or {}
    out: list[Finding] = []
    elb = aws.get("elbv2", {})
    policies = elb.get("ssl_policies", {})
    targets_by_listener = {t["source"].get("id"): t for t in aws.get("targets", []) if t.get("source")}

    for lb in elb.get("load_balancers", []):
        for li in lb["Listeners"]:
            if li["Protocol"] not in ("HTTPS", "TLS"):
                continue
            pol = li.get("SslPolicy") or "?"
            asset = f"{lb['LoadBalancerName']}:{li['Port']} ({lb['Type']}, {lb['Scheme']})"
            details = policies.get(pol) or {}
            protos = details.get("SslProtocols", [])
            legacy = [p for p in protos if p in ("TLSv1", "TLSv1.1")]
            if "-PQ-" not in pol:
                out.append(Finding(
                    "AWS-ELB-NO-PQ-POLICY", "high" if lb["Scheme"] == "internet-facing" else "medium",
                    "Load balancer listener uses a TLS policy without post-quantum key exchange", asset,
                    f"SslPolicy {pol}" + (f" (protocols: {', '.join(protos)})" if protos else "") + ". "
                    "Note: ELBSecurityPolicy-2016-08 is the default when a listener is created through the API, "
                    "CLI, CloudFormation or Terraform without naming a policy.",
                    "Switch to a hybrid policy, e.g. ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09.",
                    "aws-config", [li["ListenerArn"]]))
            if legacy:
                out.append(Finding(
                    "AWS-ELB-LEGACY-TLS", "high", "Load balancer policy allows TLS 1.0/1.1", asset,
                    f"SslPolicy {pol} allows {', '.join(legacy)}.",
                    "Use a TLS 1.2+ policy (a *-PQ-2025-09 policy also adds hybrid key exchange).",
                    "aws-config", [li["ListenerArn"]]))
            # Cross-check config against the wire.
            t = targets_by_listener.get(li["ListenerArn"])
            ep = eps_by_label.get(t["label"]) if t else None
            if ep and ep.reachable:
                g = algorithms.group(ep.default_group)
                if "-PQ-" in pol and (g is None or g.quantum not in ("hybrid", "resistant")):
                    out.append(Finding(
                        "XCHECK-PQ-POLICY-NOT-OBSERVED", "high",
                        "Listener has a PQ policy, but a PQ-capable client did not get hybrid key exchange", asset,
                        f"Policy {pol}; the probe negotiated {ep.default_group or 'nothing (handshake failed)'}.",
                        "Check the policy actually applied to the listener and any proxy in front of it.",
                        "cross-check", [li["ListenerArn"]]))

    for d in aws.get("cloudfront", []):
        mpv = d.get("MinimumProtocolVersion")
        if d.get("CloudFrontDefaultCertificate") or mpv in CLOUDFRONT_WEAK:
            out.append(Finding(
                "AWS-CF-WEAK-MIN-TLS", "medium", "CloudFront viewer TLS minimum is below TLSv1.2_2021",
                f"cloudfront {d['Id']} ({d['DomainName']})",
                f"MinimumProtocolVersion {mpv}" + (" (default *.cloudfront.net certificate)" if d.get("CloudFrontDefaultCertificate") else "") + ".",
                "Use a custom certificate with minimum protocol TLSv1.2_2021 or newer.", "aws-config"))

    for d in aws.get("apigateway_domains", []):
        if d.get("SecurityPolicy") == "TLS_1_0":
            out.append(Finding("AWS-APIGW-TLS10", "medium", "API Gateway custom domain allows TLS 1.0",
                               d["DomainName"], "SecurityPolicy TLS_1_0.", "Set SecurityPolicy to TLS_1_2.",
                               "aws-config"))

    certs = aws.get("acm_certificates", [])
    vuln = [c for c in certs if algorithms.acm_key(c.get("KeyAlgorithm")).quantum == "vulnerable"]
    for c in certs:
        key = algorithms.acm_key(c.get("KeyAlgorithm"))
        name = f"ACM {c.get('DomainName')} ({c.get('Type')})"
        if key.ref.startswith("RSA-") and key.classical_bits < 112:
            out.append(Finding("AWS-ACM-WEAK-KEY", "high", "ACM certificate key below RSA-2048", name,
                               f"KeyAlgorithm {c.get('KeyAlgorithm')}.", "Reissue.", "aws-config",
                               [c["CertificateArn"]]))
        na = c.get("NotAfter")
        if na:
            exp = datetime.fromisoformat(na)
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if exp < now:
                out.append(Finding("AWS-ACM-EXPIRED", "high", "ACM certificate expired", name,
                                   f"Expired {exp:%Y-%m-%d}; in use by {len(c.get('InUseBy') or [])} resource(s).",
                                   "Renew or remove it.", "aws-config", [c["CertificateArn"]]))
            elif exp < now + timedelta(days=30) and c.get("Type") == "IMPORTED":
                out.append(Finding("AWS-ACM-EXPIRING", "medium", "Imported ACM certificate expires within 30 days",
                                   name, f"Expires {exp:%Y-%m-%d}. ACM does not renew imported certificates.",
                                   "Import a renewed certificate.", "aws-config", [c["CertificateArn"]]))
    if vuln:
        out.append(Finding(
            "AWS-ACM-CLASSICAL", "info", f"{len(vuln)} ACM certificate(s) use quantum-vulnerable keys",
            "ACM (account-wide)",
            "; ".join(f"{c.get('DomainName')}: {c.get('KeyAlgorithm')}" for c in vuln[:10]) + ("…" if len(vuln) > 10 else ""),
            "Expected today. Keep in the migration inventory; ML-DSA certificates for TLS are not yet broadly supported.",
            "aws-config", [c["CertificateArn"] for c in vuln]))

    keys = [k for k in aws.get("kms_keys", []) if k.get("KeyManager") == "CUSTOMER"
            and k.get("KeyState") not in ("PendingDeletion", "PendingReplicaDeletion")]
    asym = [k for k in keys if algorithms.kms_key_spec(k.get("KeySpec")).quantum == "vulnerable"]
    if asym:
        out.append(Finding(
            "AWS-KMS-CLASSICAL-ASYMMETRIC", "low",
            f"{len(asym)} customer-managed asymmetric KMS key(s) are quantum-vulnerable", "KMS (account-wide)",
            "; ".join(f"{(k['Aliases'] or [k['KeyId']])[0]}: {k['KeySpec']} ({k['KeyUsage']})" for k in asym),
            "For signing, AWS KMS offers ML-DSA keys (ML_DSA_44/65/87). Identify what verifies these signatures "
            "and plan the switch. Symmetric (AES-256) keys need no change.",
            "aws-config", [k["Arn"] for k in asym]))
    return out


def sort(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.id, f.asset))
