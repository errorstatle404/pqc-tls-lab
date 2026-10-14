"""Markdown report and CSV findings."""
from __future__ import annotations

import csv
from collections import Counter

from . import __version__, algorithms
from .findings import Finding
from .probes import Endpoint
from .score import Check

POSTURE_TEXT = {
    "enforced": "✅ hybrid, enforced",
    "not-enforced": "⚠️ hybrid, not enforced",
    "pq-only": "⚠️ PQ only (no fallback)",
    "none": "❌ none",
    "no-tls13": "❌ no TLS 1.3",
    "unreachable": "– unreachable",
}


def _esc(s) -> str:
    return str(s).replace("|", "\\|").replace("\n", " ")


def write_csv(findings: list[Finding], path) -> None:
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["severity", "id", "title", "asset", "evidence", "fix", "source"])
        for x in findings:
            w.writerow([x.severity, x.id, x.title, x.asset, x.evidence, x.fix, x.source])


def render(eps: list[Endpoint], findings: list[Finding], aws: dict | None, meta: dict,
           checks: list[Check] | None, accuracy: float | None, cbom_components: int,
           cbom_valid: str | None) -> str:
    L: list[str] = []
    add = L.append
    reach = [e for e in eps if e.reachable]
    tls = [e for e in reach if e.tls13 or e.tls12 or e.legacy_versions]
    hybrid_default = [e for e in tls if (algorithms.group(e.default_group) or algorithms.Algo("", "", "", 0)).quantum in ("hybrid", "resistant")]
    enforced = [e for e in tls if e.pq_kex == "enforced"]
    no_pq = [e for e in tls if e.pq_kex in ("none", "no-tls13")]
    sev = Counter(f.severity for f in findings)

    add("# Cryptographic inventory report")
    add("")
    scope = [f"**Probed:** {meta.get('when', '?')} from `{meta.get('scanner', '?')}` using {meta.get('openssl', 'OpenSSL ?')}"]
    if aws:
        ident = aws.get("identity", {})
        scope.append(f"**AWS:** account `{ident.get('account', '?')}`, region `{aws.get('region')}`, collected {aws.get('collected_at')}")
    scope.append(f"**Tool:** cryptoinv {__version__}")
    add("  \n".join(scope))
    add("")
    add("## Summary")
    add("")
    add(f"- **{len(tls)}** TLS endpoints answered ({len(eps) - len(reach)} unreachable).")
    add(f"- **{len(hybrid_default)} of {len(tls)}** negotiated post-quantum (hybrid) key exchange with a modern client; "
        f"**{len(enforced)}** {'enforces' if len(enforced) == 1 else 'enforce'} it for clients that lead with a classical key.")
    add(f"- **{len(no_pq)}** {'offers' if len(no_pq) == 1 else 'offer'} no post-quantum key exchange at all.")
    if aws:
        lst = [li for lb in aws.get("elbv2", {}).get("load_balancers", []) for li in lb["Listeners"]
               if li["Protocol"] in ("HTTPS", "TLS")]
        pq = [li for li in lst if "-PQ-" in (li.get("SslPolicy") or "")]
        add(f"- AWS: {len(pq)} of {len(lst)} load-balancer TLS listeners use a post-quantum policy; "
            f"{len(aws.get('acm_certificates', []))} ACM certificates; "
            f"{len([k for k in aws.get('kms_keys', []) if k.get('KeyManager') == 'CUSTOMER'])} customer-managed KMS keys.")
    add(f"- Findings: **{sev.get('high', 0)} high**, {sev.get('medium', 0)} medium, {sev.get('low', 0)} low, {sev.get('info', 0)} info.")
    if accuracy is not None:
        add(f"- Accuracy against the lab's known answers: **{sum(c.ok for c in checks)}/{len(checks)} checks ({accuracy:.0%})**.")
    add("")

    add("## TLS endpoints")
    add("")
    add("| Endpoint | Modern client got | PQ key exchange | TLS 1.2 | TLS 1.0/1.1 | Certificate key / signature | Chain | Expires |")
    add("|---|---|---|---|---|---|---:|---|")
    for e in sorted(eps, key=lambda e: (e.host, e.port)):
        leaf = e.leaf
        cert = "–"
        if leaf:
            cert = f"{algorithms.cert_key(leaf.key_alg, leaf.key_bits).ref} / {algorithms.signature(leaf.sig_alg).ref}"
        add(f"| `{_esc(e.host)}:{e.port}` | {_esc(e.default_group or ('handshake failed' if e.reachable else '–'))} | "
            f"{POSTURE_TEXT.get(e.pq_kex, e.pq_kex)} | {'yes' if e.tls12 else 'no'} | "
            f"{', '.join(algorithms.VERSION_LABEL[v] for v in e.legacy_versions) or 'no'} | {_esc(cert)} | "
            f"{e.chain_bytes:,} B | {leaf.not_after.strftime('%Y-%m-%d') if leaf and leaf.not_after else '–'} |")
    add("")
    add("How to read *PQ key exchange*: **enforced** means the server asks a hybrid-capable client for a hybrid key "
        "(HelloRetryRequest) even if it led with a classical one; **not enforced** means that client silently gets "
        "classical key exchange.")
    add("")

    add("## Findings")
    add("")
    if not findings:
        add("No findings.")
    for s in ("high", "medium", "low", "info"):
        group = [f for f in findings if f.severity == s]
        if not group:
            continue
        add(f"### {s.capitalize()} ({len(group)})")
        add("")
        for f in group:
            add(f"**{_esc(f.title)}** · `{f.id}` · {_esc(f.asset)} · _{f.source}_  ")
            add(f"{_esc(f.evidence)}  ")
            add(f"**Fix:** {_esc(f.fix)}")
            add("")

    if aws:
        add("## AWS configuration")
        add("")
        lbs = aws.get("elbv2", {}).get("load_balancers", [])
        if lbs:
            add("**Load balancer listeners**")
            add("")
            add("| Load balancer | Scheme | Port | Protocol | SSL policy | PQ policy | Protocols |")
            add("|---|---|---:|---|---|---|---|")
            pols = aws.get("elbv2", {}).get("ssl_policies", {})
            for lb in lbs:
                for li in lb["Listeners"]:
                    p = li.get("SslPolicy") or "–"
                    protos = ", ".join((pols.get(p) or {}).get("SslProtocols", [])) or "–"
                    add(f"| {lb['LoadBalancerName']} ({lb['Type']}) | {lb['Scheme']} | {li['Port']} | {li['Protocol']} | "
                        f"`{p}` | {'yes' if '-PQ-' in p else ('no' if li['Protocol'] in ('HTTPS', 'TLS') else '–')} | {protos} |")
            add("")
        certs = aws.get("acm_certificates", [])
        if certs:
            add("**ACM certificates**")
            add("")
            add("| Domain | Type | Key | Signature | Expires | In use by |")
            add("|---|---|---|---|---|---:|")
            for c in certs:
                add(f"| {_esc(c.get('DomainName'))} | {c.get('Type')} | {c.get('KeyAlgorithm')} | {c.get('SignatureAlgorithm')} | "
                    f"{str(c.get('NotAfter') or '–')[:10]} | {len(c.get('InUseBy') or [])} |")
            add("")
        keys = [k for k in aws.get("kms_keys", []) if k.get("KeyManager") == "CUSTOMER"]
        if keys:
            add("**Customer-managed KMS keys**")
            add("")
            add("| Key | Spec | Usage | State | Quantum status |")
            add("|---|---|---|---|---|")
            for k in keys:
                add(f"| {_esc((k.get('Aliases') or [k['KeyId']])[0])} | {k.get('KeySpec')} | {k.get('KeyUsage')} | "
                    f"{k.get('KeyState')} | {algorithms.kms_key_spec(k.get('KeySpec')).quantum} |")
            add("")
        for title, key, cols in (("CloudFront distributions", "cloudfront", ("Id", "DomainName", "MinimumProtocolVersion")),
                                 ("API Gateway custom domains", "apigateway_domains", ("DomainName", "SecurityPolicy", "EndpointType"))):
            rows = aws.get(key, [])
            if rows:
                add(f"**{title}**")
                add("")
                add("| " + " | ".join(cols) + " |")
                add("|" + "---|" * len(cols))
                for r in rows:
                    add("| " + " | ".join(_esc(r.get(c)) for c in cols) + " |")
                add("")
        if aws.get("errors"):
            add("**Collector errors** (these parts of the account were not inventoried)")
            add("")
            for e in aws["errors"]:
                add(f"- {e['collector']}: {e['error']}")
            add("")

    if checks is not None:
        add("## Accuracy against known answers")
        add("")
        add("| Endpoint | Name | Check | Expected | Observed | |")
        add("|---|---|---|---|---|---|")
        for c in checks:
            add(f"| `{c.endpoint}` | {_esc(c.name)} | {c.field} | {_esc(c.expected)} | {_esc(c.observed)} | {'✅' if c.ok else '❌'} |")
        add("")

    add("## Method")
    add("")
    add("- **Network:** each endpoint is contacted by five client profiles built on OpenSSL 3.5: default "
        "(hybrid + classical key shares), classical-only, hybrid-only, classical-first (supports hybrid but sends an "
        "X25519 share first) and ML-KEM-only. TLS 1.2, 1.1 and 1.0 are tested separately, and the certificate chain is "
        "parsed for key type, signature algorithm and expiry.")
    if aws:
        add("- **AWS:** read-only API calls list ACM certificates (all key types), load balancers and their TLS policies, "
            "CloudFront distributions, API Gateway custom domains, KMS keys, and running EC2 instances with the TCP "
            "ports their security groups open. Those endpoints become the network targets.")
    add(f"- **CBOM:** `cbom.json` is a CycloneDX 1.6 Cryptography Bill of Materials with {cbom_components} "
        f"components ({'validated against the official 1.6 schema' if cbom_valid is None else 'schema validation: ' + cbom_valid}).")
    add("")
    add("**Limitations:** the network half sees only what the scanner can reach. Certificate chains are recorded "
        "but not validated against a trust store. AWS coverage is the services listed above in one region (plus "
        "CloudFront, which is global). Application-level cryptography (libraries, data at rest outside KMS) is out of scope.")
    add("")
    return "\n".join(L)
