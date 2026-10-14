# Cryptographic inventory for AWS and TLS endpoints

`cryptoinv` finds the cryptography in an AWS account and on its TLS endpoints, and reports how ready it is for post-quantum cryptography. It answers two questions separately, then compares the answers:

1. **What does the configuration say?** Read-only AWS API calls list ACM certificates, load-balancer TLS policies, CloudFront and API Gateway settings, KMS keys, and the TLS ports that running instances expose.
2. **What actually happens on the wire?** Each endpoint is contacted by five client profiles built on OpenSSL 3.5. The results show what gets negotiated, including whether "hybrid post-quantum" is enforced or silently skipped.

The output is a findings report, a **CycloneDX 1.6 CBOM** (Cryptography Bill of Materials, validated against the official schema), and CSV/JSON findings for a spreadsheet or ticketing system. Against the lab, the tool is scored on known answers, so its accuracy is measured rather than assumed.

This responds to what US federal guidance asks organizations to produce: an inventory of quantum-vulnerable cryptography that prioritizes long-lived data and key exchange first (OMB M-23-02, NIST IR 8547, CISA's *Strategy for Migrating to Automated PQC Discovery and Inventory Tools*).

## Quick start

```bash
make inventory-setup     # once: Python venv (boto3, CycloneDX library, pytest, moto)
make inventory-test      # offline tests; no Docker or AWS needed
make inventory-local     # inventory the local Docker lab and score it against known answers
make inventory-public    # what do public AWS endpoints (KMS, S3, STS...) negotiate today?
make aws-inventory       # full run against the AWS lab (after `make aws-up`)
```

Reports land in `results/inventory-report/<local|public>/` and `results/aws-inventory/<timestamp>/`:

| File | What it is |
|---|---|
| `report.md` | Summary, endpoint posture table, findings with fixes, AWS asset tables, accuracy check |
| `cbom.json` | CycloneDX 1.6 CBOM: algorithms, certificates, keys and TLS protocol instances, with references between them |
| `findings.csv` / `findings.json` | One row per finding: severity, ID, asset, evidence, fix |
| `aws.json`, `targets.txt` | Raw AWS collection and the endpoints derived from it (AWS runs only) |

## The five client profiles

| Profile | Groups offered (OpenSSL 3.5 syntax) | Question it answers |
|---|---|---|
| default | OpenSSL 3.5 defaults: X25519MLKEM768 + X25519 key shares | What does a modern, browser-like client get? |
| classical-only | `X25519:P-256:P-384` | Can clients without PQ support still connect? |
| hybrid-only | `X25519MLKEM768:SecP256r1MLKEM768:SecP384r1MLKEM1024` | Does the server support hybrid PQ key exchange at all? |
| classical-first | `X25519:X25519MLKEM768:…` (sends only an X25519 key share) | **Is hybrid enforced?** An enforcing server answers with a HelloRetryRequest for the hybrid group; a non-enforcing one silently accepts X25519. |
| pq-only | `MLKEM768:MLKEM1024` | Does it accept pure ML-KEM? |

Each endpoint is also tested for TLS 1.2, 1.1 and 1.0. Its certificate chain is parsed for key type, signature algorithm and expiry.

The profiles combine into one posture per endpoint:

| Posture | Meaning |
|---|---|
| `enforced` | Hybrid whenever the client supports it |
| `not-enforced` | Hybrid supported, but a client that leads with a classical key share gets classical key exchange |
| `pq-only` | Only post-quantum groups; classical clients are refused |
| `none` | No post-quantum key exchange |
| `no-tls13` | No TLS 1.3, so no PQ key exchange is possible |

## Findings

| Severity | ID | Trigger |
|---|---|---|
| high | `PQC-KEX-NONE` | TLS 1.3 without any PQ key exchange (harvest-now-decrypt-later exposure) |
| high | `PQC-KEX-NO-TLS13` | No TLS 1.3 at all |
| high | `TLS-LEGACY-VERSION` | TLS 1.0 or 1.1 accepted |
| high | `XCHECK-PQ-POLICY-NOT-OBSERVED` | A load-balancer listener has a `-PQ-` policy, but a PQ-capable client did not get hybrid key exchange |
| high | `AWS-ELB-LEGACY-TLS`, `CERT-EXPIRED`, `CERT-WEAK-KEY`, `CERT-SHA1`, `AWS-ACM-EXPIRED`, `AWS-ACM-WEAK-KEY` | Conventional TLS hygiene |
| high / medium | `AWS-ELB-NO-PQ-POLICY` | Listener TLS policy without hybrid key exchange (high if internet-facing) |
| medium | `PQC-KEX-NOT-ENFORCED` | Hybrid supported but not enforced: the silent downgrade |
| medium | `PQC-KEX-NO-FALLBACK` | PQ-only endpoint refuses classical clients |
| medium | `AWS-CF-WEAK-MIN-TLS`, `AWS-APIGW-TLS10`, `CERT-EXPIRING`, `AWS-ACM-EXPIRING` | Weak minimums, expiring certificates |
| low | `TLS-12-ACCEPTED` | TLS 1.2 still accepted: any client that falls back gets classical key exchange |
| low | `AWS-KMS-CLASSICAL-ASYMMETRIC` | Customer-managed RSA/ECC KMS keys (KMS now offers ML-DSA for signing) |
| info | `PQC-AUTH-CLASSICAL`, `AWS-ACM-CLASSICAL` | Classical certificate keys: expected today, but migration items |

Severity reflects migration priority. Key exchange comes first because recorded traffic can be decrypted later. Authentication comes later because a forged signature only matters once a quantum computer exists.

## How the AWS run works

```
your laptop (AWS credentials, read-only)          scanner EC2 inside the VPC
─────────────────────────────────────────          ─────────────────────────────────
cryptoinv aws  ──► aws.json + targets.txt ──SSM──► probe.sh (OpenSSL 3.5 + hsbench)
                                                          │ results
cryptoinv report ◄── S3 ◄─────────────────────────────────┘
  + terraform output inventory_ground_truth  ──► accuracy score
```

The endpoints to probe are derived from the AWS data, not typed in: security-group ingress rules on running instances (named through the private Route 53 zone), load-balancer HTTPS/TLS listeners, CloudFront distributions and API Gateway custom domains.

With `create_load_balancer = true` (the default), the AWS lab includes an internal ALB with two listeners. One uses `ELBSecurityPolicy-2016-08`, the policy AWS applies when an API, CLI or Terraform listener names none. The other uses `ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09`. With `create_kms_keys = true`, it also includes an RSA-3072 and an ML-DSA-65 KMS signing key. The inventory should flag the first of each and pass the second.

## Permissions

The AWS collector needs only read access. The AWS managed policy **SecurityAudit** covers everything it calls: `sts:GetCallerIdentity`, `acm:List*/Describe*`, `elasticloadbalancing:Describe*`, `cloudfront:ListDistributions`, `apigateway:GET`, `kms:ListKeys/DescribeKey/ListAliases`, `ec2:DescribeInstances/DescribeSecurityGroups` and `route53:ListHostedZones/ListResourceRecordSets`. A collector that is denied is listed in the report under *Collector errors*. The rest of the inventory still runs.

## Limitations

- The network half sees only what the scanner can reach. For AWS, that's the lab VPC. Point `probe.sh` at any target list to cover more.
- Certificate chains are recorded, not validated against a trust store.
- AWS coverage: the services above, in one region (CloudFront is global). Classic Load Balancers, IoT, and application-level cryptography (libraries, data at rest outside KMS) are out of scope.
- Hybrid enforcement on AWS-managed endpoints is observed from one vantage point with one TLS library (OpenSSL 3.5). Other clients may be treated differently.

## Tests

`make inventory-test` runs 17 offline tests.
- **Network half:** real `probe.sh` output, captured against the lab's nginx configuration (OpenSSL 3.5.4, nginx 1.28.0), plus a TLS 1.0–1.2 RSA endpoint and a closed port.
- **AWS half:** simulated with [moto](https://github.com/getmoto/moto): a VPC, security groups, a private DNS zone, an imported ACM certificate, an ALB with both policies, and KMS keys.
- **CBOM:** validated against the CycloneDX 1.6 schema.
