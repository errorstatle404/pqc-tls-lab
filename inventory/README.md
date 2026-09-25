# pqc-inventory: find the cryptography, report what's quantum-ready

A crypto inventory tool for TLS endpoints and AWS accounts. It answers the first question of any post-quantum migration: **what cryptography do we have, and which of it is exposed to "harvest now, decrypt later"?**

It works in two layers, because neither is enough on its own:

1. **Configuration (AWS APIs, read-only).** It lists ACM certificates, load balancer listeners and their TLS security policies, CloudFront distributions, KMS keys (with key specs), and EC2 instances whose security groups open TLS ports. That covers what exists and what it's configured to do.
2. **Network (what's actually negotiated).** It connects to every TLS endpoint it found as six kinds of client. A config that says "hybrid PQC enabled" doesn't prove that sessions are hybrid; the lab's endpoint `:8443` is the example.

| Client profile | What it tells you |
|---|---|
| Current browser / OpenSSL 3.5 default | What most traffic gets today |
| Hybrid-capable, classical share first | Does the server insist on hybrid (HelloRetryRequest) or silently accept classical? |
| Classical-only client | Do old clients still connect? |
| Hybrid-only client | Can the server do hybrid at all? |
| Pure ML-KEM client | Pure post-quantum support |
| TLS 1.2 client | TLS 1.2 has no post-quantum option |

Each endpoint gets a class: **hybrid-enforced**, **hybrid-downgradable** (the silent downgrade), **hybrid-not-preferred**, **pq-only** or **classical**.

## Outputs

In `results/inventory-report/<mode>/`:

| File | What |
|---|---|
| `report.md` | Summary, score, per-endpoint matrix, findings with severity and fix, AWS tables |
| `cbom.json` | CycloneDX 1.6 CBOM (Cryptography Bill of Materials); checked against the official schema on every run |
| `findings.csv` | One row per finding, for a spreadsheet or ticketing system |
| `inventory.json` | Everything, machine-readable |
| `raw-probes.txt` | The filtered `openssl s_client` output behind every result |

## Use it

From the repo root:

```bash
make inventory-setup    # one-time Python environment
make inventory-test     # unit tests, no network needed
make inventory-local    # the Docker lab; scored against ground_truth/local.json (expect 8/8)
make inventory-public   # AWS's public service endpoints (targets/public-aws.txt)
make aws-inventory      # your AWS account, after `make aws-up` (see deploy/aws/README.md)
```

Or directly: `PYTHONPATH=inventory .venv/bin/python -m pqcinv --help`. `scan host:port ...` probes anything you name.

## Where the probe runs

The probe is `openssl s_client` from **OpenSSL 3.5 or later** (earlier versions have no ML-KEM). Most distros ship an older OpenSSL, so the tool doesn't use yours by default:

- `--via docker` (local and public modes): the lab's `pqc-client` container.
- `--via ssm` (AWS mode): the lab's scanner instance inside the VPC, through SSM Run Command. There's no SSH and nothing is opened to the internet. The probe script goes up through S3 and the output comes back through S3, because SSM truncates output at 24,000 characters.
- `--via direct --openssl /path/to/openssl`: this machine, if you have OpenSSL 3.5.

What a probe sees depends on where it runs. A proxy or TLS-inspecting middlebox in the path answers the handshake itself, so the result describes the middlebox, not the server.

## Scoring

The lab knows its own answers. The Terraform output `inventory_ground_truth` (and `ground_truth/local.json` for Docker) records the right class and default-client result for every endpoint, plus the KMS key specs. The tool scores itself against them, so a wrong result shows up as a failed check instead of a plausible-looking report.

## Limits

- It inventories what's reachable and configured: TLS endpoints and AWS-managed keys and certificates. It doesn't read application code, libraries or data at rest, so it's one input to a full inventory, not the whole of it.
- AWS mode covers one region per run (CloudFront is global).
- SSH, IPsec and other non-TLS protocols aren't probed.
