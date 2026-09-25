# Deploying the lab to AWS

This Terraform module runs the PQC TLS lab server inside its own VPC, with a second instance (the scanner) in another Availability Zone. It has two jobs:

1. **Real-network benchmarks.** The scanner runs the same 8 scenarios as `make bench`, but across AZs instead of over loopback.
2. **A target for the crypto inventory.** The server is a known mix of classical, hybrid and pure post-quantum TLS endpoints behind a private DNS name. An internal load balancer adds one listener on a legacy TLS policy and one on AWS's post-quantum policy, and there are two KMS signing keys (ECDSA P-256 and ML-DSA-65). The `inventory_ground_truth` output records what a correct inventory should find, and `make aws-inventory` scores itself against it.

```
 VPC 10.42.0.0/16 ─────────────────────────────────────────────────────────────────────────
 │  AZ a                                          AZ b                                     │
 │  ┌──────────────────────────────────┐          ┌──────────────────────────────┐         │
 │  │ pqc-server.lab.internal          │  :8443   │ scanner                      │         │
 │  │ nginx 1.28 + OpenSSL 3.5.4       │◀─:8444───│ hsbench, sigbench,           │         │
 │  │ :8443 hybrid  :8446 hybrid-strict│  :8445   │ OpenSSL 3.5 CLI              │         │
 │  │ :8444 classical :8445 pq-only    │  :8446   │ `pqc-lab bench`              │         │
 │  └───────────────┬──────────────────┘          └──────────────┬───────────────┘         │
 │                  │ nginx log: port=… group=…                  │ results                 │
 └──────────────────┼────────────────────────────────────────────┼─────────────────────────┘
                    ▼                                            ▼
          CloudWatch Logs /pqc-tls-lab/nginx           S3 bucket results/<timestamp>/
```

## What it creates

| Resource | Why |
|---|---|
| VPC, 2 public + 2 private subnets in 2 AZs, internet gateway, S3 gateway endpoint | Network. The S3 endpoint is free and keeps bundle, CA and results traffic on AWS. |
| NAT gateway (only if `use_nat_gateway = true`) | Puts both instances in private subnets. More realistic, about $33/month extra. |
| 2 × EC2 (Amazon Linux 2023, t4g.small by default) | Server and scanner. Each builds the lab image from the pinned sources on first boot. |
| Security groups | Server: TCP 8443-8446 from the VPC CIDR only, plus any `allowed_cidrs`. Scanner: no inbound. No SSH anywhere. |
| IAM roles (one per instance) | SSM Session Manager, plus only the S3 prefixes and log group each instance needs. |
| S3 bucket | The lab source bundle, the two lab root CA certificates (public certs only) and benchmark results. TLS-only bucket policy, public access blocked. |
| Route 53 private zone `lab.internal` | `pqc-server.lab.internal`. The server's certificates are issued for this name. |
| CloudWatch log group + saved Logs Insights query | nginx logs `port=… group=…` for every request: server-side evidence of what was negotiated. |
| Internal ALB `alb.lab.internal` (only if `create_inventory_targets = true`, the default) | Port 443 on `ELBSecurityPolicy-2016-08` (the API default: TLS 1.0-1.2, no PQ) and port 8443 on `ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09` (hybrid ML-KEM). Fixed responses, no targets. Reachable from the VPC only. |
| ACM certificate (imported, self-signed) | For the ALB listeners. Imported certificates are free; its private key is in the Terraform state. |
| 2 × KMS signing keys | `alias/pqc-tls-lab-sign-ecdsa` (ECC_NIST_P256) and `alias/pqc-tls-lab-sign-mldsa` (ML_DSA_65). |

Hardening that's on by default: IMDSv2 required with hop limit 1 (containers can't reach instance credentials), encrypted gp3 root volumes, a default security group with no rules, and no key pairs.

## Prerequisites

- Terraform ≥ 1.7 or OpenTofu ≥ 1.7 (`TF=tofu make …` to use OpenTofu)
- AWS CLI v2 with credentials for the target account, and the [Session Manager plugin](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html) if you want interactive shells
- Permission to create VPC, EC2, IAM, S3, Route 53, CloudWatch Logs and SSM resources

## Use it

From the repo root:

```bash
cp deploy/aws/terraform.tfvars.example deploy/aws/terraform.tfvars   # optional
make aws-test      # offline tests with a mocked AWS provider; creates nothing
make aws-up        # plan + apply; review the plan before typing "yes"
make aws-status    # wait until it says "ready" (about 15 min: both instances compile OpenSSL + nginx)
make aws-smoke     # one request per endpoint, scanner -> server
make aws-bench     # 8 scenarios × 200 handshakes across AZs -> results/aws/<timestamp>/
make aws-inventory # crypto inventory, scored against the ground truth -> results/inventory-report/aws/
make aws-down      # destroy everything
```

For a shell on the scanner: `aws ssm start-session --target <scanner_instance_id>`, then `sudo pqc-lab bench`, `sudo pqc-lab capture` or `sudo pqc-lab shell`. `terraform -chdir=deploy/aws output how_to` prints ready-to-paste commands.

To see what the server negotiated, open CloudWatch → Logs Insights and run the saved query **pqc-tls-lab/negotiated-groups-by-port**, or run `aws logs tail /pqc-tls-lab/nginx --follow`.

## Cost

Rough us-east-1 on-demand prices. Check the [EC2 pricing page](https://aws.amazon.com/ec2/pricing/on-demand/) for your region.

| | Per hour | Per month if left running |
|---|---:|---:|
| 2 × t4g.small | ~$0.034 | ~$25 |
| 2 × public IPv4 (default mode) | ~$0.010 | ~$7 |
| 2 × 16 GB gp3 | – | ~$2.60 |
| Route 53 private zone | – | $0.50 |
| Internal ALB (inventory target) | ~$0.023 + LCUs (negligible here) | ~$16 |
| 2 × KMS keys (inventory target) | ~$0.003 | $2 |
| NAT gateway (only with `use_nat_gateway = true`) | ~$0.045 + data | ~$33 + data |

The default setup costs about 8 cents an hour (5 cents with `create_inventory_targets = false`). KMS keys are scheduled for deletion with a 7-day window when you destroy the lab, and AWS doesn't bill keys that are pending deletion. Run `make aws-down` when you're finished. It also empties and deletes the bucket, the log group and the hosted zone.

## Notes

- **The inventory is read-only.** `make aws-inventory` uses your CLI credentials for Describe/List/Get calls only. It runs its network probes on the scanner through SSM: it uploads the probe script to `s3://<bucket>/inventory-jobs/`, and the scanner writes the output to `s3://<bucket>/results/inventory/`.
- **Changing the lab redeploys it.** The bundle's S3 key includes a hash of its contents, so editing `server/nginx.conf` (for example) and running `make aws-up` again replaces both instances with the new build. Scanner results already in S3 are kept.
- **Certificates.** The server generates its lab PKIs (ECDSA P-256 and ML-DSA-65) on first boot, for `pqc-server.lab.internal`. The private keys stay in a Docker volume on the server. Only the two root CA certificates are copied to S3 so the scanner can verify the chains.
- **Reaching it from your laptop.** With the default (no NAT) mode, set `allowed_cidrs = ["<your-ip>/32"]` and connect to the `server_public_ip` output. Certificate hostname checks will fail because the certificates name the private DNS name. Use `-servername pqc-server.lab.internal` or skip hostname verification.
- **Timings.** Results across AZs include a real (sub-millisecond to low-millisecond) network round trip, so they are more meaningful than the loopback numbers. However, they still aren't an internet path. `make aws-bench-wan` adds `DELAY_MS` on top.
- **Bootstrap logs** are in `/var/log/pqc-lab-bootstrap.log` on each instance.
