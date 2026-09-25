"""pqc-inventory command line.

  python -m pqcinv local     the Docker lab (make up), scored against ground_truth/local.json
  python -m pqcinv public    AWS's public service endpoints (what AWS itself negotiates today)
  python -m pqcinv aws       an AWS account: API inventory + probes from the lab's scanner
  python -m pqcinv scan H:P  any endpoints you name
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
import shutil
import subprocess
import sys

from . import __version__, classify, probe, report, score as scoring
from .cbom import build_cbom, validate
from . import transports

PKG_DIR = os.path.dirname(os.path.abspath(__file__))
INV_DIR = os.path.dirname(PKG_DIR)
REPO_ROOT = os.path.dirname(INV_DIR)


def _transport(args):
    if args.via == "docker":
        if not shutil.which("docker"):
            sys.exit("docker not found. Start the lab with `make up`, or use --via direct with OpenSSL 3.5.")
        return transports.docker_compose(REPO_ROOT)
    if args.via == "direct":
        return transports.direct(args.openssl)
    sys.exit(f"--via {args.via} is not valid here")


def run_probes(targets, transport):
    raw = transport.run(probe.build_script(targets))
    version, results = probe.parse_output(raw)
    if not probe.openssl_supports_pq(version):
        sys.exit(f"The probe client runs {version or 'an unknown OpenSSL'}; it needs OpenSSL 3.5 or later "
                 "for ML-KEM. Use the lab's client container (--via docker) or the AWS scanner.")
    by_endpoint = {}
    for r in results:
        by_endpoint.setdefault((r.host, r.port), {})[r.profile] = r
    return version, raw, [classify.assess_endpoint(t, by_endpoint.get((t.host, t.port), {})) for t in targets]


def finish(args, scope, where, version, raw, assessments, aws_inv=None, truth=None):
    findings = [f for a in assessments for f in a.findings]
    if aws_inv:
        for k in aws_inv["kms_keys"]:
            if k.get("KeyState") == "Enabled":
                findings += classify.kms_key_findings(k)
        for c in aws_inv["acm_certificates"]:
            findings += classify.acm_certificate_findings(c)
        for lb in aws_inv["load_balancers"]:
            for li in lb["Listeners"]:
                if li["SslPolicy"]:
                    findings += classify.elb_listener_findings(lb["LoadBalancerName"], li, li.get("Policy"))
        for d in aws_inv["cloudfront"]:
            findings += classify.cloudfront_findings(d)
    findings = classify.sort_findings(findings)
    sc = scoring.score(assessments, truth, aws_inv) if truth else None
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    cbom = build_cbom(assessments, aws_inv, scope, ts)
    errors = validate(cbom)
    ctx = {"scope": scope, "timestamp": ts, "probe_where": where, "openssl": version,
           "assessments": assessments, "findings": findings, "score": sc, "aws": aws_inv,
           "cbom_valid": not errors, "cbom_spec": cbom["specVersion"]}
    paths = report.write_outputs(args.out, ctx, cbom, raw)

    print(f"\n{scope}: {len(assessments)} endpoint(s) probed from {where}")
    for a in assessments:
        print(f"  {report.ICON[a.classification]} {a.endpoint:<48} {a.classification:<22} "
              f"browser gets: {a.default_outcome}")
    sev = {}
    for f in findings:
        sev[f.severity] = sev.get(f.severity, 0) + 1
    print("Findings: " + (", ".join(f"{n} {s}" for s, n in sorted(sev.items(),
                                    key=lambda kv: classify.SEVERITY_ORDER[kv[0]])) or "none"))
    if sc:
        print(f"Score against ground truth: {sc['passed']}/{sc['total']} ({sc['percent']}%)")
        for c in sc["checks"]:
            if not c["pass"]:
                print(f"  ✗ {c['asset']} {c['check']}: expected {c['expected']}, found {c['found']}")
    if errors:
        print("CBOM schema check FAILED:\n  " + "\n  ".join(errors[:5]))
    else:
        print(f"CBOM: CycloneDX {cbom['specVersion']}, {len(cbom['components'])} components, schema check passed")
    print(f"Report: {os.path.relpath(paths['report'])}")
    return 1 if errors else 0


def cmd_local(args):
    with open(args.truth, encoding="utf-8") as f:
        truth = json.load(f)
    targets = [probe.Target(truth["host"], int(p), "lab", e.get("name", ""))
               for p, e in sorted(truth["endpoints"].items())]
    t = _transport(args)
    version, raw, assessments = run_probes(targets, t)
    return finish(args, "Local Docker lab", t.where, version, raw, assessments, truth=truth)


def cmd_public(args):
    targets = _read_targets(args.targets, "public")
    t = _transport(args)
    version, raw, assessments = run_probes(targets, t)
    return finish(args, "Public AWS service endpoints", t.where, version, raw, assessments)


def cmd_scan(args):
    targets = [probe.parse_target(x) for x in args.targets]
    t = _transport(args)
    version, raw, assessments = run_probes(targets, t)
    return finish(args, "Manual scan", t.where, version, raw, assessments)


def cmd_aws(args):
    import boto3
    from . import aws_collect

    tf = _terraform_outputs(args.tf_dir) if args.tf_dir else {}
    region = args.region or tf.get("region") or boto3.Session(profile_name=args.profile).region_name or "us-east-1"
    session = boto3.Session(profile_name=args.profile, region_name=region)

    print(f"Reading the AWS configuration in {region} (read-only)...")
    inv = aws_collect.collect(session, region)
    targets = aws_collect.targets_from_inventory(inv)
    print(f"  {len(inv['kms_keys'])} KMS keys, {len(inv['acm_certificates'])} ACM certificates, "
          f"{len(inv['load_balancers'])} load balancers, {len(inv['cloudfront'])} CloudFront distributions, "
          f"{len(inv['instances'])} running instances -> {len(targets)} TLS endpoints")
    for e in inv["errors"]:
        print(f"  could not read {e['collector']}: {e['error']}")

    truth = tf.get("inventory_ground_truth") if not args.no_score else None
    if args.via == "none" or not targets:
        return finish(args, f"AWS account {inv.get('account') or ''} ({region})", "nowhere (API only)",
                      "", "", [], inv, truth)
    if args.via == "ssm":
        scanner = args.scanner or tf.get("scanner_instance_id")
        bucket = args.bucket or tf.get("bucket")
        if not scanner or not bucket:
            sys.exit("--via ssm needs the lab's scanner and bucket: run from the repo after `make aws-up`, "
                     "or pass --scanner and --bucket (or use --via none for API-only).")
        t = transports.SsmTransport(session, region, scanner, bucket)
        print(f"Probing {len(targets)} endpoints from {t.where} (about 1-3 minutes)...")
    else:
        t = _transport(args)
    version, raw, assessments = run_probes(targets, t)
    return finish(args, f"AWS account {inv.get('account') or ''} ({region})", t.where,
                  version, raw, assessments, inv, truth)


def _terraform_outputs(tf_dir: str) -> dict:
    tf = os.environ.get("TF", "terraform")
    try:
        p = subprocess.run([tf, f"-chdir={tf_dir}", "output", "-json"], capture_output=True, text=True, timeout=120)
    except FileNotFoundError:
        print(f"  ({tf} not found; continuing without the lab's Terraform outputs)")
        return {}
    if p.returncode != 0 or not p.stdout.strip():
        print(f"  (no Terraform outputs in {tf_dir}; continuing without the lab's ground truth)")
        return {}
    return {k: v.get("value") for k, v in json.loads(p.stdout).items()}


def _read_targets(path: str, source: str) -> list:
    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if line:
                out.append(probe.parse_target(line, source))
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(prog="pqc-inventory", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", action="version", version=f"pqc-inventory {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p, default_out, vias=("docker", "direct"), default_via="docker"):
        p.add_argument("--out", default=default_out, help=f"output directory (default {default_out})")
        p.add_argument("--via", choices=vias, default=default_via,
                       help="where the probe runs: docker = the lab's pqc-client container; "
                            "direct = this machine (needs OpenSSL 3.5, see --openssl)")
        p.add_argument("--openssl", default=os.environ.get("OPENSSL", "openssl"),
                       help="OpenSSL 3.5 binary for --via direct")

    p = sub.add_parser("local", help="probe the Docker lab and score it")
    common(p, "results/inventory-report/local")
    p.add_argument("--truth", default=os.path.join(INV_DIR, "ground_truth", "local.json"))
    p.set_defaults(fn=cmd_local)

    p = sub.add_parser("public", help="probe AWS's public service endpoints")
    common(p, "results/inventory-report/public")
    p.add_argument("--targets", default=os.path.join(INV_DIR, "targets", "public-aws.txt"))
    p.set_defaults(fn=cmd_public)

    p = sub.add_parser("scan", help="probe endpoints given on the command line")
    common(p, "results/inventory-report/scan")
    p.add_argument("targets", nargs="+", help="host:port [host:port ...]")
    p.set_defaults(fn=cmd_scan)

    p = sub.add_parser("aws", help="inventory an AWS account (read-only)")
    common(p, "results/inventory-report/aws", vias=("ssm", "none", "docker", "direct"), default_via="ssm")
    p.add_argument("--tf-dir", default=os.path.join(REPO_ROOT, "deploy", "aws"),
                   help="the lab's Terraform directory, for the scanner, bucket and ground truth ('' to skip)")
    p.add_argument("--region")
    p.add_argument("--profile", help="AWS CLI profile name")
    p.add_argument("--scanner", help="instance id that runs the probes (default: the lab's scanner)")
    p.add_argument("--bucket", help="S3 bucket for probe jobs/results (default: the lab's bucket)")
    p.add_argument("--no-score", action="store_true", help="don't score against the lab's ground truth")
    p.set_defaults(fn=cmd_aws)

    args = ap.parse_args(argv)
    return args.fn(args)
