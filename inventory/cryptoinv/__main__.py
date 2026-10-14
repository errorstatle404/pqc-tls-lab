"""cryptoinv command line.

  python -m cryptoinv aws    --out DIR [--region R] [--profile P]
      Read-only AWS collection -> DIR/aws.json and DIR/targets.txt (endpoints to probe)

  python -m cryptoinv report --probes DIR [--aws aws.json] [--ground-truth gt.json] [--out DIR]
      Build the report from probe.sh output (+ optional AWS data and known answers):
      report.md, cbom.json (CycloneDX 1.6), findings.json, findings.csv
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import cbom, findings as F, probes, report, score


def cmd_aws(a) -> int:
    import boto3

    from . import aws_collect
    session = boto3.Session(profile_name=a.profile, region_name=a.region)
    data = aws_collect.collect(session, a.region)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "aws.json").write_text(json.dumps(data, indent=2))
    aws_collect.write_targets_file(data["targets"], out / "targets.txt")
    print(f"[cryptoinv] account {data['identity'].get('account', '?')} {data['region']}: "
          f"{len(data['acm_certificates'])} ACM certs, "
          f"{len(data['elbv2']['load_balancers'])} load balancers, {len(data['kms_keys'])} KMS keys, "
          f"{len(data['ec2_instances'])} running instances -> {len(data['targets'])} endpoints to probe")
    for e in data["errors"]:
        print(f"[cryptoinv] warning: {e['collector']}: {e['error']}", file=sys.stderr)
    print(f"[cryptoinv] wrote {out / 'aws.json'} and {out / 'targets.txt'}")
    return 0


def cmd_report(a) -> int:
    eps, meta = probes.load(a.probes)
    aws = json.loads(Path(a.aws).read_text()) if a.aws else None
    by_label = {e.label: e for e in eps}
    fs = F.network_findings(eps)
    if aws:
        fs += F.aws_findings(aws, by_label)
    fs = F.sort(fs)

    checks = acc = None
    if a.ground_truth:
        gt = json.loads(Path(a.ground_truth).read_text())
        checks, acc = score.score(gt, eps)

    bom = cbom.build(eps, aws, meta)
    bom_json = json.dumps(bom, indent=2)
    err = cbom.validate(bom_json)

    out = Path(a.out or a.probes)
    out.mkdir(parents=True, exist_ok=True)
    (out / "cbom.json").write_text(bom_json)
    (out / "findings.json").write_text(json.dumps([f.dict() for f in fs], indent=2))
    report.write_csv(fs, out / "findings.csv")
    (out / "report.md").write_text(report.render(eps, fs, aws, meta, checks, acc, len(bom["components"]), err))

    counts = {s: sum(f.severity == s for f in fs) for s in ("high", "medium", "low", "info")}
    print(f"[cryptoinv] {len(eps)} endpoints, findings: " + ", ".join(f"{v} {k}" for k, v in counts.items()))
    if checks is not None:
        print(f"[cryptoinv] accuracy vs ground truth: {sum(c.ok for c in checks)}/{len(checks)} ({acc:.0%})")
        for c in checks:
            if not c.ok:
                print(f"[cryptoinv]   mismatch {c.endpoint} {c.field}: expected {c.expected}, observed {c.observed}")
    print(f"[cryptoinv] CBOM: {len(bom['components'])} components, "
          + ("valid CycloneDX 1.6" if err is None else f"validation: {err[:200]}"))
    print(f"[cryptoinv] wrote {out}/report.md, cbom.json, findings.json, findings.csv")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="cryptoinv", description="Cryptographic inventory for AWS and TLS endpoints")
    sub = p.add_subparsers(dest="cmd", required=True)
    pa = sub.add_parser("aws", help="collect AWS configuration (read-only)")
    pa.add_argument("--out", required=True)
    pa.add_argument("--region")
    pa.add_argument("--profile")
    pa.set_defaults(fn=cmd_aws)
    pr = sub.add_parser("report", help="build report + CBOM from probe results")
    pr.add_argument("--probes", required=True, help="probe.sh output directory")
    pr.add_argument("--aws", help="aws.json from `cryptoinv aws`")
    pr.add_argument("--ground-truth", help="known answers to score against")
    pr.add_argument("--out", help="output directory (default: the probes directory)")
    pr.set_defaults(fn=cmd_report)
    a = p.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
