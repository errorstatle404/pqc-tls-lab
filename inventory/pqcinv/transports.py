"""Where the probe script runs.

  CommandTransport   any local command that reads a shell script on stdin
                     (the lab's client container, or `sh` with OpenSSL 3.5 on PATH)
  SsmTransport       the AWS scanner instance, through SSM Run Command (no SSH).
                     The script goes up through S3 and the output comes back through S3,
                     because SSM truncates command output at 24,000 characters.
"""
from __future__ import annotations

from datetime import datetime, timezone
import os
import subprocess
import time


class CommandTransport:
    def __init__(self, argv: list, cwd: str | None = None, env: dict | None = None, where: str = ""):
        self.argv, self.cwd, self.where = argv, cwd, where or " ".join(argv)
        self.env = {**os.environ, **(env or {})}

    def run(self, script: str, timeout: int = 1800) -> str:
        p = subprocess.run(self.argv, input=script, capture_output=True, text=True,
                           cwd=self.cwd, env=self.env, timeout=timeout)
        if "### DONE" not in p.stdout:
            raise RuntimeError(f"probe did not finish (exit {p.returncode}) via {self.where}:\n"
                               f"{p.stderr.strip() or p.stdout[-2000:]}")
        return p.stdout


def docker_compose(repo_root: str, service: str = "pqc-client") -> CommandTransport:
    return CommandTransport(["docker", "compose", "exec", "-T", service, "sh", "-s"], cwd=repo_root,
                            where=f"docker compose service {service}")


def direct(openssl: str = "openssl") -> CommandTransport:
    return CommandTransport(["sh", "-s"], env={"OPENSSL": openssl}, where=f"this machine ({openssl})")


class SsmTransport:
    def __init__(self, session, region: str, instance_id: str, bucket: str):
        self.ssm = session.client("ssm", region_name=region)
        self.s3 = session.client("s3", region_name=region)
        self.region, self.instance_id, self.bucket = region, instance_id, bucket
        self.where = f"scanner {instance_id} via SSM"

    def run(self, script: str, timeout: int = 1800) -> str:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        job_key = f"inventory-jobs/{stamp}/probe.sh"
        out_key = f"results/inventory/{stamp}/raw-probes.txt"
        self.s3.put_object(Bucket=self.bucket, Key=job_key, Body=script.encode(), ServerSideEncryption="AES256")
        b, r = self.bucket, self.region
        commands = [
            "set -eu",
            ". /etc/pqc-lab/env",
            "[ -f /var/lib/pqc-lab/ready ] || { echo 'The scanner is still bootstrapping. Run make aws-status and wait for ready.'; exit 2; }",
            f"aws s3 cp --only-show-errors s3://{b}/{job_key} /tmp/pqcinv-probe.sh --region {r}",
            f'OUT="$LAB_DIR/results/inventory-raw-{stamp}.txt"',
            'docker exec -i pqc-client sh -s < /tmp/pqcinv-probe.sh > "$OUT" 2>&1',
            f'aws s3 cp --only-show-errors "$OUT" s3://{b}/{out_key} --region {r}',
            'echo "probes run: $(grep -c "^### PROBE" "$OUT")"',
        ]
        cmd_id = self.ssm.send_command(
            InstanceIds=[self.instance_id], DocumentName="AWS-RunShellScript",
            Comment="pqc-tls-lab inventory probe", TimeoutSeconds=600,
            Parameters={"commands": commands, "executionTimeout": [str(timeout)]},
        )["Command"]["CommandId"]
        status, inv, deadline = "Pending", {}, time.time() + timeout + 120
        while time.time() < deadline:
            time.sleep(5)
            try:
                inv = self.ssm.get_command_invocation(CommandId=cmd_id, InstanceId=self.instance_id)
            except self.ssm.exceptions.InvocationDoesNotExist:
                continue
            status = inv["Status"]
            if status not in ("Pending", "InProgress", "Delayed"):
                break
        if status != "Success":
            raise RuntimeError(f"probe on {self.instance_id} ended with status {status}:\n"
                               f"{inv.get('StandardOutputContent', '')}\n{inv.get('StandardErrorContent', '')}")
        body = self.s3.get_object(Bucket=self.bucket, Key=out_key)["Body"].read().decode()
        if "### DONE" not in body:
            raise RuntimeError(f"probe output in s3://{self.bucket}/{out_key} is incomplete")
        return body
