#!/bin/sh
# Crypto inventory of the AWS lab, end to end:
#   1. read the account's configuration (your AWS credentials, read-only)       -> aws.json, targets.txt
#   2. probe those endpoints from the scanner inside the VPC (SSM Run Command)  -> probe results in S3
#   3. build the report, CBOM and findings, scored against the lab's known answers
#
#   usage: deploy/aws/inventory.sh            (from the repo root; `make aws-inventory` does this)
# Output: results/aws-inventory/<UTC timestamp>/{report.md,cbom.json,findings.csv,findings.json,aws.json,probes/}
set -eu
TF="${TF:-terraform}"
PY="${PY:-inventory/.venv/bin/python}"
DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/../.." && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$ROOT/results/aws-inventory/$STAMP"
mkdir -p "$OUT"

tfout() { "$TF" -chdir="$DIR" output -raw "$1"; }
REGION="$(tfout region)"
SCANNER="$(tfout scanner_instance_id 2>/dev/null || true)"
BUCKET="$(tfout bucket)"
[ -n "$SCANNER" ] && [ "$SCANNER" != "null" ] || { echo "no scanner instance (create_scanner = false?)"; exit 1; }

echo "[aws-inventory] 1/3 reading AWS configuration ($REGION)"
PYTHONPATH="$ROOT/inventory" "$PY" -m cryptoinv aws --region "$REGION" --out "$OUT"
"$TF" -chdir="$DIR" output -json inventory_ground_truth > "$OUT/ground-truth.json"

# Only endpoints inside this lab's VPC are reachable from the scanner; the scanner probes them all.
TARGETS_B64="$(grep -v '^#' "$OUT/targets.txt" | base64 | tr -d '\n')"
[ -n "$TARGETS_B64" ] || { echo "no endpoints found to probe"; exit 1; }

echo "[aws-inventory] 2/3 probing $(grep -vc '^#' "$OUT/targets.txt") endpoints from the scanner ($SCANNER)"
REMOTE="set -e; test -f /var/lib/pqc-lab/ready || { echo 'scanner still bootstrapping'; exit 2; }; \
echo $TARGETS_B64 | base64 -d > /opt/pqc-tls-lab/results/targets-$STAMP.txt; \
docker exec pqc-client probe.sh /results/targets-$STAMP.txt /results/inventory/$STAMP; \
aws s3 cp --recursive --only-show-errors /opt/pqc-tls-lab/results/inventory/$STAMP s3://$BUCKET/results/inventory/$STAMP/ --region $REGION"

ID="$(aws ssm send-command --region "$REGION" --instance-ids "$SCANNER" \
  --document-name AWS-RunShellScript --timeout-seconds 900 --comment "pqc-tls-lab inventory $STAMP" \
  --parameters "$(printf '{"commands":["%s"],"executionTimeout":["900"]}' "$REMOTE")" \
  --query Command.CommandId --output text)"

while :; do
  STATUS="$(aws ssm get-command-invocation --region "$REGION" --command-id "$ID" --instance-id "$SCANNER" \
    --query Status --output text 2>/dev/null || echo Pending)"
  case "$STATUS" in Pending|InProgress|Delayed) sleep 5 ;; *) break ;; esac
done
aws ssm get-command-invocation --region "$REGION" --command-id "$ID" --instance-id "$SCANNER" \
  --query StandardOutputContent --output text
if [ "$STATUS" != Success ]; then
  aws ssm get-command-invocation --region "$REGION" --command-id "$ID" --instance-id "$SCANNER" \
    --query StandardErrorContent --output text >&2
  echo "[aws-inventory] probe failed on the scanner ($STATUS)"; exit 1
fi
aws s3 sync --region "$REGION" --only-show-errors "s3://$BUCKET/results/inventory/$STAMP" "$OUT/probes"

echo "[aws-inventory] 3/3 building the report"
PYTHONPATH="$ROOT/inventory" "$PY" -m cryptoinv report --probes "$OUT/probes" --aws "$OUT/aws.json" \
  --ground-truth "$OUT/ground-truth.json" --out "$OUT"
echo "[aws-inventory] open $OUT/report.md"
