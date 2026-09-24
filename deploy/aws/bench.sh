#!/bin/sh
# Runs the benchmark on the AWS scanner through SSM Run Command (no SSH), waits for it,
# prints the output, and syncs the results to ./results/aws/.
#   usage: deploy/aws/bench.sh [bench|bench-wan|smoke|capture]
set -eu
CMD="${1:-bench}"
TF="${TF:-terraform}"
DIR="$(cd "$(dirname "$0")" && pwd)"
OUT_DIR="${OUT_DIR:-$DIR/../../results/aws}"

tfout() { "$TF" -chdir="$DIR" output -raw "$1"; }
REGION="$(tfout region)"
SCANNER="$(tfout scanner_instance_id 2>/dev/null || true)"
BUCKET="$(tfout bucket)"
[ -n "$SCANNER" ] && [ "$SCANNER" != "null" ] || { echo "no scanner instance (create_scanner = false?)"; exit 1; }

case "$CMD" in
  bench|bench-wan|capture) REMOTE="pqc-lab $CMD && pqc-lab upload" ;;
  smoke|status)            REMOTE="pqc-lab $CMD" ;;
  *) echo "usage: $0 [bench|bench-wan|smoke|capture|status]"; exit 1 ;;
esac

echo "[aws-bench] running '$REMOTE' on $SCANNER ($REGION)"
ID="$(aws ssm send-command --region "$REGION" --instance-ids "$SCANNER" \
  --document-name AWS-RunShellScript --timeout-seconds 1800 \
  --comment "pqc-tls-lab $CMD" \
  --parameters "commands=[\"$REMOTE\"],executionTimeout=[\"1800\"]" \
  --query Command.CommandId --output text)"

STATUS=Pending
while :; do
  STATUS="$(aws ssm get-command-invocation --region "$REGION" --command-id "$ID" \
    --instance-id "$SCANNER" --query Status --output text 2>/dev/null || echo Pending)"
  case "$STATUS" in Pending|InProgress|Delayed) sleep 5 ;; *) break ;; esac
done

aws ssm get-command-invocation --region "$REGION" --command-id "$ID" --instance-id "$SCANNER" \
  --query StandardOutputContent --output text
ERR="$(aws ssm get-command-invocation --region "$REGION" --command-id "$ID" --instance-id "$SCANNER" \
  --query StandardErrorContent --output text)"
[ -n "$ERR" ] && [ "$ERR" != "None" ] && printf '%s\n' "$ERR" >&2
echo "[aws-bench] status: $STATUS"
# SSM truncates StandardOutputContent at 24,000 characters; the full files are in S3.

if [ "$CMD" != smoke ] && [ "$CMD" != status ]; then
  mkdir -p "$OUT_DIR"
  aws s3 sync --region "$REGION" --only-show-errors "s3://$BUCKET/results" "$OUT_DIR"
  echo "[aws-bench] results synced to $OUT_DIR"
fi
[ "$STATUS" = Success ]
