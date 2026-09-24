#!/bin/sh
# Runs every handshake scenario against the lab server and writes:
#   $OUT/handshakes.csv   raw results (one row per scenario)
#   $OUT/handshakes.md    markdown table for the README / article
#   $OUT/primitives.txt   raw ML-KEM / ML-DSA vs classical speed (openssl speed)
#
# Env:
#   SERVER   hostname of the server (default pqc-server)
#   CERTS    cert directory shared with the server (default /etc/pqc-lab/certs)
#   OUT      output directory (default /results)
#   N        handshakes per scenario (default 200)
#   DELAY_MS if set, delays the client's outgoing packets by this much with tc/netem,
#            which adds DELAY_MS to every round trip (needs NET_ADMIN; "make bench-wan")
#   SKIP_SPEED=1 skips the openssl speed run
set -u

SERVER="${SERVER:-pqc-server}"
CERTS="${CERTS:-/etc/pqc-lab/certs}"
OUT="${OUT:-/results}"
N="${N:-200}"
ECA="$CERTS/ecdsa/ca.crt"
MCA="$CERTS/mldsa/ca.crt"
SUFFIX=""
mkdir -p "$OUT"

if [ -n "${DELAY_MS:-}" ]; then
  tc qdisc replace dev eth0 root netem delay "${DELAY_MS}ms" \
    || { echo "netem unavailable: needs cap_add NET_ADMIN and a kernel with sch_netem"; exit 1; }
  trap 'tc qdisc del dev eth0 root 2>/dev/null' EXIT
  SUFFIX="-wan${DELAY_MS}ms"
  echo "[bench] added ${DELAY_MS} ms to every round trip (netem on client egress)"
fi

CSV="$OUT/handshakes${SUFFIX}.csv"
MD="$OUT/handshakes${SUFFIX}.md"

# Wait for the server
for _ in $(seq 1 30); do
  hsbench -n probe -c "$SERVER:8444" -N 1 >/dev/null 2>&1 && break
  sleep 1
done

hsbench -H > "$CSV"
run() { # name port groups cafile
  name="$1"; port="$2"; groups="$3"; ca="$4"
  set -- -n "$name" -c "$SERVER:$port" -N "$N"
  [ "$groups" != "-" ] && set -- "$@" -g "$groups"
  [ "$ca" != "-" ] && set -- "$@" -C "$ca"
  hsbench "$@" >> "$CSV" || true
  printf '[bench] %-34s %s\n' "$name" "$(tail -1 "$CSV" | cut -d, -f4,5,6)"
}

#   scenario                          port  client groups                 CA
run "1-classical-baseline"            8444  "X25519:prime256v1"           "$ECA"
run "2-hybrid-default-client"         8443  "-"                           "$ECA"
run "3-x25519-first-client>hybrid"    8443  "X25519:X25519MLKEM768"       "$ECA"
run "4-x25519-first-client>strict"    8446  "X25519:X25519MLKEM768"       "$ECA"
run "5-classical-client>strict"       8446  "X25519:prime256v1"           "$ECA"
run "6-pq-only-mlkem1024+mldsa65"     8445  "MLKEM1024"                   "$MCA"
run "7-default-client>pq-only"        8445  "-"                           "$MCA"
run "8-hybrid-only-client>classical"  8444  "X25519MLKEM768"              "$ECA"

# Markdown table (subset of columns that tells the story)
awk -F, 'NR==1 {
  print "| Scenario | Result | Group | HRR | Server sig | ClientHello B | ServerHello B | Cert msg B | Total c→s B | Total s→c B | Median ms | p95 ms |"
  print "|---|---|---|---|---|---:|---:|---:|---:|---:|---:|---:|"
  next }
{ printf "| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n",
    $1, $4, $5, $6, $7, $8, $9, $10, $12, $13, $14, $15 }' "$CSV" > "$MD"

echo
cat "$MD"
echo
echo "[bench] wrote $CSV and $MD"

if [ "${SKIP_SPEED:-0}" != "1" ] && [ -z "${DELAY_MS:-}" ]; then
  echo "[bench] running openssl speed (about 40 s)..."
  {
    echo "# $(openssl version)  |  $(uname -m)"
    echo "## Key exchange (openssl speed)"
    openssl speed -seconds 3 X25519 ML-KEM-512 ML-KEM-768 ML-KEM-1024 2>/dev/null \
      | sed -n '/keygen/,$p'
    echo
    echo "## Signatures (sigbench; openssl speed 3.5.x cannot benchmark ML-DSA)"
    sigbench 3
  } > "$OUT/primitives.txt"
  cat "$OUT/primitives.txt"
fi
