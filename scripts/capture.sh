#!/bin/sh
# Captures one handshake per interesting scenario into /results/handshakes.pcap
# so you can open it in Wireshark and look at the key_share extension yourself.
# Filter suggestion in Wireshark:  tls.handshake.type == 1 || tls.handshake.type == 2
set -eu
SERVER="${SERVER:-pqc-server}"
CERTS="${CERTS:-/etc/pqc-lab/certs}"
PCAP="${OUT:-/results}/handshakes.pcap"

tcpdump -i eth0 -s 0 -w "$PCAP" "tcp port 8443 or tcp port 8444 or tcp port 8445 or tcp port 8446" \
  >/dev/null 2>&1 &
TP=$!
sleep 1

hsbench -n classical  -c "$SERVER:8444" -g X25519:prime256v1     -N 1 -C "$CERTS/ecdsa/ca.crt"
hsbench -n hybrid     -c "$SERVER:8443"                           -N 1 -C "$CERTS/ecdsa/ca.crt"
hsbench -n hrr-strict -c "$SERVER:8446" -g X25519:X25519MLKEM768  -N 1 -C "$CERTS/ecdsa/ca.crt"
hsbench -n pq-only    -c "$SERVER:8445" -g MLKEM1024              -N 1 -C "$CERTS/mldsa/ca.crt"

sleep 1
kill "$TP"; wait "$TP" 2>/dev/null || true
echo "[capture] wrote $PCAP"
