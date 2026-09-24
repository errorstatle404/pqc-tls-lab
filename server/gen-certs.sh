#!/bin/sh
# Generates two independent lab PKIs:
#   ecdsa/  : ECDSA P-256 root CA -> leaf   (what browsers accept today)
#   mldsa/  : ML-DSA-65 root CA   -> leaf   (FIPS 204, experimental in TLS)
# Everything is self-signed and for lab use only.
set -eu

OUT="${1:-/etc/pqc-lab/certs}"
CN="${LAB_CN:-pqc-lab.local}"
DAYS=825
OPENSSL="${OPENSSL:-openssl}"

SAN="subjectAltName=DNS:${CN},DNS:localhost,DNS:pqc-server,IP:127.0.0.1"

mk_pki() {
  name="$1"; shift          # directory name
  keyopts="$*"              # genpkey algorithm options
  d="${OUT}/${name}"
  mkdir -p "$d"
  if [ -s "$d/leaf.crt" ]; then
    echo "[certs] ${name}: already present, skipping"
    return
  fi
  echo "[certs] ${name}: generating CA + leaf (${keyopts})"

  # shellcheck disable=SC2086
  $OPENSSL genpkey $keyopts -out "$d/ca.key" 2>/dev/null
  $OPENSSL req -x509 -new -key "$d/ca.key" -days "$DAYS" \
    -subj "/O=PQC TLS Lab/CN=PQC Lab Root CA (${name})" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -out "$d/ca.crt"

  # shellcheck disable=SC2086
  $OPENSSL genpkey $keyopts -out "$d/leaf.key" 2>/dev/null
  $OPENSSL req -new -key "$d/leaf.key" -subj "/O=PQC TLS Lab/CN=${CN}" -out "$d/leaf.csr"
  $OPENSSL x509 -req -in "$d/leaf.csr" -CA "$d/ca.crt" -CAkey "$d/ca.key" \
    -CAcreateserial -days "$DAYS" \
    -extfile /dev/stdin -out "$d/leaf.crt" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
${SAN}
EOF
  # Chain file served by nginx (leaf + CA so clients see full chain size)
  cat "$d/leaf.crt" "$d/ca.crt" > "$d/fullchain.crt"
  rm -f "$d/leaf.csr" "$d/ca.srl"
  chmod 600 "$d"/*.key
}

mk_pki ecdsa -algorithm EC -pkeyopt ec_paramgen_curve:P-256
mk_pki mldsa -algorithm ML-DSA-65

echo "[certs] done:"
for n in ecdsa mldsa; do
  printf '  %-6s leaf sig alg: %s | chain size: %s bytes (PEM)\n' "$n" \
    "$($OPENSSL x509 -in "${OUT}/${n}/leaf.crt" -noout -text | awk -F': ' '/Signature Algorithm/{print $2; exit}')" \
    "$(wc -c < "${OUT}/${n}/fullchain.crt" | tr -d ' ')"
done
