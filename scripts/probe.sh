#!/bin/sh
# probe.sh: network half of the crypto inventory.
#
# For each TLS endpoint, connects the way different clients would and records what the
# server actually negotiates. Runs inside the lab image (OpenSSL 3.5 CLI + hsbench).
#
#   probe.sh TARGETS_FILE [OUT_DIR]
#
# TARGETS_FILE: one endpoint per line, "host port [sni] [label]"; '#' starts a comment.
#   pqc-server 8443 pqc-lab.local lab-hybrid
#   kms.us-east-1.amazonaws.com 443
#
# Writes to OUT_DIR (default /results/inventory/<UTC timestamp>):
#   probes.csv    one hsbench row per (endpoint, client profile). scenario = "<label>|<profile>"
#   versions.tsv  label, version, accepted (yes/no), cipher
#   certs.tsv     label, depth, subject, issuer, not_before, not_after, sig_alg, key_alg, key_bits, der_bytes
#   targets.tsv   label, host, port, sni
#   meta.txt      when, where from, which OpenSSL
set -u

TARGETS="${1:?usage: probe.sh TARGETS_FILE [OUT_DIR]}"
OUT="${2:-/results/inventory/$(date -u +%Y%m%dT%H%M%SZ)}"
T="${PROBE_TIMEOUT:-12}"   # seconds per connection attempt
mkdir -p "$OUT/raw"

# Client profiles (OpenSSL 3.5 group syntax). Plain ':' lists send a key share for the
# FIRST group only, which is exactly what the downgrade test needs.
#   default          OpenSSL 3.5 defaults (hybrid + classical shares): a modern browser-like client
#   classical-only   a client with no PQ support: does the server still serve it?
#   hybrid-only      offers only hybrid groups: does the server support PQ key exchange at all?
#   classical-first  supports hybrid but sends an X25519 share first: is hybrid ENFORCED (HRR)
#                    or does the server silently settle for classical?
#   pq-only          pure ML-KEM: does the server accept non-hybrid PQ key exchange?
PROFILES="default:-
classical-only:X25519:P-256:P-384
hybrid-only:X25519MLKEM768:SecP256r1MLKEM768:SecP384r1MLKEM1024
classical-first:X25519:X25519MLKEM768:SecP256r1MLKEM768
pq-only:MLKEM768:MLKEM1024"

# Broad list used only to fetch the certificate chain from any kind of server.
ALL_GROUPS="X25519MLKEM768:X25519:P-256:P-384:SecP256r1MLKEM768:SecP384r1MLKEM1024:MLKEM768:MLKEM1024"

{
  echo "when=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "scanner=$(hostname)"
  echo "openssl=$(openssl version)"
  echo "targets_file=$TARGETS"
} > "$OUT/meta.txt"

hsbench -H > "$OUT/probes.csv"
printf 'label\tversion\taccepted\tcipher\n' > "$OUT/versions.tsv"
printf 'label\tdepth\tsubject\tissuer\tnot_before\tnot_after\tsig_alg\tkey_alg\tkey_bits\tder_bytes\n' > "$OUT/certs.tsv"
printf 'label\thost\tport\tsni\n' > "$OUT/targets.tsv"

probe_versions() { # label host port sni
  for v in tls1_2 tls1_1 tls1; do
    extra=""
    # OpenSSL 3 refuses TLS 1.0/1.1 at the default security level; lower it for the test.
    [ "$v" != tls1_2 ] && extra="-cipher DEFAULT:@SECLEVEL=0"
    # shellcheck disable=SC2086
    (timeout "$T" openssl s_client -connect "$2:$3" -servername "$4" -"$v" $extra \
      </dev/null >"$OUT/raw/$1.$v.txt" 2>&1) 2>/dev/null
    cipher="$(sed -n 's/^New, [^,]*, Cipher is \(.*\)$/\1/p' "$OUT/raw/$1.$v.txt" | head -1)"
    if [ -n "$cipher" ] && [ "$cipher" != "(NONE)" ]; then acc=yes; else acc=no; cipher="-"; fi
    printf '%s\t%s\t%s\t%s\n' "$1" "$v" "$acc" "$cipher" >> "$OUT/versions.tsv"
  done
}

probe_certs() { # label host port sni
  raw="$OUT/raw/$1.chain.txt"
  (timeout "$T" openssl s_client -connect "$2:$3" -servername "$4" -showcerts \
    -groups "$ALL_GROUPS" </dev/null >"$raw" 2>&1) 2>/dev/null
  # TLS 1.3 cipher suite from the same connection (if it was TLS 1.3)
  c13="$(sed -n 's/^New, TLSv1.3, Cipher is \(.*\)$/\1/p' "$raw" | head -1)"
  [ -n "$c13" ] && printf '%s\ttls1_3\tyes\t%s\n' "$1" "$c13" >> "$OUT/versions.tsv"
  # Split the PEM blocks into separate files: depth 0 = leaf.
  awk -v dir="$OUT/raw" -v lbl="$1" '
    /-----BEGIN CERTIFICATE-----/ { f = sprintf("%s/%s.cert%d.pem", dir, lbl, n++) }
    f { print > f }
    /-----END CERTIFICATE-----/   { close(f); f = "" }' "$raw"
  d=0
  while [ -f "$OUT/raw/$1.cert$d.pem" ]; do
    pem="$OUT/raw/$1.cert$d.pem"
    txt="$(openssl x509 -in "$pem" -noout -text 2>/dev/null)"
    subj="$(openssl x509 -in "$pem" -noout -subject -nameopt RFC2253 2>/dev/null | sed 's/^subject=//')"
    iss="$(openssl x509 -in "$pem" -noout -issuer -nameopt RFC2253 2>/dev/null | sed 's/^issuer=//')"
    nb="$(openssl x509 -in "$pem" -noout -startdate 2>/dev/null | sed 's/^notBefore=//')"
    na="$(openssl x509 -in "$pem" -noout -enddate 2>/dev/null | sed 's/^notAfter=//')"
    sig="$(printf '%s\n' "$txt" | sed -n 's/^ *Signature Algorithm: *//p' | head -1)"
    kalg="$(printf '%s\n' "$txt" | sed -n 's/^ *Public Key Algorithm: *//p' | head -1)"
    # EC keys: name the curve rather than "id-ecPublicKey"
    curve="$(printf '%s\n' "$txt" | sed -n 's/^ *ASN1 OID: *//p' | head -1)"
    [ "$kalg" = "id-ecPublicKey" ] && [ -n "$curve" ] && kalg="EC:$curve"
    bits="$(printf '%s\n' "$txt" | sed -n 's/^ *Public-Key: *(\([0-9]*\) bit).*/\1/p' | head -1)"
    der="$(openssl x509 -in "$pem" -outform DER 2>/dev/null | wc -c | tr -d ' ')"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$d" "$subj" "$iss" "$nb" "$na" \
      "$sig" "$kalg" "${bits:--}" "$der" >> "$OUT/certs.tsv"
    d=$((d + 1))
  done
}

grep -v '^[[:space:]]*#' "$TARGETS" | while read -r host port sni label _; do
  [ -z "${host:-}" ] && continue
  port="${port:-443}"
  sni="${sni:-$host}"
  [ "$sni" = "-" ] && sni="$host"
  label="${label:-$host:$port}"
  label="$(printf '%s' "$label" | tr -c 'A-Za-z0-9._:-' '_')"
  printf '%s\t%s\t%s\t%s\n' "$label" "$host" "$port" "$sni" >> "$OUT/targets.tsv"
  printf '[probe] %-40s ' "$label"

  rm -f "$OUT/.silent"
  printf '%s\n' "$PROFILES" | while IFS=: read -r prof groups; do
    shown="$groups"; [ "$groups" = "-" ] && shown="(default)"
    if [ -f "$OUT/.silent" ]; then   # endpoint already timed out: don't wait on it again
      echo "$label|$prof,$host:$port,$shown,FAIL: timeout,-,no,-,0,0,0,0,0,0,0.000,0.000,0" >> "$OUT/probes.csv"
      continue
    fi
    set -- -r -n "$label|$prof" -c "$host:$port" -s "$sni" -N 1
    [ "$groups" != "-" ] && set -- "$@" -g "$groups"
    # hsbench prints one row even when the handshake fails; an empty result means the
    # connection hung until the timeout killed it.
    row="$(timeout "$T" hsbench "$@" 2>/dev/null)"
    if [ -z "$row" ]; then
      row="$label|$prof,$host:$port,$shown,FAIL: timeout,-,no,-,0,0,0,0,0,0,0.000,0.000,0"
      : > "$OUT/.silent"
    fi
    printf '%s\n' "$row" >> "$OUT/probes.csv"
  done 2>/dev/null   # busybox ash reports "Terminated" on stderr when timeout kills a probe
  if [ -f "$OUT/.silent" ]; then
    for v in tls1_2 tls1_1 tls1; do printf '%s\t%s\tno\t-\n' "$label" "$v" >> "$OUT/versions.tsv"; done
  else
    probe_versions "$label" "$host" "$port" "$sni"
    probe_certs "$label" "$host" "$port" "$sni"
  fi
  printf '%s\n' "$(grep -F "$label|default," "$OUT/probes.csv" | cut -d, -f4,5 | head -1)"
done

rm -f "$OUT/.silent"
echo "[probe] wrote $OUT"
