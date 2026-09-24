#!/bin/sh
# Container entrypoint.
#   (no args) -> generate certs if missing, then run nginx in the foreground
#   anything else -> exec it (used by the client container, e.g. "sleep infinity")
set -eu

if [ "$#" -gt 0 ]; then
  exec "$@"
fi

/usr/local/bin/gen-certs.sh /etc/pqc-lab/certs
echo "[entrypoint] $(openssl version)"
nginx -t
exec nginx -g 'daemon off;'
