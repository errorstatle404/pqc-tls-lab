# syntax=docker/dockerfile:1
#
# One image for both the server (nginx) and the client (hsbench, openssl CLI).
# OpenSSL and nginx are built from pinned, checksum-verified source so the lab
# does not depend on whichever OpenSSL version a distro happens to ship.
#
#   OpenSSL 3.5.4 (LTS) : native ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205)
#                         and the hybrid TLS group X25519MLKEM768. No oqs-provider needed.
#   nginx 1.28.0        : stable branch, linked against the OpenSSL above.

ARG ALPINE_VERSION=3.22

########################  build stage  ########################
FROM alpine:${ALPINE_VERSION} AS build

ARG OPENSSL_VERSION=3.5.4
ARG OPENSSL_SHA256=967311f84955316969bdb1d8d4b983718ef42338639c621ec4c34fddef355e99
ARG NGINX_VERSION=1.28.0
ARG NGINX_SHA256=c6b5c6b086c0df9d3ca3ff5e084c1d0ef909e6038279c71c1c3e985f576ff76a

RUN apk add --no-cache build-base perl linux-headers pcre2-dev zlib-dev curl

WORKDIR /src

# ---- OpenSSL ----
RUN curl -fsSLo openssl.tar.gz \
      "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz" \
 && echo "${OPENSSL_SHA256}  openssl.tar.gz" | sha256sum -c - \
 && tar xzf openssl.tar.gz \
 && cd "openssl-${OPENSSL_VERSION}" \
 && ./config --prefix=/opt/openssl --openssldir=/opt/openssl/ssl --libdir=lib \
      -Wl,-rpath,/opt/openssl/lib no-docs no-tests \
 && make -j"$(nproc)" \
 && make install_sw install_ssldirs

# ---- nginx ---- (nginx.org, with Ubuntu's byte-identical mirror of the release as fallback)
RUN ( curl -fsSLo nginx.tar.gz "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz" \
   || curl -fsSLo nginx.tar.gz "https://archive.ubuntu.com/ubuntu/pool/main/n/nginx/nginx_${NGINX_VERSION}.orig.tar.gz" ) \
 && echo "${NGINX_SHA256}  nginx.tar.gz" | sha256sum -c - \
 && tar xzf nginx.tar.gz \
 && cd "nginx-${NGINX_VERSION}" \
 && ./configure --prefix=/etc/nginx --sbin-path=/usr/local/sbin/nginx \
      --conf-path=/etc/nginx/nginx.conf --pid-path=/tmp/nginx.pid \
      --http-client-body-temp-path=/tmp/client_body \
      --with-http_ssl_module --with-http_v2_module \
      --with-cc-opt="-I/opt/openssl/include" \
      --with-ld-opt="-L/opt/openssl/lib -Wl,-rpath,/opt/openssl/lib" \
 && make -j"$(nproc)" && make install

# ---- hsbench (handshake benchmark) + sigbench (ML-DSA vs ECDSA) ----
COPY client/hsbench.c client/sigbench.c /src/
RUN cc -O2 -Wall -Wextra -I/opt/openssl/include -o /usr/local/bin/hsbench /src/hsbench.c \
      -L/opt/openssl/lib -Wl,-rpath,/opt/openssl/lib -lssl -lcrypto \
 && cc -O2 -Wall -Wextra -I/opt/openssl/include -o /usr/local/bin/sigbench /src/sigbench.c \
      -L/opt/openssl/lib -Wl,-rpath,/opt/openssl/lib -lcrypto

########################  runtime stage  ########################
FROM alpine:${ALPINE_VERSION}

RUN apk add --no-cache pcre2 zlib iproute2 tcpdump \
 && mkdir -p /etc/pqc-lab/certs /results

COPY --from=build /opt/openssl /opt/openssl
COPY --from=build /usr/local/sbin/nginx /usr/local/sbin/nginx
COPY --from=build /etc/nginx /etc/nginx
COPY --from=build /usr/local/bin/hsbench /usr/local/bin/sigbench /usr/local/bin/
RUN ln -s /opt/openssl/bin/openssl /usr/local/bin/openssl

COPY server/nginx.conf /etc/nginx/nginx.conf
COPY server/gen-certs.sh server/entrypoint.sh scripts/run-bench.sh scripts/capture.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/*.sh

# Fail the build loudly if the PQC algorithms are not actually available.
RUN openssl version \
 && openssl list -kem-algorithms | grep -q X25519MLKEM768 \
 && openssl list -signature-algorithms | grep -q ML-DSA-65 \
 && nginx -V 2>&1 | grep -q "OpenSSL 3.5"

EXPOSE 8443 8444 8445 8446
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
