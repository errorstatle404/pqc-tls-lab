/*
 * hsbench — TLS 1.3 handshake benchmark for the PQC TLS lab.
 *
 * Performs N full handshakes (no resumption) against host:port with a chosen
 * client group list, and reports:
 *   - negotiated key-exchange group and peer signature algorithm
 *   - whether a HelloRetryRequest happened (extra round trip)
 *   - size of key handshake messages (ClientHello, ServerHello, Certificate,
 *     CertificateVerify) and total TLS record bytes each direction
 *   - handshake latency (median / p95), measured from first byte sent to
 *     handshake completion, excluding TCP connect
 *
 * Output: one CSV line on stdout (use -H to print the header first).
 * Build:  cc -O2 -o hsbench hsbench.c -lssl -lcrypto   (OpenSSL >= 3.5)
 */
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

typedef struct {
    long ch_bytes;        /* ClientHello message(s), summed if HRR */
    long sh_bytes;        /* final ServerHello */
    long cert_bytes;      /* Certificate message */
    long cv_bytes;        /* CertificateVerify message */
    long rec_c2s;         /* TLS record bytes client->server (incl. 5-byte headers) */
    long rec_s2c;         /* TLS record bytes server->client */
    int server_hellos;    /* 2 => HelloRetryRequest occurred */
    int sigscheme;        /* TLS SignatureScheme from CertificateVerify */
} stats_t;

/* IANA TLS SignatureScheme names for the schemes this lab can produce */
static const char *sigscheme_name(int s, char *buf, size_t n) {
    switch (s) {
    case 0x0403: return "ecdsa_secp256r1_sha256";
    case 0x0503: return "ecdsa_secp384r1_sha384";
    case 0x0804: return "rsa_pss_rsae_sha256";
    case 0x0807: return "ed25519";
    case 0x0904: return "mldsa44";
    case 0x0905: return "mldsa65";
    case 0x0906: return "mldsa87";
    case 0: return "-";
    }
    snprintf(buf, n, "0x%04x", s);
    return buf;
}

static void msg_cb(int write_p, int version, int content_type, const void *buf,
                   size_t len, SSL *ssl, void *arg) {
    (void)version; (void)ssl;
    stats_t *st = (stats_t *)arg;
    const unsigned char *p = (const unsigned char *)buf;

    if (content_type == SSL3_RT_HEADER && len >= 5) {
        long rec = 5 + ((long)p[3] << 8 | p[4]);
        if (write_p) st->rec_c2s += rec; else st->rec_s2c += rec;
        return;
    }
    if (content_type != SSL3_RT_HANDSHAKE || len < 4) return;
    switch (p[0]) {
    case 1:  if (write_p) st->ch_bytes += (long)len; break;          /* ClientHello */
    case 2:  if (!write_p) { st->server_hellos++; st->sh_bytes = (long)len; } break;
    case 11: if (!write_p) st->cert_bytes = (long)len; break;        /* Certificate */
    case 15:                                                         /* CertificateVerify */
        if (!write_p) {
            st->cv_bytes = (long)len;
            if (len >= 6) st->sigscheme = p[4] << 8 | p[5];
        }
        break;
    }
}

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e3 + ts.tv_nsec / 1e6;
}

static int tcp_connect(const char *host, const char *port) {
    struct addrinfo hints = {0}, *res, *rp;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &res) != 0) return -1;
    int fd = -1;
    for (rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    if (fd >= 0) { int one = 1; setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one); }
    return fd;
}

static int cmp_d(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

static void usage(const char *argv0) {
    fprintf(stderr,
        "usage: %s [-H] -n NAME -c HOST:PORT [-g GROUPS] [-C CAFILE] [-N ITER] [-s SNI]\n"
        "  -g  client group list, OpenSSL syntax (default: library default)\n"
        "  -N  handshakes to run (default 50)\n"
        "  -H  print CSV header first\n", argv0);
    exit(2);
}

int main(int argc, char **argv) {
    const char *name = NULL, *target = NULL, *groups = NULL, *cafile = NULL, *sni = "pqc-lab.local";
    int iters = 50, header = 0, opt;
    while ((opt = getopt(argc, argv, "Hn:c:g:C:N:s:")) != -1) {
        switch (opt) {
        case 'H': header = 1; break;
        case 'n': name = optarg; break;
        case 'c': target = optarg; break;
        case 'g': groups = optarg; break;
        case 'C': cafile = optarg; break;
        case 'N': iters = atoi(optarg); break;
        case 's': sni = optarg; break;
        default: usage(argv[0]);
        }
    }
    if (header)
        puts("scenario,target,client_groups,result,group,hrr,peer_sig,"
             "clienthello_B,serverhello_B,certificate_B,certverify_B,"
             "bytes_c2s,bytes_s2c,median_ms,p95_ms,n");
    if (!name || !target) { if (header) return 0; usage(argv[0]); }
    if (iters < 1) iters = 1;

    char host[256], port[16];
    const char *colon = strrchr(target, ':');
    if (!colon) usage(argv[0]);
    snprintf(host, sizeof host, "%.*s", (int)(colon - target), target);
    snprintf(port, sizeof port, "%s", colon + 1);

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
    if (groups && SSL_CTX_set1_groups_list(ctx, groups) != 1) {
        fprintf(stderr, "invalid group list: %s\n", groups);
        return 2;
    }
    if (cafile) {
        SSL_CTX_load_verify_locations(ctx, cafile, NULL);
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    }

    double *lat = calloc((size_t)iters, sizeof(double));
    stats_t st = {0};
    char group[64] = "-", sig[64] = "-", result[160] = "ok";
    int done = 0;

    for (int i = 0; i < iters; i++) {
        int fd = tcp_connect(host, port);
        if (fd < 0) { snprintf(result, sizeof result, "tcp-connect-failed"); break; }
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, fd);
        SSL_set_tlsext_host_name(ssl, sni);
        if (cafile) SSL_set1_host(ssl, sni);
        memset(&st, 0, sizeof st);
        SSL_set_msg_callback(ssl, msg_cb);
        SSL_set_msg_callback_arg(ssl, &st);

        double t0 = now_ms();
        int rc = SSL_connect(ssl);
        double t1 = now_ms();

        if (rc != 1) {
            unsigned long e = ERR_peek_last_error();
            char buf[120];
            ERR_error_string_n(e, buf, sizeof buf);
            /* keep only the reason text, e.g. "tls alert handshake failure" */
            const char *r = strrchr(buf, ':');
            snprintf(result, sizeof result, "FAIL: %s", r ? r + 1 : buf);
            ERR_clear_error();
            SSL_free(ssl); close(fd);
            break;
        }
        lat[done++] = t1 - t0;
        if (i == 0) {
            const char *g = SSL_get0_group_name(ssl);
            snprintf(group, sizeof group, "%s", g ? g : "?");
            char tmp[16];
            snprintf(sig, sizeof sig, "%s", sigscheme_name(st.sigscheme, tmp, sizeof tmp));
        }
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(fd);
    }

    double med = 0, p95 = 0;
    if (done) {
        qsort(lat, (size_t)done, sizeof(double), cmp_d);
        med = lat[done / 2];
        p95 = lat[(int)((done - 1) * 0.95)];
    }
    printf("%s,%s,%s,%s,%s,%s,%s,%ld,%ld,%ld,%ld,%ld,%ld,%.3f,%.3f,%d\n",
           name, target, groups ? groups : "(default)", result, group,
           st.server_hellos >= 2 ? "yes" : "no", sig,
           st.ch_bytes, st.sh_bytes, st.cert_bytes, st.cv_bytes,
           st.rec_c2s, st.rec_s2c, med, p95, done);
    free(lat);
    SSL_CTX_free(ctx);
    return done ? 0 : 1;
}
