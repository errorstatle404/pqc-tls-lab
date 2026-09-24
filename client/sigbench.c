/*
 * sigbench — sign/verify speed and size for ECDSA P-256 vs ML-DSA (FIPS 204).
 *
 * `openssl speed` in 3.5.x cannot benchmark ML-DSA ("provider signature not
 * supported"), so this does it directly through the EVP API.
 *
 * Build: cc -O2 -o sigbench sigbench.c -lcrypto   (OpenSSL >= 3.5)
 */
#define _POSIX_C_SOURCE 200809L
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static double now_s(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

static EVP_PKEY *keygen(const char *alg) {
    if (strcmp(alg, "EC-P256") == 0)
        return EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
    return EVP_PKEY_Q_keygen(NULL, NULL, alg);
}

static void bench(const char *label, const char *alg, double secs) {
    EVP_PKEY *k = keygen(alg);
    if (!k) { printf("%-12s  (not available)\n", label); return; }
    const char *md = strcmp(alg, "EC-P256") == 0 ? "SHA256" : NULL;  /* ML-DSA signs the message directly */

    unsigned char msg[32] = "TLS 1.3 CertificateVerify input";
    unsigned char sig[8192];
    size_t siglen = 0;
    long nsign = 0, nver = 0;

    double t0 = now_s(), t;
    do {
        EVP_MD_CTX *c = EVP_MD_CTX_new();
        siglen = sizeof sig;
        EVP_DigestSignInit_ex(c, NULL, md, NULL, NULL, k, NULL);
        EVP_DigestSign(c, sig, &siglen, msg, sizeof msg);
        EVP_MD_CTX_free(c);
        nsign++;
    } while ((t = now_s() - t0) < secs);
    double sign_s = nsign / t;

    t0 = now_s();
    int ok = 1;
    do {
        EVP_MD_CTX *c = EVP_MD_CTX_new();
        EVP_DigestVerifyInit_ex(c, NULL, md, NULL, NULL, k, NULL);
        ok &= EVP_DigestVerify(c, sig, siglen, msg, sizeof msg) == 1;
        EVP_MD_CTX_free(c);
        nver++;
    } while ((t = now_s() - t0) < secs);
    double ver_s = nver / t;

    int publen = i2d_PUBKEY(k, NULL);   /* SubjectPublicKeyInfo DER, as it appears in a cert */
    printf("%-12s %10.0f %10.0f %10d %10zu %s\n", label, sign_s, ver_s, publen, siglen,
           ok ? "" : "VERIFY-FAILED");
    EVP_PKEY_free(k);
}

int main(int argc, char **argv) {
    double secs = argc > 1 ? atof(argv[1]) : 2.0;
    printf("%-12s %10s %10s %10s %10s\n", "algorithm", "sign/s", "verify/s", "pubkey_B", "sig_B");
    bench("ECDSA-P256", "EC-P256", secs);
    bench("ML-DSA-44", "ML-DSA-44", secs);
    bench("ML-DSA-65", "ML-DSA-65", secs);
    bench("ML-DSA-87", "ML-DSA-87", secs);
    return 0;
}
