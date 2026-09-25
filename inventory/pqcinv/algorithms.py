"""Catalog of the algorithms the inventory can report, with their quantum status.

Everything that ends up in the CBOM goes through `lookup()`, so names seen on the wire
(OpenSSL's spelling), in AWS APIs (KMS key specs, ACM key algorithms) and in certificates
all resolve to one entry.

Quantum status:
  "pq"         post-quantum (ML-KEM, ML-DSA), or a hybrid that includes one
  "vulnerable" broken by a large quantum computer (RSA, ECDH, ECDSA, EdDSA, finite-field DH)
  "adequate"   symmetric or hash; Grover's algorithm only halves the security level
  "unknown"    not in this catalog
"""
from __future__ import annotations

from dataclasses import dataclass, field
import re


@dataclass(frozen=True)
class Algorithm:
    key: str                      # stable id, used in the CBOM bom-ref
    name: str                     # display name
    primitive: str                # CycloneDX algorithmProperties.primitive
    quantum: str                  # pq | vulnerable | adequate | unknown
    classical_bits: int | None = None
    nist_level: int = 0           # CycloneDX nistQuantumSecurityLevel (0 = none)
    functions: tuple = ()
    oid: str | None = None
    parameter_set: str | None = None
    curve: str | None = None
    aliases: tuple = field(default_factory=tuple)


_CATALOG = [
    # ---- TLS key exchange groups ----
    Algorithm("x25519mlkem768", "X25519MLKEM768", "kem", "pq", 128, 3,
              ("keygen", "encapsulate", "decapsulate"), parameter_set="768",
              aliases=("x25519mlkem768", "x25519_mlkem768")),
    Algorithm("secp256r1mlkem768", "SecP256r1MLKEM768", "kem", "pq", 128, 3,
              ("keygen", "encapsulate", "decapsulate"), parameter_set="768",
              aliases=("secp256r1mlkem768", "p256mlkem768")),
    Algorithm("secp384r1mlkem1024", "SecP384r1MLKEM1024", "kem", "pq", 192, 5,
              ("keygen", "encapsulate", "decapsulate"), parameter_set="1024",
              aliases=("secp384r1mlkem1024", "p384mlkem1024")),
    Algorithm("mlkem512", "ML-KEM-512", "kem", "pq", 128, 1,
              ("keygen", "encapsulate", "decapsulate"), "2.16.840.1.101.3.4.4.1", "512",
              aliases=("mlkem512", "ml-kem-512")),
    Algorithm("mlkem768", "ML-KEM-768", "kem", "pq", 192, 3,
              ("keygen", "encapsulate", "decapsulate"), "2.16.840.1.101.3.4.4.2", "768",
              aliases=("mlkem768", "ml-kem-768")),
    Algorithm("mlkem1024", "ML-KEM-1024", "kem", "pq", 256, 5,
              ("keygen", "encapsulate", "decapsulate"), "2.16.840.1.101.3.4.4.3", "1024",
              aliases=("mlkem1024", "ml-kem-1024")),
    Algorithm("x25519", "X25519", "key-agree", "vulnerable", 128, 0, ("keygen", "keyderive"),
              "1.3.101.110", curve="Curve25519", aliases=("x25519",)),
    Algorithm("x448", "X448", "key-agree", "vulnerable", 224, 0, ("keygen", "keyderive"),
              "1.3.101.111", curve="Curve448", aliases=("x448",)),
    Algorithm("ecdh-p256", "ECDH P-256", "key-agree", "vulnerable", 128, 0, ("keygen", "keyderive"),
              curve="secp256r1", aliases=("secp256r1", "prime256v1", "p-256", "ecdh_p256")),
    Algorithm("ecdh-p384", "ECDH P-384", "key-agree", "vulnerable", 192, 0, ("keygen", "keyderive"),
              curve="secp384r1", aliases=("secp384r1", "p-384", "ecdh_p384")),
    Algorithm("ecdh-p521", "ECDH P-521", "key-agree", "vulnerable", 256, 0, ("keygen", "keyderive"),
              curve="secp521r1", aliases=("secp521r1", "p-521", "ecdh_p521")),
    Algorithm("ffdhe2048", "FFDHE-2048", "key-agree", "vulnerable", 112, 0, ("keygen", "keyderive"),
              aliases=("ffdhe2048", "dh")),

    # ---- Signatures (certificates, CertificateVerify, KMS keys) ----
    Algorithm("mldsa44", "ML-DSA-44", "signature", "pq", 128, 2, ("sign", "verify"),
              "2.16.840.1.101.3.4.3.17", "44", aliases=("mldsa44", "ml-dsa-44", "ml_dsa_44")),
    Algorithm("mldsa65", "ML-DSA-65", "signature", "pq", 192, 3, ("sign", "verify"),
              "2.16.840.1.101.3.4.3.18", "65", aliases=("mldsa65", "ml-dsa-65", "ml_dsa_65")),
    Algorithm("mldsa87", "ML-DSA-87", "signature", "pq", 256, 5, ("sign", "verify"),
              "2.16.840.1.101.3.4.3.19", "87", aliases=("mldsa87", "ml-dsa-87", "ml_dsa_87")),
    Algorithm("ecdsa-p256", "ECDSA P-256", "signature", "vulnerable", 128, 0, ("sign", "verify"),
              "1.2.840.10045.4.3.2", curve="secp256r1",
              aliases=("ecdsa_secp256r1_sha256", "ecdsa-with-sha256", "ec-prime256v1", "ecc_nist_p256",
                       "ec_prime256v1", "ec/prime256v1")),
    Algorithm("ecdsa-p384", "ECDSA P-384", "signature", "vulnerable", 192, 0, ("sign", "verify"),
              "1.2.840.10045.4.3.3", curve="secp384r1",
              aliases=("ecdsa_secp384r1_sha384", "ecdsa-with-sha384", "ec-secp384r1", "ecc_nist_p384",
                       "ec_secp384r1", "ec/secp384r1")),
    Algorithm("ecdsa-p521", "ECDSA P-521", "signature", "vulnerable", 256, 0, ("sign", "verify"),
              curve="secp521r1",
              aliases=("ecdsa_secp521r1_sha512", "ecdsa-with-sha512", "ec-secp521r1", "ecc_nist_p521",
                       "ec_secp521r1", "ec/secp521r1")),
    Algorithm("ecdsa-secp256k1", "ECDSA secp256k1", "signature", "vulnerable", 128, 0, ("sign", "verify"),
              curve="secp256k1", aliases=("ecc_secg_p256k1",)),
    Algorithm("ed25519", "Ed25519", "signature", "vulnerable", 128, 0, ("sign", "verify"),
              "1.3.101.112", aliases=("ed25519", "ecc_nist_edwards25519")),
    Algorithm("rsa-2048", "RSA-2048", "signature", "vulnerable", 112, 0, ("sign", "verify", "encrypt", "decrypt"),
              "1.2.840.113549.1.1.1", parameter_set="2048",
              aliases=("rsa-2048", "rsa_2048", "rsa/2048")),
    Algorithm("rsa-3072", "RSA-3072", "signature", "vulnerable", 128, 0, ("sign", "verify", "encrypt", "decrypt"),
              "1.2.840.113549.1.1.1", parameter_set="3072",
              aliases=("rsa-3072", "rsa_3072", "rsa/3072")),
    Algorithm("rsa-4096", "RSA-4096", "signature", "vulnerable", 152, 0, ("sign", "verify", "encrypt", "decrypt"),
              "1.2.840.113549.1.1.1", parameter_set="4096",
              aliases=("rsa-4096", "rsa_4096", "rsa/4096")),
    Algorithm("rsa", "RSA", "signature", "vulnerable", None, 0, ("sign", "verify"),
              "1.2.840.113549.1.1.1",
              aliases=("rsa_pss_rsae_sha256", "rsa_pss_rsae_sha384", "rsa_pss_rsae_sha512",
                       "rsa_pkcs1_sha256", "rsa_pkcs1_sha384", "rsa_pkcs1_sha512",
                       "sha256withrsaencryption", "sha384withrsaencryption", "rsa")),
    Algorithm("sm2", "SM2", "signature", "vulnerable", 128, 0, ("sign", "verify", "encrypt", "decrypt"),
              aliases=("sm2",)),

    # ---- Symmetric (TLS record protection, KMS symmetric keys) ----
    Algorithm("aes-128-gcm", "AES-128-GCM", "ae", "adequate", 128, 1, ("encrypt", "decrypt"),
              aliases=("tls_aes_128_gcm_sha256", "aes128-gcm", "aes-128-gcm")),
    Algorithm("aes-256-gcm", "AES-256-GCM", "ae", "adequate", 256, 5, ("encrypt", "decrypt"),
              aliases=("tls_aes_256_gcm_sha384", "aes256-gcm", "aes-256-gcm", "symmetric_default")),
    Algorithm("chacha20-poly1305", "ChaCha20-Poly1305", "ae", "adequate", 256, 5, ("encrypt", "decrypt"),
              aliases=("tls_chacha20_poly1305_sha256", "chacha20-poly1305")),
    Algorithm("hmac-sha256", "HMAC-SHA256", "mac", "adequate", 256, 0, ("tag",), aliases=("hmac_256",)),
    Algorithm("hmac-sha384", "HMAC-SHA384", "mac", "adequate", 384, 0, ("tag",), aliases=("hmac_384",)),
    Algorithm("hmac-sha512", "HMAC-SHA512", "mac", "adequate", 512, 0, ("tag",), aliases=("hmac_512",)),
    Algorithm("hmac-sha224", "HMAC-SHA224", "mac", "adequate", 224, 0, ("tag",), aliases=("hmac_224",)),
]

_BY_ALIAS: dict[str, Algorithm] = {}
for _a in _CATALOG:
    for _name in (_a.key, _a.name.lower(), *_a.aliases):
        _BY_ALIAS[_name.lower()] = _a


def _norm(name: str) -> str:
    return re.sub(r"\s+", "", name.strip().lower())


def lookup(name: str | None) -> Algorithm | None:
    """Find an algorithm by any spelling OpenSSL, AWS or a certificate uses."""
    if not name:
        return None
    n = _norm(name)
    if n in _BY_ALIAS:
        return _BY_ALIAS[n]
    # OpenSSL cert key descriptions: "EC, (prime256v1)", "RSA, 2048 (bit)", "ML-DSA-65, 15616 (bit)"
    m = re.match(r"^ec,\(?([a-z0-9-]+)\)?", n)
    if m:
        return _BY_ALIAS.get("ec/" + m.group(1))
    m = re.match(r"^rsa,(\d+)", n)
    if m:
        return _BY_ALIAS.get("rsa/" + m.group(1)) or _BY_ALIAS["rsa"]
    m = re.match(r"^(ml-dsa-\d+|mldsa\d+|ed25519)", n)
    if m:
        return _BY_ALIAS.get(m.group(1))
    # ECDHE-ECDSA-AES256-GCM-SHA384 style TLS 1.2 suites -> the bulk cipher
    if "aes256-gcm" in n or "aes_256_gcm" in n:
        return _BY_ALIAS["aes-256-gcm"]
    if "aes128-gcm" in n or "aes_128_gcm" in n:
        return _BY_ALIAS["aes-128-gcm"]
    if "chacha20" in n:
        return _BY_ALIAS["chacha20-poly1305"]
    return None


def quantum_status(name: str | None) -> str:
    a = lookup(name)
    return a.quantum if a else "unknown"


def is_pq(name: str | None) -> bool:
    return quantum_status(name) == "pq"


def display(name: str | None) -> str:
    a = lookup(name)
    return a.name if a else (name or "")
