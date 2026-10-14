"""What the inventory knows about algorithms: which are quantum-vulnerable and how to name them.

Quantum status values:
  "vulnerable"  broken by a large quantum computer (Shor): RSA, ECDH, ECDSA, EdDSA, finite-field DH
  "hybrid"      classical + ML-KEM combined: secure if either part holds
  "resistant"   NIST post-quantum standards (FIPS 203/204/205) and large symmetric keys
  "weakened"    symmetric/hash with reduced margin under Grover (e.g. AES-128): not an urgent migration item
  "unknown"
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Algo:
    ref: str            # stable bom-ref / display name
    primitive: str      # CycloneDX 1.6 primitive: kem, key-agree, signature, ae, block-cipher, ...
    quantum: str        # vulnerable | hybrid | resistant | weakened | unknown
    nist_level: int     # CycloneDX nistQuantumSecurityLevel (0 = none against a quantum adversary)
    classical_bits: int = 0
    oid: str | None = None
    note: str = ""


# ---- TLS key-exchange groups (names as OpenSSL / IANA report them) ----
_GROUPS = {
    "x25519": Algo("X25519", "key-agree", "vulnerable", 0, 128, "1.3.101.110"),
    "x448": Algo("X448", "key-agree", "vulnerable", 0, 224, "1.3.101.111"),
    "secp256r1": Algo("ECDH-P256", "key-agree", "vulnerable", 0, 128, "1.2.840.10045.3.1.7"),
    "prime256v1": Algo("ECDH-P256", "key-agree", "vulnerable", 0, 128, "1.2.840.10045.3.1.7"),
    "secp384r1": Algo("ECDH-P384", "key-agree", "vulnerable", 0, 192, "1.3.132.0.34"),
    "secp521r1": Algo("ECDH-P521", "key-agree", "vulnerable", 0, 256, "1.3.132.0.35"),
    "ffdhe2048": Algo("FFDHE2048", "key-agree", "vulnerable", 0, 112),
    "ffdhe3072": Algo("FFDHE3072", "key-agree", "vulnerable", 0, 128),
    "x25519mlkem768": Algo("X25519MLKEM768", "kem", "hybrid", 3, 128,
                           note="IETF draft-ietf-tls-ecdhe-mlkem, codepoint 0x11EC"),
    "secp256r1mlkem768": Algo("SecP256r1MLKEM768", "kem", "hybrid", 3, 128,
                              note="IETF draft-ietf-tls-ecdhe-mlkem, codepoint 0x11EB"),
    "secp384r1mlkem1024": Algo("SecP384r1MLKEM1024", "kem", "hybrid", 5, 192,
                               note="IETF draft-ietf-tls-ecdhe-mlkem, codepoint 0x11ED"),
    "mlkem512": Algo("ML-KEM-512", "kem", "resistant", 1, 128, "2.16.840.1.101.3.4.4.1"),
    "mlkem768": Algo("ML-KEM-768", "kem", "resistant", 3, 192, "2.16.840.1.101.3.4.4.2"),
    "mlkem1024": Algo("ML-KEM-1024", "kem", "resistant", 5, 256, "2.16.840.1.101.3.4.4.3"),
}


def group(name: str | None) -> Algo | None:
    if not name or name in ("-", "?"):
        return None
    key = name.lower().replace("-", "").replace("_", "")
    return _GROUPS.get(key) or Algo(name, "key-agree", "unknown", 0)


# ---- Certificate public keys and signatures ----
def cert_key(key_alg: str, bits: str | int | None = None) -> Algo:
    """key_alg as printed by `openssl x509 -text` (probe.sh) or ACM KeyAlgorithm."""
    k = (key_alg or "").strip()
    kl = k.lower()
    try:
        b = int(bits) if bits not in (None, "", "-") else 0
    except ValueError:
        b = 0
    if kl in ("rsaencryption", "rsa") or kl.startswith("rsa_") or kl.startswith("rsa-"):
        if not b:
            digits = "".join(c for c in k if c.isdigit())
            b = int(digits) if digits else 0
        return Algo(f"RSA-{b}" if b else "RSA", "pke", "vulnerable", 0, _rsa_strength(b), "1.2.840.113549.1.1.1")
    if kl.startswith("ec:") or kl.startswith("ec_") or kl == "id-ecpublickey":
        curve = k.split(":", 1)[-1].split("_", 1)[-1]
        name = {"prime256v1": "P-256", "secp256r1": "P-256", "secp384r1": "P-384",
                "secp521r1": "P-521"}.get(curve.lower(), curve)
        strength = {"P-256": 128, "P-384": 192, "P-521": 256}.get(name, 0)
        return Algo(f"EC-{name}", "signature", "vulnerable", 0, strength, "1.2.840.10045.2.1")
    if kl in ("ed25519",):
        return Algo("Ed25519", "signature", "vulnerable", 0, 128, "1.3.101.112")
    if kl in ("ed448",):
        return Algo("Ed448", "signature", "vulnerable", 0, 224, "1.3.101.113")
    for lvl, n in ((2, "44"), (3, "65"), (5, "87")):
        if kl in (f"ml-dsa-{n}", f"ml_dsa_{n}", f"mldsa{n}"):
            return Algo(f"ML-DSA-{n}", "signature", "resistant", lvl, oid=_MLDSA_OID[n])
    if kl.startswith("slh-dsa") or kl.startswith("slh_dsa"):
        return Algo(k.upper().replace("_", "-"), "signature", "resistant", 1)
    return Algo(k or "unknown", "other", "unknown", 0)


def signature(sig_alg: str) -> Algo:
    """X.509 signature algorithm as printed by OpenSSL, or a TLS SignatureScheme name."""
    s = (sig_alg or "").strip()
    sl = s.lower()
    if "ml-dsa" in sl or sl.startswith("mldsa"):
        n = "".join(c for c in sl if c.isdigit())[-2:]
        return Algo(f"ML-DSA-{n}", "signature", "resistant", {"44": 2, "65": 3, "87": 5}.get(n, 0),
                    oid=_MLDSA_OID.get(n))
    if "slh-dsa" in sl or "sphincs" in sl:
        return Algo(s, "signature", "resistant", 1)
    h = "SHA1" if sl.startswith("sha1") else "SHA384" if "384" in sl else "SHA512" if "512" in sl else "SHA256"
    if "ecdsa" in sl:
        return Algo(f"ECDSA-{h}", "signature", "vulnerable", 0, 128,
                    {"SHA256": "1.2.840.10045.4.3.2", "SHA384": "1.2.840.10045.4.3.3",
                     "SHA512": "1.2.840.10045.4.3.4"}.get(h))
    if "rsa" in sl:
        pss = "pss" in sl
        return Algo(f"RSA{'-PSS' if pss else ''}-{h}", "signature", "vulnerable", 0, 112)
    if "ed25519" in sl:
        return Algo("Ed25519", "signature", "vulnerable", 0, 128)
    if "ed448" in sl:
        return Algo("Ed448", "signature", "vulnerable", 0, 224)
    return Algo(s or "unknown", "signature", "unknown", 0)


_MLDSA_OID = {"44": "2.16.840.1.101.3.4.3.17", "65": "2.16.840.1.101.3.4.3.18", "87": "2.16.840.1.101.3.4.3.19"}


def _rsa_strength(bits: int) -> int:
    return 80 if bits < 2048 else 112 if bits < 3072 else 128 if bits < 7680 else 192


# ---- AWS KMS key specs ----
def kms_key_spec(spec: str) -> Algo:
    s = spec or ""
    if s == "SYMMETRIC_DEFAULT":
        return Algo("AES-256-GCM", "ae", "resistant", 5, 256, note="AES-256: Grover leaves ~128-bit security")
    if s.startswith("HMAC_"):
        return Algo(s.replace("_", "-"), "mac", "resistant", 1)
    if s.startswith("RSA_"):
        b = int(s.split("_")[1])
        return Algo(f"RSA-{b}", "pke", "vulnerable", 0, _rsa_strength(b))
    if s.startswith("ECC_"):
        curve = {"ECC_NIST_P256": "P-256", "ECC_NIST_P384": "P-384", "ECC_NIST_P521": "P-521",
                 "ECC_SECG_P256K1": "secp256k1", "ECC_NIST_EDWARDS25519": "Ed25519"}.get(s, s)
        return Algo(f"EC-{curve}", "signature", "vulnerable", 0)
    if s.startswith("SM2"):
        return Algo("SM2", "signature", "vulnerable", 0)
    if s.startswith("ML_DSA_"):
        n = s.split("_")[-1]
        return Algo(f"ML-DSA-{n}", "signature", "resistant", {"44": 2, "65": 3, "87": 5}.get(n, 0))
    return Algo(s or "unknown", "other", "unknown", 0)


# ---- AWS ACM key algorithms ----
def acm_key(key_algorithm: str) -> Algo:
    k = key_algorithm or ""
    if k.startswith("RSA_"):
        return cert_key("rsa", k.split("_")[1])
    if k.startswith("EC_"):
        return cert_key("EC:" + k[3:])
    if k.startswith("ML_DSA_"):
        return cert_key(k)
    return Algo(k or "unknown", "other", "unknown", 0)


# ---- TLS protocol versions ----
LEGACY_TLS = ("tls1", "tls1_1")  # TLS 1.0 / 1.1: deprecated (RFC 8996)
VERSION_LABEL = {"tls1": "TLS 1.0", "tls1_1": "TLS 1.1", "tls1_2": "TLS 1.2", "tls1_3": "TLS 1.3"}
