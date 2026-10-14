"""CycloneDX 1.6 Cryptography Bill of Materials (CBOM) from the inventory."""
from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone

from . import __version__, algorithms
from .algorithms import Algo
from .probes import Endpoint

KMS_STATE = {"Enabled": "active", "Disabled": "suspended", "PendingImport": "pre-activation",
             "PendingDeletion": "deactivated", "Unavailable": "suspended", "Creating": "pre-activation"}

FUNCTIONS = {
    "kem": ["keygen", "encapsulate", "decapsulate"],
    "key-agree": ["keygen", "keyderive"],
    "signature": ["sign", "verify"],
    "pke": ["encrypt", "decrypt", "sign", "verify"],
    "ae": ["encrypt", "decrypt"],
    "mac": ["tag"],
}


class _Builder:
    def __init__(self):
        self.components: dict[str, dict] = {}

    def algorithm(self, a: Algo) -> str:
        ref = f"crypto/algorithm/{a.ref}"
        if ref not in self.components:
            props = {"primitive": a.primitive if a.primitive in (
                "drbg", "mac", "block-cipher", "stream-cipher", "signature", "hash", "pke", "xof", "kdf",
                "key-agree", "kem", "ae", "combiner", "other") else "other",
                "nistQuantumSecurityLevel": a.nist_level}
            if a.classical_bits:
                props["classicalSecurityLevel"] = a.classical_bits
            if a.primitive in FUNCTIONS:
                props["cryptoFunctions"] = FUNCTIONS[a.primitive]
            cp = {"assetType": "algorithm", "algorithmProperties": props}
            if a.oid:
                cp["oid"] = a.oid
            comp = {"type": "cryptographic-asset", "bom-ref": ref, "name": a.ref, "cryptoProperties": cp,
                    "properties": [{"name": "cryptoinv:quantum", "value": a.quantum}]}
            if a.note:
                comp["description"] = a.note
            self.components[ref] = comp
        return ref

    def public_key(self, a: Algo, bits: int | None) -> str:
        alg_ref = self.algorithm(a)
        ref = f"crypto/public-key/{a.ref}"
        if ref not in self.components:
            rcp = {"type": "public-key", "algorithmRef": alg_ref}
            if bits:
                rcp["size"] = bits
            self.components[ref] = {"type": "cryptographic-asset", "bom-ref": ref, "name": f"{a.ref} public key",
                                    "cryptoProperties": {"assetType": "related-crypto-material",
                                                         "relatedCryptoMaterialProperties": rcp}}
        return ref

    def certificate(self, *, subject, issuer, not_before, not_after, sig: Algo, key: Algo, key_bits,
                    ident: str, source: str, extra_props=None) -> str:
        ref = "crypto/certificate/" + hashlib.sha256(ident.encode()).hexdigest()[:16]
        if ref not in self.components:
            cert = {"subjectName": subject, "issuerName": issuer, "certificateFormat": "X.509",
                    "signatureAlgorithmRef": self.algorithm(sig),
                    "subjectPublicKeyRef": self.public_key(key, key_bits)}
            if not_before:
                cert["notValidBefore"] = not_before
            if not_after:
                cert["notValidAfter"] = not_after
            props = [{"name": "cryptoinv:source", "value": source},
                     {"name": "cryptoinv:quantum", "value": key.quantum}] + (extra_props or [])
            self.components[ref] = {"type": "cryptographic-asset", "bom-ref": ref,
                                    "name": _cn(subject) or subject or "certificate",
                                    "cryptoProperties": {"assetType": "certificate", "certificateProperties": cert},
                                    "properties": props}
        return ref


def _cn(dn: str) -> str:
    for part in (dn or "").replace(", ", ",").split(","):
        if part.upper().startswith("CN="):
            return part[3:]
    return ""


def _iso(d) -> str | None:
    if d is None:
        return None
    if isinstance(d, str):
        return d if "T" in d else None
    return d.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def build(eps: list[Endpoint], aws: dict | None = None, meta: dict | None = None) -> dict:
    b = _Builder()

    for ep in eps:
        if not ep.reachable:
            continue
        refs: list[str] = []
        for h in ep.handshakes.values():
            g = algorithms.group(h.group) if h.ok else None
            if g:
                refs.append(b.algorithm(g))
        chain_refs = []
        for c in ep.chain:
            key = algorithms.cert_key(c.key_alg, c.key_bits)
            bits = int(c.key_bits) if str(c.key_bits).isdigit() else None
            chain_refs.append(b.certificate(
                subject=c.subject, issuer=c.issuer, not_before=_iso(c.not_before), not_after=_iso(c.not_after),
                sig=algorithms.signature(c.sig_alg), key=key, key_bits=bits,
                ident=f"{c.subject}|{c.issuer}|{c.not_before}|{c.der_bytes}", source="network",
                extra_props=[{"name": "cryptoinv:der_bytes", "value": str(c.der_bytes)}]))
        refs += chain_refs
        for ver, (accepted, cipher) in sorted(ep.versions.items()):
            if not accepted:
                continue
            version = {"tls1": "1.0", "tls1_1": "1.1", "tls1_2": "1.2", "tls1_3": "1.3"}[ver]
            ref = f"crypto/protocol/tls{version}@{ep.host}:{ep.port}"
            pp = {"type": "tls", "version": version}
            if cipher and cipher != "-":
                pp["cipherSuites"] = [{"name": cipher}]
            if version == "1.3":
                pp["cryptoRefArray"] = sorted(set(refs))
            elif chain_refs:
                pp["cryptoRefArray"] = sorted(set(chain_refs))
            props = [{"name": "cryptoinv:endpoint", "value": f"{ep.host}:{ep.port}"},
                     {"name": "cryptoinv:label", "value": ep.label}]
            if version == "1.3":
                props += [{"name": "cryptoinv:pq_kex", "value": ep.pq_kex},
                          {"name": "cryptoinv:default_group", "value": ep.default_group or "-"},
                          {"name": "cryptoinv:pq_auth", "value": ep.pq_auth}]
            b.components[ref] = {"type": "cryptographic-asset", "bom-ref": ref,
                                 "name": f"TLS {version} {ep.host}:{ep.port}",
                                 "cryptoProperties": {"assetType": "protocol", "protocolProperties": pp},
                                 "properties": props}

    if aws:
        for c in aws.get("acm_certificates", []):
            key = algorithms.acm_key(c.get("KeyAlgorithm"))
            bits = key.classical_bits and int("".join(ch for ch in c.get("KeyAlgorithm", "") if ch.isdigit()) or 0) or None
            if c.get("KeyAlgorithm", "").startswith("EC_"):
                bits = {"EC_prime256v1": 256, "EC_secp384r1": 384, "EC_secp521r1": 521}.get(c["KeyAlgorithm"])
            b.certificate(
                subject=f"CN={c.get('DomainName')}", issuer=c.get("Issuer") or "", not_before=c.get("NotBefore"),
                not_after=c.get("NotAfter"), sig=algorithms.signature(c.get("SignatureAlgorithm") or ""),
                key=key, key_bits=bits, ident=c["CertificateArn"], source="aws-acm",
                extra_props=[{"name": "aws:arn", "value": c["CertificateArn"]},
                             {"name": "aws:acm:type", "value": str(c.get("Type"))},
                             {"name": "aws:acm:in_use_by", "value": str(len(c.get("InUseBy") or []))}])
        for k in aws.get("kms_keys", []):
            if k.get("KeyManager") != "CUSTOMER":
                continue
            a = algorithms.kms_key_spec(k.get("KeySpec"))
            alg_ref = b.algorithm(a)
            ref = f"crypto/kms-key/{k['KeyId']}"
            rcp = {"type": "secret-key" if k.get("KeySpec") == "SYMMETRIC_DEFAULT" or str(k.get("KeySpec", "")).startswith("HMAC")
                   else "private-key", "id": k["KeyId"], "algorithmRef": alg_ref,
                   "state": KMS_STATE.get(k.get("KeyState"), "active")}
            if k.get("CreationDate"):
                rcp["creationDate"] = _iso(datetime.fromisoformat(k["CreationDate"]))
            b.components[ref] = {"type": "cryptographic-asset", "bom-ref": ref,
                                 "name": (k.get("Aliases") or [k["KeyId"]])[0],
                                 "cryptoProperties": {"assetType": "related-crypto-material",
                                                      "relatedCryptoMaterialProperties": rcp},
                                 "properties": [{"name": "aws:arn", "value": k["Arn"]},
                                                {"name": "aws:kms:key_spec", "value": str(k.get("KeySpec"))},
                                                {"name": "aws:kms:key_usage", "value": str(k.get("KeyUsage"))},
                                                {"name": "cryptoinv:quantum", "value": a.quantum}]}

    md_props = [{"name": k if ":" in k else f"cryptoinv:probe:{k}", "value": str(v)} for k, v in (meta or {}).items()]
    if aws:
        md_props += [{"name": "aws:account", "value": str(aws.get("identity", {}).get("account", "?"))},
                     {"name": "aws:region", "value": str(aws.get("region"))}]
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
            "tools": {"components": [{"type": "application", "name": "cryptoinv", "version": __version__}]},
            "properties": md_props,
        },
        "components": sorted(b.components.values(), key=lambda c: c["bom-ref"]),
    }


def validate(bom_json: str) -> str | None:
    """Validate against the official CycloneDX 1.6 JSON schema. Returns an error message or None."""
    try:
        from cyclonedx.schema import SchemaVersion
        from cyclonedx.validation.json import JsonStrictValidator
    except ImportError:
        return "skipped: cyclonedx-python-lib not installed"
    err = JsonStrictValidator(SchemaVersion.V1_6).validate_str(bom_json)
    return str(err) if err else None
