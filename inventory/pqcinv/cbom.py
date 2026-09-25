"""CycloneDX 1.6 CBOM (Cryptography Bill of Materials) from the inventory.

Components:
  algorithm                 every algorithm seen (groups, signature schemes, cipher suites, key specs)
  protocol                  one per probed TLS endpoint, pointing at what it negotiated
  certificate               the certificate chain each endpoint served, plus ACM certificates
  related-crypto-material   KMS keys
"""
from __future__ import annotations

from datetime import datetime, timezone
import re
import uuid

from . import __version__, algorithms

SPEC_VERSION = "1.6"


def _slug(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._:-]+", "-", s).strip("-").lower()


def _openssl_date(s: str) -> str | None:
    """'Sep 25 10:20:09 2026 GMT' -> '2026-09-25T10:20:09Z'."""
    try:
        d = datetime.strptime(re.sub(r"\s+", " ", s.strip()), "%b %d %H:%M:%S %Y GMT")
        return d.strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, AttributeError):
        return None


def _iso(s: str) -> str | None:
    if not s:
        return None
    try:
        d = datetime.fromisoformat(str(s).replace("Z", "+00:00"))
        if d.tzinfo is None:
            d = d.replace(tzinfo=timezone.utc)
        return d.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return None


class _Builder:
    def __init__(self):
        self.components: dict[str, dict] = {}
        self.deps: dict[str, set] = {}

    def algorithm(self, name: str | None) -> str | None:
        if not name:
            return None
        a = algorithms.lookup(name)
        if a is None:
            ref = f"crypto/algorithm/unknown/{_slug(name)}"
            if ref not in self.components:
                self.components[ref] = {
                    "type": "cryptographic-asset", "bom-ref": ref, "name": name,
                    "cryptoProperties": {"assetType": "algorithm",
                                         "algorithmProperties": {"primitive": "unknown"}},
                    "properties": [{"name": "pqcinv:quantum-status", "value": "unknown"}],
                }
            return ref
        ref = f"crypto/algorithm/{a.key}"
        if ref not in self.components:
            props = {"primitive": a.primitive, "nistQuantumSecurityLevel": a.nist_level}
            if a.classical_bits:
                props["classicalSecurityLevel"] = a.classical_bits
            if a.functions:
                props["cryptoFunctions"] = list(a.functions)
            if a.parameter_set:
                props["parameterSetIdentifier"] = a.parameter_set
            if a.curve:
                props["curve"] = a.curve
            if a.primitive == "ae":
                props["mode"] = "gcm" if "gcm" in a.key else "other"
            cp = {"assetType": "algorithm", "algorithmProperties": props}
            if a.oid:
                cp["oid"] = a.oid
            self.components[ref] = {
                "type": "cryptographic-asset", "bom-ref": ref, "name": a.name,
                "cryptoProperties": cp,
                "properties": [{"name": "pqcinv:quantum-status", "value": a.quantum}],
            }
        return ref

    def depend(self, ref: str, *on: str | None):
        s = self.deps.setdefault(ref, set())
        s.update(o for o in on if o)

    def bom(self, scope: str, timestamp: str) -> dict:
        refs = set(self.components)
        deps = [{"ref": r, "dependsOn": sorted(d & refs)} for r, d in sorted(self.deps.items()) if r in refs]
        return {
            "bomFormat": "CycloneDX",
            "specVersion": SPEC_VERSION,
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": timestamp,
                "tools": {"components": [{"type": "application", "name": "pqc-inventory",
                                          "version": __version__}]},
                "component": {"type": "platform", "bom-ref": "scope", "name": scope},
            },
            "components": sorted(self.components.values(), key=lambda c: c["bom-ref"]),
            "dependencies": deps,
        }


def build_cbom(assessments: list, aws_inv: dict | None = None, scope: str = "pqc-inventory scan",
               timestamp: str | None = None) -> dict:
    timestamp = timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    b = _Builder()

    for a in assessments:
        ep = a.endpoint
        ref = f"crypto/protocol/tls/{_slug(ep)}"
        ok = [r for r in a.results.values() if r.ok]
        versions = sorted({r.protocol.replace("TLSv", "") for r in ok if r.protocol}, reverse=True)
        algo_refs, suites = [], {}
        for r in ok:
            algo_refs += [b.algorithm(r.group), b.algorithm(r.peer_sig)]
            if r.cipher and r.cipher not in suites:
                suites[r.cipher] = [x for x in [b.algorithm(r.cipher)] if x]
        cert_refs = []
        for c in a.chain:
            cref = f"crypto/certificate/{_slug(ep)}/{c.depth}"
            sig_ref, key_ref = b.algorithm(c.sigalg), b.algorithm(c.key)
            cprops = {"subjectName": c.subject, "issuerName": c.issuer, "certificateFormat": "X.509"}
            if (nb := _openssl_date(c.not_before)):
                cprops["notValidBefore"] = nb
            if (na := _openssl_date(c.not_after)):
                cprops["notValidAfter"] = na
            if sig_ref:
                cprops["signatureAlgorithmRef"] = sig_ref
            if key_ref:
                cprops["subjectPublicKeyRef"] = key_ref
            b.components[cref] = {
                "type": "cryptographic-asset", "bom-ref": cref,
                "name": f"{c.subject or 'certificate'} (depth {c.depth} at {ep})",
                "cryptoProperties": {"assetType": "certificate", "certificateProperties": cprops},
                "properties": [{"name": "pqcinv:public-key", "value": c.key}],
            }
            b.depend(cref, sig_ref, key_ref)
            cert_refs.append(cref)
        proto = {"type": "tls"}
        if versions:
            proto["version"] = versions[0]
        if suites:
            proto["cipherSuites"] = [{"name": n, "algorithms": al} if al else {"name": n}
                                     for n, al in sorted(suites.items())]
        crypto_refs = sorted({x for x in algo_refs if x})
        if crypto_refs:
            proto["cryptoRefArray"] = crypto_refs
        props = [
            {"name": "pqcinv:endpoint", "value": ep},
            {"name": "pqcinv:discovered-by", "value": a.target.source},
            {"name": "pqcinv:classification", "value": a.classification},
            {"name": "pqcinv:default-client-result", "value": a.default_outcome},
            {"name": "pqcinv:hello-retry-for-hybrid", "value": str(a.hrr_for_hybrid).lower()},
            {"name": "pqcinv:tls12-accepted", "value": str(a.supports_tls12).lower()},
        ]
        for pid, r in a.results.items():
            props.append({"name": f"pqcinv:probe:{pid}",
                          "value": (f"{r.protocol} {r.group}{' (HRR)' if r.hrr else ''}".strip()
                                    if r.ok else f"failed: {r.error}")})
        for k, v in a.target.meta:
            props.append({"name": f"pqcinv:aws:{k}", "value": str(v)})
        b.components[ref] = {
            "type": "cryptographic-asset", "bom-ref": ref,
            "name": f"TLS {a.target.name + ' ' if a.target.name else ''}({ep})",
            "cryptoProperties": {"assetType": "protocol", "protocolProperties": proto},
            "properties": props,
        }
        b.depend(ref, *crypto_refs, *cert_refs, *[x for s in suites.values() for x in s])

    if aws_inv:
        _add_aws(b, aws_inv)

    return b.bom(scope, timestamp)


_KMS_STATE = {"Enabled": "active", "Disabled": "suspended", "PendingDeletion": "deactivated",
              "PendingImport": "pre-activation", "Creating": "pre-activation", "Unavailable": "suspended",
              "Updating": "active", "PendingReplicaDeletion": "deactivated"}


def _add_aws(b: _Builder, inv: dict) -> None:
    for k in inv.get("kms_keys", []):
        spec = k.get("KeySpec", "")
        aref = b.algorithm(spec)
        ref = f"crypto/key/kms/{k['KeyId']}"
        symmetric = spec == "SYMMETRIC_DEFAULT" or spec.startswith("HMAC")
        rp = {"type": "secret-key" if symmetric else "private-key", "id": k["Arn"]}
        if (st := _KMS_STATE.get(k.get("KeyState", ""))):
            rp["state"] = st
        if aref:
            rp["algorithmRef"] = aref
        if (cd := _iso(k.get("CreationDate"))):
            rp["creationDate"] = cd
        props = [{"name": "aws:kms:key-spec", "value": spec},
                 {"name": "aws:kms:key-usage", "value": k.get("KeyUsage", "")},
                 {"name": "aws:kms:key-manager", "value": k.get("KeyManager", "")}]
        props += [{"name": "aws:kms:alias", "value": al} for al in k.get("Aliases", [])]
        b.components[ref] = {
            "type": "cryptographic-asset", "bom-ref": ref,
            "name": f"KMS key {', '.join(k.get('Aliases', [])) or k['KeyId']}",
            "cryptoProperties": {"assetType": "related-crypto-material",
                                 "relatedCryptoMaterialProperties": rp},
            "properties": props,
        }
        b.depend(ref, aref)

    for c in inv.get("acm_certificates", []):
        ref = f"crypto/certificate/acm/{c['CertificateArn'].rsplit('/', 1)[-1]}"
        key_ref, sig_ref = b.algorithm(c.get("KeyAlgorithm")), b.algorithm(_acm_sig(c.get("SignatureAlgorithm", "")))
        cp = {"subjectName": f"CN={c.get('DomainName', '')}", "certificateFormat": "X.509"}
        if (nb := _iso(c.get("NotBefore"))):
            cp["notValidBefore"] = nb
        if (na := _iso(c.get("NotAfter"))):
            cp["notValidAfter"] = na
        if key_ref:
            cp["subjectPublicKeyRef"] = key_ref
        if sig_ref:
            cp["signatureAlgorithmRef"] = sig_ref
        b.components[ref] = {
            "type": "cryptographic-asset", "bom-ref": ref, "name": f"ACM certificate {c.get('DomainName', '')}",
            "cryptoProperties": {"assetType": "certificate", "certificateProperties": cp},
            "properties": [{"name": "aws:acm:arn", "value": c["CertificateArn"]},
                           {"name": "aws:acm:type", "value": c.get("Type", "")}]
                          + [{"name": "aws:acm:in-use-by", "value": u} for u in c.get("InUseBy", [])],
        }
        b.depend(ref, key_ref, sig_ref)


def _acm_sig(s: str) -> str:
    # ACM: "SHA256WITHECDSA", "SHA256WITHRSA"
    s = s.upper()
    if "ECDSA" in s:
        return "ecdsa-with-" + s.split("WITH")[0].lower()
    if "RSA" in s:
        return "rsa"
    return s


def validate(bom: dict) -> list:
    """Validate against the official CycloneDX 1.6 JSON schema. Returns a list of errors."""
    import json
    try:
        from cyclonedx.schema import SchemaVersion
        from cyclonedx.validation.json import JsonStrictValidator
    except ImportError:
        return ["cyclonedx-python-lib is not installed; schema validation skipped"]
    err = JsonStrictValidator(SchemaVersion.V1_6).validate_str(json.dumps(bom))
    return [] if err is None else [str(err)]
