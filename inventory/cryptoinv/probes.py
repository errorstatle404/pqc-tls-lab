"""Read the output of scripts/probe.sh and work out each endpoint's TLS / post-quantum posture."""
from __future__ import annotations

import csv
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import algorithms

PROFILES = ("default", "classical-only", "hybrid-only", "classical-first", "pq-only")


@dataclass
class Handshake:
    profile: str
    ok: bool
    result: str
    group: str | None
    hrr: bool
    peer_sig: str | None
    clienthello_b: int
    serverhello_b: int
    certificate_b: int
    certverify_b: int
    bytes_s2c: int


@dataclass
class Cert:
    depth: int
    subject: str
    issuer: str
    not_before: datetime | None
    not_after: datetime | None
    sig_alg: str
    key_alg: str
    key_bits: str
    der_bytes: int

    @property
    def self_signed(self) -> bool:
        return self.subject == self.issuer


@dataclass
class Endpoint:
    label: str
    host: str
    port: int
    sni: str
    handshakes: dict[str, Handshake] = field(default_factory=dict)
    versions: dict[str, tuple[bool, str]] = field(default_factory=dict)  # tls1_2 -> (accepted, cipher)
    chain: list[Cert] = field(default_factory=list)
    aws_source: dict | None = None  # filled in when the AWS collector knows what this is

    # ---------- derived posture ----------
    def hs(self, profile: str) -> Handshake | None:
        return self.handshakes.get(profile)

    def _ok(self, profile: str) -> bool:
        h = self.hs(profile)
        return bool(h and h.ok)

    def _quantum(self, profile: str) -> str | None:
        h = self.hs(profile)
        if not h or not h.ok:
            return None
        g = algorithms.group(h.group)
        return g.quantum if g else None

    @property
    def reachable(self) -> bool:
        results = [h.result for h in self.handshakes.values()]
        if any(h.ok for h in self.handshakes.values()) or any(a for a, _ in self.versions.values()):
            return True
        return not all(r.startswith(("tcp-connect-failed", "FAIL: timeout")) for r in results)

    @property
    def tls13(self) -> bool:
        return any(h.ok for h in self.handshakes.values())

    @property
    def legacy_versions(self) -> list[str]:
        return [v for v in algorithms.LEGACY_TLS if self.versions.get(v, (False, ""))[0]]

    @property
    def tls12(self) -> bool:
        return self.versions.get("tls1_2", (False, ""))[0]

    @property
    def default_group(self) -> str | None:
        h = self.hs("default")
        return h.group if h and h.ok else None

    @property
    def pq_kex(self) -> str:
        """Post-quantum key-exchange posture.

        enforced        hybrid whenever the client supports it (server asks via HelloRetryRequest)
        not-enforced    hybrid supported, but a client that leads with a classical share gets classical
        pq-only         only post-quantum groups accepted; classical-only clients are refused
        none            no post-quantum key exchange at all
        no-tls13        server does not speak TLS 1.3 (hybrid PQ key exchange requires it)
        unreachable
        """
        if not self.reachable:
            return "unreachable"
        if not self.tls13:
            return "no-tls13"
        hybrid_ok = self._quantum("hybrid-only") in ("hybrid", "resistant")
        pq_ok = self._quantum("pq-only") in ("hybrid", "resistant")
        classical_ok = self._quantum("classical-only") == "vulnerable"
        if not (hybrid_ok or pq_ok):
            return "none"
        if not classical_ok:
            return "pq-only"
        cf = self._quantum("classical-first")
        if cf in ("hybrid", "resistant"):
            return "enforced"
        return "not-enforced"

    @property
    def pure_pq_kex(self) -> bool:
        return self._quantum("pq-only") == "resistant"

    @property
    def leaf(self) -> Cert | None:
        return self.chain[0] if self.chain else None

    @property
    def pq_auth(self) -> str:
        """resistant / vulnerable / unknown, from the leaf certificate's key."""
        if not self.leaf:
            return "unknown"
        return algorithms.cert_key(self.leaf.key_alg, self.leaf.key_bits).quantum

    @property
    def chain_bytes(self) -> int:
        return sum(c.der_bytes for c in self.chain)


def _int(v: str) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def _date(v: str) -> datetime | None:
    v = (v or "").strip()
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"):
        try:
            return datetime.strptime(v, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def load(probe_dir: str | Path) -> tuple[list[Endpoint], dict[str, str]]:
    """Returns (endpoints, meta) from a probe.sh output directory."""
    d = Path(probe_dir)
    meta: dict[str, str] = {}
    if (d / "meta.txt").exists():
        for line in (d / "meta.txt").read_text().splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                meta[k] = v

    eps: dict[str, Endpoint] = {}
    with open(d / "targets.tsv", newline="") as f:
        for r in csv.DictReader(f, delimiter="\t"):
            eps[r["label"]] = Endpoint(r["label"], r["host"], _int(r["port"]), r["sni"])

    with open(d / "probes.csv", newline="") as f:
        for r in csv.DictReader(f):
            label, _, profile = r["scenario"].rpartition("|")
            ep = eps.get(label)
            if not ep:
                continue
            ok = r["result"] == "ok"
            ep.handshakes[profile] = Handshake(
                profile=profile, ok=ok, result=r["result"],
                group=r["group"] if ok else None, hrr=r["hrr"] == "yes",
                peer_sig=r["peer_sig"] if ok else None,
                clienthello_b=_int(r["clienthello_B"]), serverhello_b=_int(r["serverhello_B"]),
                certificate_b=_int(r["certificate_B"]), certverify_b=_int(r["certverify_B"]),
                bytes_s2c=_int(r["bytes_s2c"]),
            )

    if (d / "versions.tsv").exists():
        with open(d / "versions.tsv", newline="") as f:
            for r in csv.DictReader(f, delimiter="\t"):
                if r["label"] in eps:
                    eps[r["label"]].versions[r["version"]] = (r["accepted"] == "yes", r["cipher"])

    if (d / "certs.tsv").exists():
        with open(d / "certs.tsv", newline="") as f:
            for r in csv.DictReader(f, delimiter="\t"):
                if r["label"] in eps:
                    eps[r["label"]].chain.append(Cert(
                        depth=_int(r["depth"]), subject=r["subject"], issuer=r["issuer"],
                        not_before=_date(r["not_before"]), not_after=_date(r["not_after"]),
                        sig_alg=r["sig_alg"], key_alg=r["key_alg"], key_bits=r["key_bits"],
                        der_bytes=_int(r["der_bytes"]),
                    ))
    for ep in eps.values():
        ep.chain.sort(key=lambda c: c.depth)
    return list(eps.values()), meta
