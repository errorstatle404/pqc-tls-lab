"""Score the inventory against a known answer (the lab's ground truth).

Ground-truth file format:
  {"endpoints": [
     {"host": "pqc-server", "port": 8443, "name": "hybrid (preferred)",
      "expected_posture": "not-enforced",            # or a list of acceptable postures
      "expected_default_group": "X25519MLKEM768"},   # or "handshake_failure"
     ...]}
"""
from __future__ import annotations

from dataclasses import dataclass

from .probes import Endpoint


@dataclass
class Check:
    endpoint: str
    name: str
    field: str
    expected: str
    observed: str
    ok: bool


def _norm(v) -> list[str]:
    return [x.lower() for x in (v if isinstance(v, list) else [v])]


def _match(gt: dict, eps: list[Endpoint]) -> Endpoint | None:
    host = str(gt.get("host", "*")).lower().rstrip(".")
    for ep in eps:
        if ep.port != int(gt["port"]):
            continue
        if host == "*" or host in (ep.host.lower().rstrip("."), ep.sni.lower().rstrip(".")):
            return ep
    return None


def score(ground_truth: dict, eps: list[Endpoint]) -> tuple[list[Check], float]:
    checks: list[Check] = []
    for gt in ground_truth.get("endpoints", []):
        where = f"{gt.get('host', '*')}:{gt['port']}"
        name = gt.get("name", "")
        ep = _match(gt, eps)
        if ep is None:
            checks.append(Check(where, name, "discovered", "yes", "no (not in probe results)", False))
            continue
        if "expected_posture" in gt:
            exp = _norm(gt["expected_posture"])
            checks.append(Check(where, name, "pq_kex", " or ".join(exp), ep.pq_kex, ep.pq_kex.lower() in exp))
        if "expected_default_group" in gt:
            exp = _norm(gt["expected_default_group"])
            obs = ep.default_group or "handshake_failure"
            checks.append(Check(where, name, "default_group", " or ".join(exp), obs, obs.lower() in exp))
    acc = sum(c.ok for c in checks) / len(checks) if checks else 0.0
    return checks, acc
