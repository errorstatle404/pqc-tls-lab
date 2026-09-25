"""Score the inventory against a known answer (the lab's ground truth).

Ground truth format (the Terraform output `inventory_ground_truth`, or ground_truth/local.json):
  {"host": ..., "ip": ...,
   "endpoints": {"8443": {"inventory_class": "...", "expected_default_client": "..."}, ...},
   "alb": {"dns_name": ..., "listeners": {"443": {...same fields...}}},     (optional)
   "kms_keys": {"alias/...": {"key_spec": "...", "quantum_safe": true}}}    (optional)

An expected class of "hybrid" accepts any hybrid-* class, and an expected default-client result
of "classical" accepts any quantum-vulnerable group. They are used where the exact answer is not
documented, such as AWS's load balancer policies.
"""
from __future__ import annotations

from . import algorithms


def _same_group(expected: str, found: str) -> bool:
    if expected == "classical":
        return algorithms.quantum_status(found) == "vulnerable"
    if expected.lower() == found.lower():
        return True
    a, b = algorithms.lookup(expected), algorithms.lookup(found)
    return bool(a and b and a.key == b.key)


def _class_ok(expected: str, found: str) -> bool:
    return found.startswith("hybrid-") if expected == "hybrid" else expected == found


def _score_endpoints(checks, assessments, hosts, endpoints, label):
    for port, exp in sorted(endpoints.items(), key=lambda kv: int(kv[0])):
        a = next((x for x in assessments if x.target.port == int(port) and x.target.host in hosts), None)
        asset = f"{label}:{port}"
        if "inventory_class" in exp:
            found = a.classification if a else "not probed"
            checks.append({"asset": asset, "check": "classification", "expected": exp["inventory_class"],
                           "found": found, "pass": bool(a) and _class_ok(exp["inventory_class"], found)})
        if "expected_default_client" in exp:
            found = a.default_outcome if a else "not probed"
            checks.append({"asset": asset, "check": "default client negotiates",
                           "expected": exp["expected_default_client"], "found": found,
                           "pass": bool(a) and _same_group(exp["expected_default_client"], found)})


def score(assessments: list, truth: dict, aws_inv: dict | None = None) -> dict:
    checks: list = []
    hosts = {h for h in (truth.get("host"), truth.get("ip")) if h}
    _score_endpoints(checks, assessments, hosts, truth.get("endpoints", {}), truth.get("host", "server"))

    alb = truth.get("alb")
    if alb:
        _score_endpoints(checks, assessments, {alb.get("dns_name")}, alb.get("listeners", {}),
                         alb.get("name", "alb"))

    for alias, exp in sorted((truth.get("kms_keys") or {}).items()):
        key = next((k for k in (aws_inv or {}).get("kms_keys", []) if alias in k.get("Aliases", [])), None)
        found_spec = key["KeySpec"] if key else "not found"
        found_safe = algorithms.quantum_status(found_spec) == "pq"
        checks.append({"asset": alias, "check": "key spec / quantum-safe",
                       "expected": f"{exp['key_spec']} / {'yes' if exp['quantum_safe'] else 'no'}",
                       "found": f"{found_spec} / {'yes' if found_safe else 'no'}" if key else "not found",
                       "pass": bool(key) and found_spec == exp["key_spec"] and found_safe == exp["quantum_safe"]})

    passed = sum(c["pass"] for c in checks)
    return {"checks": checks, "passed": passed, "total": len(checks),
            "percent": round(100 * passed / len(checks)) if checks else None}
