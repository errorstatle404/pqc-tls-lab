"""Write the inventory outputs: report.md, findings.csv, cbom.json, inventory.json, raw-probes.txt."""
from __future__ import annotations

import csv
import json
import os

from . import __version__, algorithms
from .classify import CLASSES, SEVERITY_ORDER
from .probe import PROFILES

ICON = {"hybrid-enforced": "✅", "hybrid-downgradable": "⚠️", "hybrid-not-preferred": "⚠️",
        "pq-only": "⚠️", "classical": "❌", "unreachable": "–"}
SEV_ICON = {"high": "🔴", "medium": "🟠", "low": "🟡", "info": "🔵"}


def _cell(r) -> str:
    if r is None:
        return "–"
    if not r.ok:
        return f"✗ {r.error.replace('_', ' ')}"
    g = algorithms.display(r.group) or "?"
    extra = " (HRR)" if r.hrr else ""
    proto = "" if r.protocol == "TLSv1.3" else f" {r.protocol.replace('TLSv', 'TLS ')}"
    return f"{g}{extra}{proto}"


def _md_escape(s: str) -> str:
    return str(s).replace("|", "\\|").replace("\n", " ")


def render_markdown(ctx: dict) -> str:
    A, F, S, inv = ctx["assessments"], ctx["findings"], ctx.get("score"), ctx.get("aws")
    L = [f"# Post-quantum readiness inventory: {ctx['scope']}", "",
         f"Generated {ctx['timestamp']} by pqc-inventory {__version__}. "
         f"Probes ran from {ctx['probe_where']} using {ctx['openssl'] or 'no probe'}.", ""]

    # ---- Summary ----
    L += ["## Summary", ""]
    if A:
        counts = {}
        for a in A:
            counts[a.classification] = counts.get(a.classification, 0) + 1
        L.append(f"**{len(A)} TLS endpoint{'s' if len(A) != 1 else ''} probed:** " + ", ".join(
            f"{ICON[c]} {n} {c}" for c, n in sorted(counts.items(), key=lambda kv: list(CLASSES).index(kv[0]))))
        pq_default = sum(1 for a in A if algorithms.is_pq(a.default_group))
        L += ["", f"A current browser gets post-quantum key exchange on **{pq_default} of {len(A)}** endpoints."]
    sev = {}
    for f in F:
        sev[f.severity] = sev.get(f.severity, 0) + 1
    L += ["", "**Findings:** " + (", ".join(f"{SEV_ICON[s]} {sev[s]} {s}" for s in SEVERITY_ORDER if s in sev)
                                  or "none"), ""]
    if S:
        L += [f"**Accuracy against the lab's ground truth: {S['passed']}/{S['total']} checks "
              f"({S['percent']}%).**", ""]

    # ---- Score ----
    if S:
        L += ["## Score against ground truth", "",
              "| Asset | Check | Expected | Found | |", "|---|---|---|---|---|"]
        for c in S["checks"]:
            L.append(f"| {_md_escape(c['asset'])} | {c['check']} | {_md_escape(c['expected'])} | "
                     f"{_md_escape(c['found'])} | {'✅' if c['pass'] else '❌'} |")
        L.append("")

    # ---- Endpoints ----
    if A:
        L += ["## TLS endpoints", "",
              "| Endpoint | Found via | Class | Current browser gets | Leaf certificate | TLS 1.2 |",
              "|---|---|---|---|---|---|"]
        for a in A:
            leaf = a.chain[0] if a.chain else None
            cert = (f"{algorithms.display(leaf.key) or leaf.key} ({algorithms.quantum_status(leaf.key)})"
                    if leaf else "–")
            name = f"{a.target.name}<br>`{a.endpoint}`" if a.target.name else f"`{a.endpoint}`"
            L.append(f"| {name} | {a.target.source} | {ICON[a.classification]} {a.classification} | "
                     f"{_cell(a.results.get('pq-default'))} | {_md_escape(cert)} | "
                     f"{'yes' if a.supports_tls12 else 'no'} |")
        L += ["", "### What each kind of client negotiated", "",
              "| Endpoint | " + " | ".join(p.label for p in PROFILES) + " |",
              "|---|" + "---|" * len(PROFILES)]
        for a in A:
            L.append(f"| `{a.endpoint}` | " + " | ".join(_cell(a.results.get(p.id)) for p in PROFILES) + " |")
        L += ["", "HRR = the server sent a HelloRetryRequest to get the hybrid key share (one extra round trip).", "",
              "Classes:", ""]
        L += [f"- {ICON[c]} **{c}**: {d}" for c, d in CLASSES.items() if c != "unreachable"]
        L.append("")

    # ---- Findings ----
    L += ["## Findings", ""]
    if not F:
        L += ["None.", ""]
    for f in F:
        L += [f"### {SEV_ICON[f.severity]} {f.severity.upper()}: {f.title}", "",
              f"**Asset:** `{f.asset}` ({f.asset_type})  ", f"**What:** {f.detail}  ",
              f"**Fix:** {f.recommendation}", ""]

    # ---- AWS ----
    if inv:
        L += ["## AWS configuration", "",
              f"Account `{inv.get('account') or '?'}`, region `{inv['region']}`. Read-only API calls.", ""]
        if inv["kms_keys"]:
            L += ["### KMS keys", "", "| Key | Spec | Usage | Managed by | State | Quantum |", "|---|---|---|---|---|---|"]
            for k in sorted(inv["kms_keys"], key=lambda k: (k["KeyManager"], k["KeySpec"])):
                L.append(f"| {', '.join(k['Aliases']) or k['KeyId']} | {k['KeySpec']} | {k['KeyUsage']} | "
                         f"{k['KeyManager']} | {k['KeyState']} | {algorithms.quantum_status(k['KeySpec'])} |")
            L.append("")
        if inv["acm_certificates"]:
            L += ["### ACM certificates", "", "| Domain | Key | Type | Expires | In use by |", "|---|---|---|---|---|"]
            for c in inv["acm_certificates"]:
                L.append(f"| {c['DomainName']} | {c['KeyAlgorithm']} | {c['Type']} | {c['NotAfter'][:10]} | "
                         f"{len(c['InUseBy'])} |")
            L.append("")
        lis = [(lb, li) for lb in inv["load_balancers"] for li in lb["Listeners"] if li["SslPolicy"]]
        if lis:
            L += ["### Load balancer listeners", "", "| Load balancer | Port | Policy | TLS versions | PQ policy |",
                  "|---|---|---|---|---|"]
            for lb, li in lis:
                pol = li.get("Policy") or {}
                L.append(f"| {lb['LoadBalancerName']} ({lb['Scheme']}) | {li['Port']} | {li['SslPolicy']} | "
                         f"{', '.join(pol.get('SslProtocols', [])) or '?'} | "
                         f"{'yes' if '-PQ-' in li['SslPolicy'].upper() else 'no'} |")
            L.append("")
        if inv["cloudfront"]:
            L += ["### CloudFront distributions", "", "| Domain | Minimum TLS policy | Enabled |", "|---|---|---|"]
            for d in inv["cloudfront"]:
                L.append(f"| {d['DomainName']} | {d['MinimumProtocolVersion']} | {d['Enabled']} |")
            L.append("")
        if inv["instances"]:
            L += ["### EC2 instances with TLS ports open in their security groups", "",
                  "| Instance | Name | Private IP | DNS name | TLS ports |", "|---|---|---|---|---|"]
            for i in inv["instances"]:
                L.append(f"| {i['InstanceId']} | {i['Name']} | {i['PrivateIpAddress']} | {i['DnsName'] or '–'} | "
                         f"{', '.join(map(str, i['TlsPorts'])) or 'none'} |")
            L.append("")
        if inv["errors"]:
            L += ["### Could not read", ""] + [f"- **{e['collector']}**: {_md_escape(e['error'])}" for e in inv["errors"]]
            L.append("")

    # ---- Method ----
    L += ["## Method and limits", "",
          "Each endpoint was probed with these client profiles (`openssl s_client`, OpenSSL 3.5):", ""]
    L += [f"- **{p.label}** (`{p.id}`): {p.description}" for p in PROFILES]
    L += ["",
          "- Results depend on where the probe runs: a firewall, proxy or TLS-inspecting middlebox in the path "
          "changes what is negotiated.",
          "- Each probe sends one `GET /` so it also appears in server access logs (servers log requests, "
          "not bare handshakes).",
          "- Certificate verification is not enforced: the goal is to record what is offered, not whether it is trusted.",
          f"- The CBOM (`cbom.json`) is CycloneDX {ctx.get('cbom_spec', '1.6')}"
          + (" and passed the official schema check." if ctx.get("cbom_valid") else "."), ""]
    return "\n".join(L)


def write_outputs(out_dir: str, ctx: dict, cbom: dict, raw: str) -> dict:
    os.makedirs(out_dir, exist_ok=True)
    paths = {k: os.path.join(out_dir, v) for k, v in
             {"report": "report.md", "cbom": "cbom.json", "csv": "findings.csv",
              "json": "inventory.json", "raw": "raw-probes.txt"}.items()}
    with open(paths["report"], "w", encoding="utf-8") as f:
        f.write(render_markdown(ctx))
    with open(paths["cbom"], "w", encoding="utf-8") as f:
        json.dump(cbom, f, indent=2)
    with open(paths["csv"], "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["severity", "id", "asset_type", "asset", "title", "detail", "recommendation"])
        for x in ctx["findings"]:
            w.writerow([x.severity, x.id, x.asset_type, x.asset, x.title, x.detail, x.recommendation])
    with open(paths["json"], "w", encoding="utf-8") as f:
        json.dump({
            "scope": ctx["scope"], "timestamp": ctx["timestamp"], "tool_version": __version__,
            "probe": {"where": ctx["probe_where"], "openssl": ctx["openssl"]},
            "endpoints": [{
                "endpoint": a.endpoint, "source": a.target.source, "name": a.target.name,
                "meta": a.target.meta_dict(), "classification": a.classification,
                "default_client": a.default_outcome, "tls12_accepted": a.supports_tls12,
                "hrr_for_hybrid": a.hrr_for_hybrid,
                "chain": [c.__dict__ for c in a.chain],
                "probes": {pid: r.to_dict() for pid, r in a.results.items()},
            } for a in ctx["assessments"]],
            "findings": [x.to_dict() for x in ctx["findings"]],
            "score": ctx.get("score"), "aws": ctx.get("aws"),
        }, f, indent=2, default=str)
    if raw:
        with open(paths["raw"], "w", encoding="utf-8") as f:
            f.write(raw)
    else:
        paths.pop("raw")
    return paths
