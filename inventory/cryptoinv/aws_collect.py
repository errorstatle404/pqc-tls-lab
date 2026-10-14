"""AWS half of the crypto inventory: what the account's own configuration says.

Read-only. Needs these permissions (the AWS managed policy SecurityAudit covers all of them):
  sts:GetCallerIdentity, acm:ListCertificates, acm:DescribeCertificate,
  elasticloadbalancing:Describe*, cloudfront:ListDistributions, apigateway:GET,
  kms:ListKeys, kms:DescribeKey, kms:ListAliases, ec2:DescribeInstances,
  ec2:DescribeSecurityGroups, route53:ListHostedZones, route53:ListResourceRecordSets
"""
from __future__ import annotations

import datetime as _dt
from typing import Any

# Ports worth probing when a security group opens a range. Anything else is ignored unless the
# range is small (a range of <= MAX_RANGE ports is probed port by port).
KNOWN_TLS_PORTS = {443, 636, 853, 993, 995, 5671, 6443, 8443, 8444, 8445, 8446, 9443}
MAX_RANGE = 16


def _jsonable(o: Any) -> Any:
    if isinstance(o, dict):
        return {k: _jsonable(v) for k, v in o.items() if k != "ResponseMetadata"}
    if isinstance(o, list):
        return [_jsonable(v) for v in o]
    if isinstance(o, (_dt.datetime, _dt.date)):
        return o.isoformat()
    return o


class _Collector:
    def __init__(self, session, region: str):
        self.s = session
        self.region = region
        self.errors: list[dict] = []

    def client(self, name: str, region: str | None = None):
        return self.s.client(name, region_name=region or self.region)

    def safe(self, what: str, fn, default):
        try:
            return fn()
        except Exception as e:  # noqa: BLE001 - one failing service must not stop the inventory
            code = getattr(e, "response", {}).get("Error", {}).get("Code", type(e).__name__)
            self.errors.append({"collector": what, "error": code, "message": str(e)[:300]})
            return default

    # ---------------- collectors ----------------
    def identity(self) -> dict:
        r = self.client("sts").get_caller_identity()
        return {"account": r["Account"], "arn": r["Arn"]}

    def acm(self) -> list[dict]:
        c = self.client("acm")
        # ListCertificates returns only RSA-2048 certificates unless you ask for every key type.
        key_types = list(c.meta.service_model.shape_for("KeyAlgorithm").enum)
        arns = []
        for page in c.get_paginator("list_certificates").paginate(Includes={"keyTypes": key_types}):
            arns += [x["CertificateArn"] for x in page["CertificateSummaryList"]]
        out = []
        for arn in arns:
            d = c.describe_certificate(CertificateArn=arn)["Certificate"]
            out.append({k: d.get(k) for k in (
                "CertificateArn", "DomainName", "Type", "Status", "KeyAlgorithm", "SignatureAlgorithm",
                "NotBefore", "NotAfter", "InUseBy", "Issuer", "Serial")})
        return out

    def elbv2(self) -> dict:
        c = self.client("elbv2")
        lbs = []
        policy_names: set[str] = set()
        for page in c.get_paginator("describe_load_balancers").paginate():
            for lb in page["LoadBalancers"]:
                listeners = []
                for lp in c.get_paginator("describe_listeners").paginate(LoadBalancerArn=lb["LoadBalancerArn"]):
                    for li in lp["Listeners"]:
                        entry = {
                            "ListenerArn": li["ListenerArn"], "Port": li["Port"], "Protocol": li["Protocol"],
                            "SslPolicy": li.get("SslPolicy"),
                            "Certificates": [x["CertificateArn"] for x in li.get("Certificates", [])],
                        }
                        if entry["SslPolicy"]:
                            policy_names.add(entry["SslPolicy"])
                        listeners.append(entry)
                lbs.append({
                    "LoadBalancerArn": lb["LoadBalancerArn"], "LoadBalancerName": lb["LoadBalancerName"],
                    "Type": lb["Type"], "Scheme": lb["Scheme"], "DNSName": lb["DNSName"],
                    "VpcId": lb.get("VpcId"), "Listeners": listeners,
                })
        policies = {}
        for name in sorted(policy_names):
            def one(n=name):
                p = c.describe_ssl_policies(Names=[n])["SslPolicies"][0]
                return {"SslProtocols": p.get("SslProtocols", []),
                        "Ciphers": [x["Name"] for x in p.get("Ciphers", [])]}
            policies[name] = self.safe(f"elbv2.describe_ssl_policies:{name}", one, None)
        return {"load_balancers": lbs, "ssl_policies": policies}

    def cloudfront(self) -> list[dict]:
        c = self.client("cloudfront", "us-east-1")
        out = []
        for page in c.get_paginator("list_distributions").paginate():
            for d in page.get("DistributionList", {}).get("Items", []) or []:
                vc = d.get("ViewerCertificate", {})
                out.append({
                    "Id": d["Id"], "DomainName": d["DomainName"],
                    "Aliases": d.get("Aliases", {}).get("Items", []) or [],
                    "MinimumProtocolVersion": vc.get("MinimumProtocolVersion"),
                    "CloudFrontDefaultCertificate": vc.get("CloudFrontDefaultCertificate", False),
                    "ACMCertificateArn": vc.get("ACMCertificateArn"),
                })
        return out

    def apigateway(self) -> list[dict]:
        c = self.client("apigatewayv2")
        out, token = [], None
        while True:
            r = c.get_domain_names(**({"NextToken": token} if token else {}))
            for d in r.get("Items", []):
                for cfg in d.get("DomainNameConfigurations", []):
                    out.append({"DomainName": d["DomainName"], "SecurityPolicy": cfg.get("SecurityPolicy"),
                                "EndpointType": cfg.get("EndpointType"), "CertificateArn": cfg.get("CertificateArn")})
            token = r.get("NextToken")
            if not token:
                return out

    def kms(self) -> list[dict]:
        c = self.client("kms")
        aliases: dict[str, list[str]] = {}
        for page in c.get_paginator("list_aliases").paginate():
            for a in page["Aliases"]:
                if a.get("TargetKeyId"):
                    aliases.setdefault(a["TargetKeyId"], []).append(a["AliasName"])
        out = []
        for page in c.get_paginator("list_keys").paginate():
            for k in page["Keys"]:
                m = c.describe_key(KeyId=k["KeyId"])["KeyMetadata"]
                out.append({
                    "KeyId": m["KeyId"], "Arn": m["Arn"], "Aliases": aliases.get(m["KeyId"], []),
                    "KeySpec": m.get("KeySpec") or m.get("CustomerMasterKeySpec"), "KeyUsage": m.get("KeyUsage"),
                    "KeyManager": m.get("KeyManager"), "KeyState": m.get("KeyState"), "Origin": m.get("Origin"),
                    "CreationDate": m.get("CreationDate"), "Description": m.get("Description", ""),
                })
        return out

    def ec2(self) -> list[dict]:
        c = self.client("ec2")
        sgs = {}
        for page in c.get_paginator("describe_security_groups").paginate():
            for g in page["SecurityGroups"]:
                sgs[g["GroupId"]] = g
        out = []
        pages = c.get_paginator("describe_instances").paginate(
            Filters=[{"Name": "instance-state-name", "Values": ["running"]}])
        for page in pages:
            for res in page["Reservations"]:
                for i in res["Instances"]:
                    ports: set[int] = set()
                    for ref in i.get("SecurityGroups", []):
                        for perm in sgs.get(ref["GroupId"], {}).get("IpPermissions", []):
                            if perm.get("IpProtocol") not in ("tcp", "-1"):
                                continue
                            lo, hi = perm.get("FromPort", 0), perm.get("ToPort", 65535)
                            if perm.get("IpProtocol") == "-1":
                                lo, hi = 0, 65535
                            if hi - lo + 1 <= MAX_RANGE:
                                ports.update(range(lo, hi + 1))
                            else:
                                ports.update(p for p in KNOWN_TLS_PORTS if lo <= p <= hi)
                    name = next((t["Value"] for t in i.get("Tags", []) if t["Key"] == "Name"), "")
                    out.append({
                        "InstanceId": i["InstanceId"], "Name": name,
                        "PrivateIpAddress": i.get("PrivateIpAddress"), "PublicIpAddress": i.get("PublicIpAddress"),
                        "PrivateDnsName": i.get("PrivateDnsName"), "VpcId": i.get("VpcId"),
                        "OpenTcpPorts": sorted(ports),
                    })
        return out

    def route53_private(self) -> dict[str, list[str]]:
        """IP -> private DNS names (A records in private hosted zones)."""
        c = self.client("route53", "us-east-1")
        ip_names: dict[str, list[str]] = {}
        for page in c.get_paginator("list_hosted_zones").paginate():
            for z in page["HostedZones"]:
                if not z.get("Config", {}).get("PrivateZone"):
                    continue
                for rp in c.get_paginator("list_resource_record_sets").paginate(HostedZoneId=z["Id"]):
                    for rr in rp["ResourceRecordSets"]:
                        if rr["Type"] != "A":
                            continue
                        for v in rr.get("ResourceRecords", []):
                            ip_names.setdefault(v["Value"], []).append(rr["Name"].rstrip("."))
        return ip_names


def collect(session, region: str | None = None) -> dict:
    region = region or session.region_name or "us-east-1"
    c = _Collector(session, region)
    data = {
        "collected_at": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
        "region": region,
        "identity": c.safe("sts", c.identity, {}),
        "acm_certificates": c.safe("acm", c.acm, []),
        "elbv2": c.safe("elbv2", c.elbv2, {"load_balancers": [], "ssl_policies": {}}),
        "cloudfront": c.safe("cloudfront", c.cloudfront, []),
        "apigateway_domains": c.safe("apigatewayv2", c.apigateway, []),
        "kms_keys": c.safe("kms", c.kms, []),
        "ec2_instances": c.safe("ec2", c.ec2, []),
        "private_dns": c.safe("route53", c.route53_private, {}),
    }
    data["errors"] = c.errors
    data["targets"] = derive_targets(data)
    return _jsonable(data)


def _label(s: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "._:-" else "_" for ch in s)[:60]


def derive_targets(data: dict) -> list[dict]:
    """Network endpoints worth probing, with where each one came from."""
    targets: list[dict] = []
    seen: set[tuple[str, int]] = set()

    def add(host, port, sni, label, source):
        if not host or (host, port) in seen:
            return
        seen.add((host, port))
        targets.append({"host": host, "port": int(port), "sni": sni or host, "label": _label(label), "source": source})

    for inst in data.get("ec2_instances", []):
        ip = inst.get("PrivateIpAddress")
        names = data.get("private_dns", {}).get(ip, [])
        host = names[0] if names else ip
        base = inst.get("Name") or inst["InstanceId"]
        for p in inst.get("OpenTcpPorts", []):
            if p == 22:
                continue
            add(host, p, host, f"{base}-{p}", {"kind": "ec2", "id": inst["InstanceId"]})

    for lb in data.get("elbv2", {}).get("load_balancers", []):
        for li in lb["Listeners"]:
            if li["Protocol"] in ("HTTPS", "TLS"):
                add(lb["DNSName"], li["Port"], lb["DNSName"], f"{lb['LoadBalancerName']}-{li['Port']}",
                    {"kind": "elbv2-listener", "id": li["ListenerArn"], "ssl_policy": li.get("SslPolicy")})

    for d in data.get("cloudfront", []):
        host = (d.get("Aliases") or [d["DomainName"]])[0]
        add(host, 443, host, f"cloudfront-{d['Id']}", {"kind": "cloudfront", "id": d["Id"]})

    for d in data.get("apigateway_domains", []):
        add(d["DomainName"], 443, d["DomainName"], f"apigw-{d['DomainName']}",
            {"kind": "apigateway-domain", "id": d["DomainName"]})
    return targets


def write_targets_file(targets: list[dict], path) -> None:
    with open(path, "w") as f:
        f.write("# host port sni label   (generated by cryptoinv aws)\n")
        for t in targets:
            f.write(f"{t['host']} {t['port']} {t['sni']} {t['label']}\n")
