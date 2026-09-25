"""Read-only AWS collectors: what the account says is configured.

Every call here is a Describe/List/Get call. The tool never creates, changes or deletes
anything in the account. Missing permissions are recorded and the rest carries on.
"""
from __future__ import annotations

from botocore.exceptions import BotoCoreError, ClientError

from .probe import Target

# Ports that usually speak TLS. Security-group rules are expanded against this list.
DEFAULT_TLS_PORTS = (443, 465, 636, 853, 993, 995, 5671, 6443, 8443, 8444, 8445, 8446, 9443)

# ACM only lists RSA_1024 and RSA_2048 certificates unless asked for the other key types.
ACM_KEY_TYPES = ["RSA_1024", "RSA_2048", "RSA_3072", "RSA_4096",
                 "EC_prime256v1", "EC_secp384r1", "EC_secp521r1"]


def collect(session, region: str, ports=DEFAULT_TLS_PORTS) -> dict:
    inv = {"region": region, "account": None, "kms_keys": [], "acm_certificates": [],
           "load_balancers": [], "cloudfront": [], "instances": [], "errors": []}

    def guard(name, fn):
        try:
            fn()
        except (ClientError, BotoCoreError) as e:  # keep going: partial inventory beats none
            inv["errors"].append({"collector": name, "error": str(e)})

    guard("sts", lambda: inv.update(account=session.client("sts", region_name=region)
                                    .get_caller_identity()["Account"]))
    guard("kms", lambda: inv.update(kms_keys=collect_kms(session, region)))
    guard("acm", lambda: inv.update(acm_certificates=collect_acm(session, region)))
    guard("elbv2", lambda: inv.update(load_balancers=collect_elbv2(session, region)))
    guard("cloudfront", lambda: inv.update(cloudfront=collect_cloudfront(session)))
    guard("ec2", lambda: inv.update(instances=collect_ec2(session, region, ports)))
    return inv


def collect_kms(session, region: str) -> list:
    kms = session.client("kms", region_name=region)
    aliases: dict[str, list] = {}
    for page in kms.get_paginator("list_aliases").paginate():
        for a in page["Aliases"]:
            if a.get("TargetKeyId"):
                aliases.setdefault(a["TargetKeyId"], []).append(a["AliasName"])
    keys = []
    for page in kms.get_paginator("list_keys").paginate():
        for k in page["Keys"]:
            md = kms.describe_key(KeyId=k["KeyId"])["KeyMetadata"]
            keys.append({
                "KeyId": md["KeyId"], "Arn": md["Arn"],
                "KeySpec": md.get("KeySpec") or md.get("CustomerMasterKeySpec", ""),
                "KeyUsage": md.get("KeyUsage", ""), "KeyManager": md.get("KeyManager", ""),
                "KeyState": md.get("KeyState", ""), "Description": md.get("Description", ""),
                "CreationDate": _iso(md.get("CreationDate")),
                "Aliases": sorted(aliases.get(md["KeyId"], [])),
            })
    return keys


def collect_acm(session, region: str) -> list:
    acm = session.client("acm", region_name=region)
    certs = []
    pages = acm.get_paginator("list_certificates").paginate(Includes={"keyTypes": ACM_KEY_TYPES})
    for page in pages:
        for summary in page["CertificateSummaryList"]:
            c = acm.describe_certificate(CertificateArn=summary["CertificateArn"])["Certificate"]
            certs.append({
                "CertificateArn": c["CertificateArn"], "DomainName": c.get("DomainName", ""),
                "KeyAlgorithm": c.get("KeyAlgorithm", ""), "SignatureAlgorithm": c.get("SignatureAlgorithm", ""),
                "Type": c.get("Type", ""), "Status": c.get("Status", ""),
                "NotBefore": _iso(c.get("NotBefore")), "NotAfter": _iso(c.get("NotAfter")),
                "InUseBy": c.get("InUseBy", []),
            })
    return certs


def collect_elbv2(session, region: str) -> list:
    elb = session.client("elbv2", region_name=region)
    lbs = []
    for page in elb.get_paginator("describe_load_balancers").paginate():
        for lb in page["LoadBalancers"]:
            listeners = []
            for lpage in elb.get_paginator("describe_listeners").paginate(LoadBalancerArn=lb["LoadBalancerArn"]):
                for li in lpage["Listeners"]:
                    listeners.append({
                        "ListenerArn": li["ListenerArn"], "Port": li["Port"], "Protocol": li["Protocol"],
                        "SslPolicy": li.get("SslPolicy", ""),
                        "Certificates": [c["CertificateArn"] for c in li.get("Certificates", [])],
                    })
            lbs.append({
                "LoadBalancerArn": lb["LoadBalancerArn"], "LoadBalancerName": lb["LoadBalancerName"],
                "DNSName": lb["DNSName"], "Scheme": lb.get("Scheme", ""), "Type": lb.get("Type", ""),
                "VpcId": lb.get("VpcId", ""), "Listeners": listeners,
            })
    names = sorted({li["SslPolicy"] for lb in lbs for li in lb["Listeners"] if li["SslPolicy"]})
    policies = {}
    if names:
        for p in elb.describe_ssl_policies(Names=names).get("SslPolicies", []):
            policies[p["Name"]] = {"SslProtocols": p.get("SslProtocols", []),
                                   "Ciphers": [c["Name"] for c in p.get("Ciphers", [])]}
    for lb in lbs:
        for li in lb["Listeners"]:
            li["Policy"] = policies.get(li["SslPolicy"])
    return lbs


def collect_cloudfront(session) -> list:
    cf = session.client("cloudfront")
    out = []
    for page in cf.get_paginator("list_distributions").paginate():
        for d in page.get("DistributionList", {}).get("Items", []) or []:
            vc = d.get("ViewerCertificate", {})
            out.append({
                "Id": d["Id"], "DomainName": d["DomainName"], "Enabled": d.get("Enabled", False),
                "Aliases": d.get("Aliases", {}).get("Items", []) or [],
                "MinimumProtocolVersion": vc.get("MinimumProtocolVersion", ""),
                "CloudFrontDefaultCertificate": vc.get("CloudFrontDefaultCertificate", False),
                "ACMCertificateArn": vc.get("ACMCertificateArn", ""),
            })
    return out


def collect_ec2(session, region: str, ports=DEFAULT_TLS_PORTS) -> list:
    ec2 = session.client("ec2", region_name=region)
    instances = []
    for page in ec2.get_paginator("describe_instances").paginate(
            Filters=[{"Name": "instance-state-name", "Values": ["running"]}]):
        for res in page["Reservations"]:
            instances.extend(res["Instances"])
    if not instances:
        return []
    sg_ids = sorted({g["GroupId"] for i in instances for g in i.get("SecurityGroups", [])})
    sgs = {g["GroupId"]: g for g in ec2.describe_security_groups(GroupIds=sg_ids)["SecurityGroups"]}
    names = _private_dns_names(session)
    out = []
    for i in instances:
        open_ports = set()
        for gid in (g["GroupId"] for g in i.get("SecurityGroups", [])):
            for perm in sgs.get(gid, {}).get("IpPermissions", []):
                open_ports |= _ports_in_rule(perm, ports)
        ip = i.get("PrivateIpAddress", "")
        tags = {t["Key"]: t["Value"] for t in i.get("Tags", [])}
        out.append({
            "InstanceId": i["InstanceId"], "Name": tags.get("Name", ""), "PrivateIpAddress": ip,
            "PublicIpAddress": i.get("PublicIpAddress", ""), "VpcId": i.get("VpcId", ""),
            "DnsName": names.get(ip, ""), "TlsPorts": sorted(open_ports),
        })
    return out


def _ports_in_rule(perm: dict, ports) -> set:
    if perm.get("IpProtocol") == "-1":
        return set(ports)
    if perm.get("IpProtocol") != "tcp":
        return set()
    lo, hi = perm.get("FromPort", 0), perm.get("ToPort", 65535)
    return {p for p in ports if lo <= p <= hi}


def _private_dns_names(session) -> dict:
    """private IP -> DNS name, from Route 53 private hosted zones (best effort)."""
    try:
        r53 = session.client("route53")
        out = {}
        for page in r53.get_paginator("list_hosted_zones").paginate():
            for z in page["HostedZones"]:
                if not z.get("Config", {}).get("PrivateZone"):
                    continue
                for rpage in r53.get_paginator("list_resource_record_sets").paginate(HostedZoneId=z["Id"]):
                    for rr in rpage["ResourceRecordSets"]:
                        if rr["Type"] == "A":
                            for v in rr.get("ResourceRecords", []):
                                out.setdefault(v["Value"], rr["Name"].rstrip("."))
        return out
    except (ClientError, BotoCoreError):
        return {}


def targets_from_inventory(inv: dict) -> list:
    """Every TLS endpoint the configuration says exists, ready for the network probe."""
    targets = []
    for i in inv.get("instances", []):
        host = i["DnsName"] or i["PrivateIpAddress"]
        for port in i["TlsPorts"]:
            targets.append(Target(host, port, "ec2", i["Name"] or i["InstanceId"],
                                  (("instance_id", i["InstanceId"]), ("private_ip", i["PrivateIpAddress"]))))
    for lb in inv.get("load_balancers", []):
        for li in lb["Listeners"]:
            if li["Protocol"] in ("HTTPS", "TLS"):
                targets.append(Target(lb["DNSName"], li["Port"], "elbv2",
                                      f"{lb['LoadBalancerName']} listener {li['Port']}",
                                      (("load_balancer", lb["LoadBalancerName"]), ("ssl_policy", li["SslPolicy"]))))
    for d in inv.get("cloudfront", []):
        if d.get("Enabled"):
            targets.append(Target(d["DomainName"], 443, "cloudfront", d["Id"],
                                  (("minimum_protocol", d["MinimumProtocolVersion"]),)))
    seen, unique = set(), []
    for t in targets:
        if t.endpoint not in seen:
            seen.add(t.endpoint)
            unique.append(t)
    return unique


def _iso(v):
    return v.isoformat() if hasattr(v, "isoformat") else (v or "")
