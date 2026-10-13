"""Infrastructure-as-Code collectors: Terraform (.tf) -> AWS inventory, Kubernetes YAML -> k8s inventory."""
import json
import re

import yaml

from . import CollectorError

REF = re.compile(r"\$\{([^}]*)\}")


def _v(val):
    """Normalize python-hcl2 values (strip quotes / ${} wrappers, unwrap single-item lists)."""
    if isinstance(val, list) and len(val) == 1 and not isinstance(val[0], (dict, list)):
        val = val[0]
    if isinstance(val, str):
        s = val.strip()
        if len(s) >= 2 and s[0] == s[-1] == '"':
            s = s[1:-1]
        m = REF.fullmatch(s)
        return m.group(1) if m else s
    return val


def _b(val, default=False):
    v = _v(val)
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        return v.lower() == "true"
    return default


def _block(attrs, name):
    blk = attrs.get(name)
    if isinstance(blk, list):
        return blk[0] if blk and isinstance(blk[0], dict) else {}
    return blk if isinstance(blk, dict) else {}


def _blocks(attrs, name):
    blk = attrs.get(name) or []
    return [b for b in (blk if isinstance(blk, list) else [blk]) if isinstance(b, dict)]


def _list(val):
    if isinstance(val, list):
        return [_v(x) for x in val]
    return [_v(val)] if val is not None else []


def parse_terraform(text: str, filename: str = "main.tf") -> dict:
    try:
        import hcl2
        doc = hcl2.loads(text)
    except Exception as exc:
        raise CollectorError(f"Could not parse Terraform: {str(exc).splitlines()[0][:200]}")
    resources = {}
    for entry in doc.get("resource", []):
        for rtype, named in entry.items():
            for rname, attrs in named.items():
                resources[f"{rtype}.{rname}"] = (rtype, rname, attrs)

    inv = {"account_id": "terraform", "region": "plan", "source_file": filename,
           "s3_buckets": [], "security_groups": [], "ec2_instances": [], "rds_instances": [],
           "iam_users": [], "iam_roles": [], "kms_keys": []}
    bucket_by_addr = {}

    def bucket_for(ref):
        ref = _v(ref) or ""
        addr = ".".join(ref.split(".")[:2])
        return bucket_by_addr.get(addr) or next((b for b in inv["s3_buckets"] if b["name"] == ref), None)

    for addr, (rtype, rname, a) in resources.items():
        if rtype == "aws_s3_bucket":
            b = {"name": _v(a.get("bucket")) or rname, "address": addr, "public_access_block": {},
                 "acl_public": _v(a.get("acl")) in ("public-read", "public-read-write"),
                 "policy_public": False, "encryption": "AES256 (S3 default)", "versioning": False, "tags": {}}
            if _block(a, "versioning"):
                b["versioning"] = _b(_block(a, "versioning").get("enabled"))
            inv["s3_buckets"].append(b)
            bucket_by_addr[addr] = b
        elif rtype == "aws_security_group":
            ingress = []
            for ing in _blocks(a, "ingress"):
                for cidr in _list(ing.get("cidr_blocks")) + _list(ing.get("ipv6_cidr_blocks")):
                    ingress.append({"protocol": str(_v(ing.get("protocol"))), "from": _v(ing.get("from_port")),
                                    "to": _v(ing.get("to_port")), "cidr": cidr})
            inv["security_groups"].append({"id": addr, "name": _v(a.get("name")) or rname, "ingress": ingress})
        elif rtype == "aws_instance":
            mo = _block(a, "metadata_options")
            rbd = _block(a, "root_block_device")
            sgs = [".".join(str(s).split(".")[:2]) for s in _list(a.get("vpc_security_group_ids"))]
            inv["ec2_instances"].append({
                "id": addr, "name": rname, "security_groups": sgs,
                "public_ip": "planned" if _b(a.get("associate_public_ip_address"), True) else None,
                "imdsv2_required": _v(mo.get("http_tokens")) == "required",
                "instance_profile_role": _v(a.get("iam_instance_profile")),
                "ebs_encrypted": _b(rbd.get("encrypted"))})
        elif rtype == "aws_db_instance":
            inv["rds_instances"].append({
                "id": _v(a.get("identifier")) or addr, "engine": _v(a.get("engine")),
                "publicly_accessible": _b(a.get("publicly_accessible")),
                "storage_encrypted": _b(a.get("storage_encrypted")),
                "backup_retention_days": int(_v(a.get("backup_retention_period")) or 0), "security_groups": []})
        elif rtype == "aws_iam_user":
            inv["iam_users"].append({"name": _v(a.get("name")) or rname, "console_access": False,
                                     "mfa_enabled": False, "attached_policies": [], "access_keys": [], "address": addr})
        elif rtype == "aws_iam_role":
            inv["iam_roles"].append({"name": _v(a.get("name")) or rname, "policies": [], "address": addr})
        elif rtype == "aws_kms_key":
            inv["kms_keys"].append({"id": addr, "rotation_enabled": _b(a.get("enable_key_rotation"))})
        elif rtype == "aws_cloudtrail":
            inv["cloudtrail"] = {"enabled": _b(a.get("enable_logging"), True),
                                 "multi_region": _b(a.get("is_multi_region_trail")),
                                 "log_file_validation": _b(a.get("enable_log_file_validation"))}

    # second pass: resources that modify others
    for addr, (rtype, rname, a) in resources.items():
        if rtype == "aws_s3_bucket_public_access_block":
            b = bucket_for(a.get("bucket"))
            if b:
                b["public_access_block"] = {k: _b(a.get(k)) for k in (
                    "block_public_acls", "ignore_public_acls", "block_public_policy", "restrict_public_buckets")}
        elif rtype == "aws_s3_bucket_versioning":
            b = bucket_for(a.get("bucket"))
            if b:
                b["versioning"] = _v(_block(a, "versioning_configuration").get("status")) == "Enabled"
        elif rtype == "aws_s3_bucket_server_side_encryption_configuration":
            b = bucket_for(a.get("bucket"))
            if b:
                b["encryption"] = "aws:kms"
        elif rtype == "aws_s3_bucket_acl":
            b = bucket_for(a.get("bucket"))
            if b and _v(a.get("acl")) in ("public-read", "public-read-write"):
                b["acl_public"] = True
        elif rtype == "aws_s3_bucket_policy":
            b = bucket_for(a.get("bucket"))
            pol = str(_v(a.get("policy")))
            if b and re.search(r'"Principal"\s*[:=]\s*"\*"|Principal\s*=\s*"\*"|"AWS"\s*:\s*"\*"', pol):
                b["policy_public"] = True
        elif rtype in ("aws_security_group_rule", "aws_vpc_security_group_ingress_rule"):
            if rtype == "aws_security_group_rule" and _v(a.get("type")) != "ingress":
                continue
            sg_ref = ".".join(str(_v(a.get("security_group_id"))).split(".")[:2])
            sg = next((s for s in inv["security_groups"] if s["id"] == sg_ref), None)
            if sg is None:
                sg = {"id": sg_ref or addr, "name": sg_ref or rname, "ingress": []}
                inv["security_groups"].append(sg)
            cidrs = _list(a.get("cidr_blocks")) or [_v(a.get("cidr_ipv4"))] if a.get("cidr_ipv4") or a.get("cidr_blocks") else []
            for cidr in cidrs:
                sg["ingress"].append({"protocol": str(_v(a.get("protocol") or a.get("ip_protocol"))),
                                      "from": _v(a.get("from_port")), "to": _v(a.get("to_port")), "cidr": cidr})
        elif rtype == "aws_iam_user_policy_attachment":
            name = str(_v(a.get("user"))).split(".")[-2] if "." in str(_v(a.get("user"))) else _v(a.get("user"))
            u = next((u for u in inv["iam_users"] if u["name"] == name or u["address"].endswith("." + str(name))), None)
            if u:
                u["attached_policies"].append(str(_v(a.get("policy_arn"))).split("/")[-1])
        elif rtype == "aws_iam_role_policy_attachment":
            name = str(_v(a.get("role"))).split(".")[-2] if "." in str(_v(a.get("role"))) else _v(a.get("role"))
            r = next((r for r in inv["iam_roles"] if r["name"] == name or r["address"].endswith("." + str(name))), None)
            if r:
                r["policies"].append(str(_v(a.get("policy_arn"))).split("/")[-1])
        elif rtype == "aws_iam_user_login_profile":
            name = str(_v(a.get("user"))).split(".")[-2] if "." in str(_v(a.get("user"))) else _v(a.get("user"))
            u = next((u for u in inv["iam_users"] if u["name"] == name or u["address"].endswith("." + str(name))), None)
            if u:
                u["console_access"] = True
    if not any(inv[k] for k in ("s3_buckets", "security_groups", "ec2_instances", "rds_instances",
                                "iam_users", "iam_roles", "kms_keys")) and "cloudtrail" not in inv:
        raise CollectorError("No supported AWS resources found in this Terraform file")
    return inv


POD_KINDS = {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "Pod", "CronJob"}


def parse_kubernetes(text: str) -> dict:
    try:
        docs = [d for d in yaml.safe_load_all(text) if isinstance(d, dict)]
    except yaml.YAMLError as exc:
        raise CollectorError(f"Could not parse YAML: {str(exc).splitlines()[0][:200]}")
    # support `kubectl get all -o yaml` style List objects
    expanded = []
    for d in docs:
        expanded.extend(d.get("items", []) if d.get("kind") == "List" else [d])
    inv = {"workloads": [], "services": [], "role_bindings": [], "network_policies": []}
    for d in expanded:
        kind, meta = d.get("kind"), d.get("metadata") or {}
        ns = meta.get("namespace", "default")
        if kind in POD_KINDS:
            spec = d.get("spec") or {}
            if kind == "CronJob":
                spec = ((spec.get("jobTemplate") or {}).get("spec") or {})
            pod = spec if kind == "Pod" else ((spec.get("template") or {}).get("spec") or {})
            pod_sc = pod.get("securityContext") or {}
            containers = []
            for c in (pod.get("containers") or []) + (pod.get("initContainers") or []):
                sc = c.get("securityContext") or {}
                containers.append({
                    "name": c.get("name", "container"), "image": c.get("image", ""),
                    "privileged": bool(sc.get("privileged")),
                    "run_as_non_root": bool(sc.get("runAsNonRoot", pod_sc.get("runAsNonRoot"))),
                    "resources": c.get("resources") or {},
                    "env": [{"name": e.get("name"), **({"value": str(e["value"])} if "value" in e else
                                                         {"value_from": "ref"})} for e in c.get("env") or []]})
            inv["workloads"].append({"kind": kind, "name": meta.get("name", "unnamed"), "namespace": ns,
                                     "service_account": pod.get("serviceAccountName", "default"),
                                     "host_network": bool(pod.get("hostNetwork")), "host_pid": bool(pod.get("hostPID")),
                                     "containers": containers})
        elif kind == "Service":
            spec = d.get("spec") or {}
            inv["services"].append({"name": meta.get("name"), "namespace": ns, "type": spec.get("type", "ClusterIP"),
                                    "ports": [p.get("port") for p in spec.get("ports", []) if p.get("port")]})
        elif kind in ("ClusterRoleBinding", "RoleBinding"):
            inv["role_bindings"].append({"name": meta.get("name"), "role": (d.get("roleRef") or {}).get("name"),
                                         "subjects": d.get("subjects") or []})
        elif kind == "NetworkPolicy":
            inv["network_policies"].append(ns)
    if not (inv["workloads"] or inv["services"] or inv["role_bindings"]):
        raise CollectorError("No Kubernetes workloads, services or role bindings found in the file")
    return inv


def parse_any(filename: str, text: str):
    """Detect file type -> (provider, inventory). JSON snapshots are handled by the caller."""
    # Browsers submit <textarea> text with CRLF line endings, and Windows editors save .tf files that way;
    # the HCL parser only accepts LF, so normalise first.
    text = (text or "").replace("\r\n", "\n").replace("\r", "\n")
    low = filename.lower()
    if low.endswith(".tf"):
        return "aws", parse_terraform(text, filename)
    if low.endswith((".yaml", ".yml")):
        return "kubernetes", parse_kubernetes(text)
    if low.endswith(".json"):
        try:
            data = json.loads(text)
        except ValueError as exc:
            raise CollectorError(f"Invalid JSON: {exc}")
        if isinstance(data, dict) and data.get("kind") == "List":
            return "kubernetes", parse_kubernetes(text)
        raise CollectorError("Upload JSON inventories from the Integrations page (Import snapshot)")
    raise CollectorError("Unsupported file type. Use .tf, .yaml/.yml")
