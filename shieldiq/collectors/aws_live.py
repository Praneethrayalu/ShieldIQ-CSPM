"""Live, read-only AWS collector (optional; needs `pip install -r requirements-cloud.txt`).

Uses only Describe/List/Get calls. Suggested IAM policy for the credentials: the AWS managed
`SecurityAudit` policy (read-only).

Coverage and error handling: a read that fails (access denied, throttled, service error) is
recorded in `inv["_errors"]` as a sanitized, structured entry - the call label, the AWS error
code, the HTTP status and a coarse kind (denied / not_found / error). The exception *message*
is never stored: AWS error messages can embed account ARNs, resource names and request
parameters. The affected inventory fields are left unknown (None / omitted / listed in a
bucket's `_unknown`) instead of being replaced with defaults, so a failed read is never
reported as a passing or a failing check - rules skip what could not be read. A read that
returns a genuine "not configured" response (NoSuchEntity and friends) is NOT an error: it
is a real, reportable state. `inv["_coverage"]` summarizes per-service read coverage so the
UI, API and reports can distinguish a fully evaluated scan from a partial one.

Completeness (v2.2): every list/describe call is paginated (boto3 paginators), regional services
(EC2, RDS, KMS, GuardDuty) are read in every enabled region (DescribeRegions, opted-in only) or in
an explicitly configured region list, and IAM permissions are read from the actual policy
documents (attached managed via GetPolicy/GetPolicyVersion, inline user/group/role policies and
group membership), not just policy names. Credentials: only the integration's own access key, or
an AWS CLI profile the operator explicitly allowed (SHIELDIQ_ALLOWED_AWS_PROFILES) - never the
server's default credential chain.
"""
from datetime import datetime, timezone

from . import CollectorError

UNSET = object()  # sentinel: the call failed - the value is unknown, NOT an empty/default value

_DENIED = ("accessdenied", "unauthorized", "authfailure", "forbidden", "notauthorized")
_NOT_FOUND = ("nosuchentity", "notfound", "nosuchbucket", "nosuchpublicaccessblock",
              "serversideencryptionconfigurationnotfound")

# "Genuinely not configured" is per-API, never a blanket NotFound: only these exact error codes
# for these exact calls mean a real, reportable absent state. Anything else that looks like a
# NotFound (e.g. NoSuchBucket: the bucket vanished between List and the sub-call) is an unknown.
ABSENT_CODES = {
    "iam:GetAccountPasswordPolicy": ("NoSuchEntity", "NoSuchEntityException"),
    "iam:GetLoginProfile": ("NoSuchEntity", "NoSuchEntityException"),
    "s3:GetPublicAccessBlock": ("NoSuchPublicAccessBlockConfiguration",),
    "s3control:GetPublicAccessBlock": ("NoSuchPublicAccessBlockConfiguration",),
    "s3:GetBucketPolicyStatus": ("NoSuchBucketPolicy",),
    "s3:GetBucketEncryption": ("ServerSideEncryptionConfigurationNotFoundError",),
}


def _is_absent(label, code):
    return code in ABSENT_CODES.get(label, ())


def _sanitize(exc):
    """Secret-free identity of a failed call: the AWS error code and HTTP status only.
    The message text is deliberately dropped - it can contain ARNs, names and parameters."""
    code = exc.__class__.__name__
    status = None
    resp = getattr(exc, "response", None)
    if isinstance(resp, dict):
        code = (resp.get("Error") or {}).get("Code") or code
        status = (resp.get("ResponseMetadata") or {}).get("HTTPStatusCode")
    return code, status


def _kind(code):
    cl = (code or "").lower()
    if any(t in cl for t in _DENIED):
        return "denied"
    if any(t in cl for t in _NOT_FOUND):
        return "not_found"
    return "error"


def allowed_profiles(config=None):
    """AWS CLI profiles an integration may name. Empty (the default) = profiles are disabled, so a user can
    never make ShieldIQ scan with the server's own ~/.aws credentials. An operator opts specific profiles in
    with SHIELDIQ_ALLOWED_AWS_PROFILES=prof-a,prof-b."""
    import os
    raw = None
    if config is not None:
        raw = config.get("ALLOWED_AWS_PROFILES")
    if raw is None:
        raw = os.getenv("SHIELDIQ_ALLOWED_AWS_PROFILES", "")
    if isinstance(raw, (list, tuple, set)):
        return {str(p).strip() for p in raw if str(p).strip()}
    return {p.strip() for p in str(raw).split(",") if p.strip()}


def _session(creds, profiles=None):
    try:
        import boto3
    except ImportError:
        raise CollectorError("Live AWS scanning needs boto3: pip install -r requirements-cloud.txt")
    kw = {"region_name": creds.get("region") or "us-east-1"}
    if creds.get("access_key_id"):
        kw.update(aws_access_key_id=creds["access_key_id"], aws_secret_access_key=creds.get("secret_access_key"))
        if creds.get("session_token"):
            kw["aws_session_token"] = creds["session_token"]
    elif creds.get("profile"):
        allowed = allowed_profiles() if profiles is None else set(profiles)
        if creds["profile"] not in allowed:
            raise CollectorError("This AWS CLI profile is not allowed on this server. Use an access key for a "
                                 "read-only SecurityAudit user, or ask the operator to allow the profile "
                                 "(SHIELDIQ_ALLOWED_AWS_PROFILES).")
        kw["profile_name"] = creds["profile"]
    else:
        # Never fall back to boto3's default credential chain: that would scan with the server's own
        # environment / instance-role credentials instead of the tenant's.
        raise CollectorError("No AWS credentials stored for this integration (access key or allowed profile).")
    try:
        return boto3.Session(**kw)
    except Exception as exc:  # e.g. ProfileNotFound: a clean, user-facing error instead of a 500
        raise CollectorError(f"Could not open the AWS session ({exc.__class__.__name__}).") from None


def _pages(client, method, key, **kw):
    """Every item of a list/describe call, across all pages (boto3 paginator when the operation has one)."""
    can = getattr(client, "can_paginate", None)
    try:
        paginated = callable(can) and can(method) is True
    except TypeError:  # duck-typed / test clients without boto3's can_paginate(operation_name) signature
        paginated = False
    if paginated:
        out = []
        for page in client.get_paginator(method).paginate(**kw):
            out.extend(page.get(key) or [])
        return out
    return getattr(client, method)(**kw).get(key) or []


def _policy_doc(doc):
    """boto3 returns IAM policy documents already JSON-decoded; raw API/snapshot data may be a URL-encoded string."""
    if isinstance(doc, dict):
        return doc
    if isinstance(doc, str):
        import json
        from urllib.parse import unquote
        try:
            return json.loads(doc)
        except ValueError:
            try:
                return json.loads(unquote(doc))
            except ValueError:
                return None
    return None


_OPTED_IN = ("opt-in-not-required", "opted-in")


def collect(creds: dict, session=None) -> dict:
    s = session or _session(creds)
    errors = []

    def record(label, exc, region=None):
        code, status = _sanitize(exc)
        e = {"call": label, "code": code, "status": status, "kind": _kind(code)}
        if region:
            e["region"] = region
        errors.append(e)
        return code

    def safe(label, fn, default=UNSET, region=None):
        """Run one read-only call. On failure, record a sanitized error and return `default`
        (UNSET when no default is given) so callers can tell "read failed" from "really empty"."""
        try:
            return fn()
        except Exception as exc:  # AccessDenied etc. -> recorded, scan continues
            record(label, exc, region)
            return default

    def client(svc, region=None):
        if region is None or region == getattr(s, "region_name", None):
            return s.client(svc)
        return s.client(svc, region_name=region)

    try:
        ident = s.client("sts").get_caller_identity()
    except Exception as exc:
        raise CollectorError(f"AWS credentials rejected ({exc.__class__.__name__}). Check the keys/profile.")
    region = s.region_name or "us-east-1"
    inv = {"account_id": ident["Account"], "region": region, "_source": "aws-live", "account": {},
           "s3_buckets": [], "iam_users": [], "iam_roles": [], "security_groups": [], "ec2_instances": [],
           "rds_instances": [], "kms_keys": [], "guardduty": []}
    now = datetime.now(timezone.utc)

    # ---------------------------------------------------------------- regions
    wanted = creds.get("regions")
    if isinstance(wanted, str):
        wanted = [r.strip() for r in wanted.split(",") if r.strip()]
    if wanted:
        regions = list(dict.fromkeys(wanted))
    else:
        found = safe("ec2:DescribeRegions", lambda: client("ec2", region).describe_regions(
            AllRegions=True, Filters=[{"Name": "opt-in-status", "Values": list(_OPTED_IN)}])["Regions"])
        if found is UNSET:
            regions = [region]  # recorded as an error -> the scan is reported partial, never "complete"
        else:
            regions = sorted({r["RegionName"] for r in found
                              if r.get("OptInStatus", "opt-in-not-required") in _OPTED_IN}) or [region]
    inv["regions"] = regions

    # ---------------------------------------------------------------- IAM (global)
    iam = client("iam")
    summary = safe("iam:GetAccountSummary", lambda: iam.get_account_summary()["SummaryMap"])
    if summary is not UNSET and summary:
        inv["account"]["root_mfa"] = bool(summary.get("AccountMFAEnabled"))
        inv["account"]["root_access_keys"] = bool(summary.get("AccountAccessKeysPresent"))
    try:
        pp = iam.get_account_password_policy()["PasswordPolicy"]
        inv["account"]["password_policy"] = {"min_length": pp.get("MinimumPasswordLength", 0),
                                             "reuse_prevention": pp.get("PasswordReusePrevention", 0)}
    except Exception as exc:
        code, _ = _sanitize(exc)
        if _is_absent("iam:GetAccountPasswordPolicy", code):
            # genuinely no password policy configured: a real, reportable state
            inv["account"]["password_policy"] = {"min_length": 0, "reuse_prevention": 0}
        else:
            record("iam:GetAccountPasswordPolicy", exc)
        # any other failure (denied, throttled...) leaves the key absent, so the check is skipped

    managed_cache = {}

    def managed_doc(arn):
        """Default version of a managed policy (GetPolicy -> GetPolicyVersion), cached. UNSET when unreadable."""
        if arn not in managed_cache:
            def read():
                ver = iam.get_policy(PolicyArn=arn)["Policy"]["DefaultVersionId"]
                doc = _policy_doc(iam.get_policy_version(PolicyArn=arn, VersionId=ver)["PolicyVersion"]["Document"])
                if doc is None:
                    raise ValueError("unparseable policy document")
                return doc
            managed_cache[arn] = safe("iam:GetPolicyVersion", read)
        return managed_cache[arn]

    def attached(list_method, get_label, **who):
        """[(name, source, doc-or-UNSET)] for attached managed policies; UNSET if the list itself failed."""
        pols = safe(get_label, lambda: _pages(iam, list_method, "AttachedPolicies", **who))
        if pols is UNSET:
            return UNSET
        return [(p["PolicyName"], "managed:" + p.get("PolicyArn", p["PolicyName"]), managed_doc(p["PolicyArn"])
                 if p.get("PolicyArn") else UNSET) for p in pols]

    def inline(list_method, get_method, list_label, get_label, **who):
        names = safe(list_label, lambda: _pages(iam, list_method, "PolicyNames", **who))
        if names is UNSET:
            return UNSET
        out = []
        for n in names:
            doc = safe(get_label, lambda n=n: _policy_doc(getattr(iam, get_method)(PolicyName=n, **who)["PolicyDocument"]))
            out.append((n, "inline", UNSET if doc is None else doc))
        return out

    group_cache = {}

    def group_policies(gname):
        if gname not in group_cache:
            a = attached("list_attached_group_policies", "iam:ListAttachedGroupPolicies", GroupName=gname)
            i = inline("list_group_policies", "get_group_policy", "iam:ListGroupPolicies", "iam:GetGroupPolicy",
                       GroupName=gname)
            group_cache[gname] = (a, i)
        return group_cache[gname]

    def principal_policies(parts):
        """Merge policy lists into (attached names, documents, complete?)."""
        names, docs, complete = [], [], True
        for part in parts:
            if part is UNSET:
                complete = False
                continue
            for name, source, doc in part:
                if source.startswith("managed:") or source.startswith("group-managed:"):
                    names.append(name)
                if doc is UNSET or doc is None:
                    complete = False
                else:
                    docs.append({"name": name, "source": source, "document": doc})
        return names, docs, complete

    users = safe("iam:ListUsers", lambda: _pages(iam, "list_users", "Users"))
    if users is not UNSET:
        for u in users:
            name = u["UserName"]
            try:
                iam.get_login_profile(UserName=name)
                console = True
            except Exception as exc:
                code, _ = _sanitize(exc)
                if _is_absent("iam:GetLoginProfile", code):
                    console = False  # this user genuinely has no console password
                else:
                    record("iam:GetLoginProfile", exc)
                    console = None  # unknown: could not read the login profile
            mfa = safe("iam:ListMFADevices", lambda: bool(_pages(iam, "list_mfa_devices", "MFADevices", UserName=name)))
            keys = safe("iam:ListAccessKeys", lambda: _pages(iam, "list_access_keys", "AccessKeyMetadata", UserName=name))
            att = attached("list_attached_user_policies", "iam:ListAttachedUserPolicies", UserName=name)
            inl = inline("list_user_policies", "get_user_policy", "iam:ListUserPolicies", "iam:GetUserPolicy",
                         UserName=name)
            groups = safe("iam:ListGroupsForUser", lambda: [g["GroupName"] for g in
                                                             _pages(iam, "list_groups_for_user", "Groups", UserName=name)])
            parts = [att, inl]
            if groups is UNSET:
                parts.append(UNSET)
            else:
                for g in groups:
                    ga, gi = group_policies(g)
                    parts.append(UNSET if ga is UNSET else [(n, "group-managed:" + g + ":" + src.split(":", 1)[1], d)
                                                             for n, src, d in ga])
                    parts.append(UNSET if gi is UNSET else [(n, "group-inline:" + g, d) for n, _src, d in gi])
            names, docs, complete = principal_policies(parts)
            inv["iam_users"].append({
                "name": name,
                "console_access": console,
                "mfa_enabled": None if mfa is UNSET else mfa,
                # direct + group managed policy names (name match is kept: AdministratorAccess)
                "attached_policies": None if att is UNSET else names,
                "groups": None if groups is UNSET else groups,
                "policy_documents": docs,
                "policies_complete": complete,
                "access_keys": None if keys is UNSET else [
                    {"id": k["AccessKeyId"][:4] + "****" + k["AccessKeyId"][-4:],
                     "age_days": (now - k["CreateDate"]).days,
                     "active": k["Status"] == "Active"} for k in keys]})
    roles = safe("iam:ListRoles", lambda: _pages(iam, "list_roles", "Roles"))
    if roles is not UNSET:
        for r in roles:
            if r.get("Path", "/").startswith("/aws-service-role/"):
                continue
            rn = r["RoleName"]
            att = attached("list_attached_role_policies", "iam:ListAttachedRolePolicies", RoleName=rn)
            inl = inline("list_role_policies", "get_role_policy", "iam:ListRolePolicies", "iam:GetRolePolicy",
                         RoleName=rn)
            names, docs, complete = principal_policies([att, inl])
            inv["iam_roles"].append({"name": rn, "policies": None if att is UNSET else names,
                                     "policy_documents": docs, "policies_complete": complete})

    # ---------------------------------------------------------------- S3 (global)
    def pab_dict(cfg):
        return {k: bool(cfg.get(w)) for k, w in
                (("block_public_acls", "BlockPublicAcls"), ("ignore_public_acls", "IgnorePublicAcls"),
                 ("block_public_policy", "BlockPublicPolicy"), ("restrict_public_buckets", "RestrictPublicBuckets"))}

    try:
        acfg = client("s3control", region).get_public_access_block(AccountId=inv["account_id"])[
            "PublicAccessBlockConfiguration"]
        inv["s3_account_public_access_block"] = pab_dict(acfg)
    except Exception as exc:
        code, _ = _sanitize(exc)
        if _is_absent("s3control:GetPublicAccessBlock", code):
            inv["s3_account_public_access_block"] = pab_dict({})  # genuinely not configured: all off
        else:
            record("s3control:GetPublicAccessBlock", exc)
            inv["s3_account_public_access_block"] = None  # unknown

    s3 = client("s3")
    buckets = safe("s3:ListBuckets", lambda: _pages(s3, "list_buckets", "Buckets"))
    if buckets is not UNSET:
        for b in buckets:
            n = b["Name"]
            unknown = []
            try:
                pab = pab_dict(s3.get_public_access_block(Bucket=n)["PublicAccessBlockConfiguration"])
            except Exception as exc:
                code, _ = _sanitize(exc)
                if _is_absent("s3:GetPublicAccessBlock", code):
                    # genuinely not configured at bucket level: all four settings are off for the bucket
                    pab = pab_dict({})
                else:
                    record("s3:GetPublicAccessBlock", exc)
                    pab = None
                    unknown.append("public_access_block")
            grants = safe("s3:GetBucketAcl", lambda: s3.get_bucket_acl(Bucket=n)["Grants"])
            if grants is UNSET:
                acl_public, grantees = None, None
                unknown.append("acl_public")
            else:
                grantees = sorted({g for g in ("AllUsers", "AuthenticatedUsers")
                                   for gr in grants or [] if (gr.get("Grantee", {}).get("URI") or "").endswith("/" + g)})
                # AuthenticatedUsers = any AWS account in the world; AWS itself treats it as public
                acl_public = bool(grantees)
            try:
                pol_public = s3.get_bucket_policy_status(Bucket=n)["PolicyStatus"]["IsPublic"]
            except Exception as exc:
                code, _ = _sanitize(exc)
                if _is_absent("s3:GetBucketPolicyStatus", code):
                    pol_public = False  # genuinely no bucket policy at all
                else:
                    record("s3:GetBucketPolicyStatus", exc)
                    pol_public = None
                    unknown.append("policy_public")
            try:
                enc = s3.get_bucket_encryption(Bucket=n)[
                    "ServerSideEncryptionConfiguration"]["Rules"][0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]
            except Exception as exc:
                code, _ = _sanitize(exc)
                if not _is_absent("s3:GetBucketEncryption", code):
                    record("s3:GetBucketEncryption", exc)
                    unknown.append("encryption")
                enc = None  # absent config = no default encryption; anything else = unknown (see _unknown)
            ver = safe("s3:GetBucketVersioning", lambda: s3.get_bucket_versioning(Bucket=n).get("Status") == "Enabled")
            if ver is UNSET:
                ver = None
                unknown.append("versioning")
            entry = {"name": n, "encryption": enc, "versioning": ver, "policy_public": pol_public,
                     "acl_public": acl_public, "acl_public_grantees": grantees, "public_access_block": pab}
            if unknown:
                entry["_unknown"] = unknown
            inv["s3_buckets"].append(entry)

    # ---------------------------------------------------------------- regional services
    cloudtrail_done = False
    for rg in regions:
        ec2 = client("ec2", rg)
        sgs = safe("ec2:DescribeSecurityGroups", lambda: _pages(ec2, "describe_security_groups", "SecurityGroups"),
                   region=rg)
        if sgs is not UNSET:
            for g in sgs:
                ingress = []
                for p in g.get("IpPermissions", []):
                    for rng in p.get("IpRanges", []) + [{"CidrIp": r["CidrIpv6"]} for r in p.get("Ipv6Ranges", [])]:
                        ingress.append({"protocol": p.get("IpProtocol"), "from": p.get("FromPort", 0),
                                        "to": p.get("ToPort", 65535), "cidr": rng.get("CidrIp")})
                inv["security_groups"].append({"id": g["GroupId"], "name": g.get("GroupName"), "region": rg,
                                               "ingress": ingress})
        vols_raw = safe("ec2:DescribeVolumes", lambda: _pages(ec2, "describe_volumes", "Volumes"), region=rg)
        vols = None if vols_raw is UNSET else {v["VolumeId"]: v.get("Encrypted") for v in vols_raw}
        res = safe("ec2:DescribeInstances", lambda: _pages(ec2, "describe_instances", "Reservations"), region=rg)
        if res is not UNSET:
            for reservation in res:
                for i in reservation.get("Instances", []):
                    state = (i.get("State") or {}).get("Name")
                    if state in ("terminated", "shutting-down"):
                        continue  # gone (or going): not a resource that can be exposed
                    name = next((t["Value"] for t in i.get("Tags", []) if t["Key"] == "Name"), i["InstanceId"])
                    vol_ids = [m["Ebs"]["VolumeId"] for m in i.get("BlockDeviceMappings", []) if "Ebs" in m]
                    if not vol_ids:
                        ebs = True
                    elif vols is None:
                        ebs = None  # volume data could not be read: encryption state unknown
                    else:
                        states = [vols.get(v) for v in vol_ids]
                        if any(st is False for st in states):
                            ebs = False
                        elif any(st is None for st in states):
                            ebs = None  # a volume missing from the complete listing: unknown, not unencrypted
                        else:
                            ebs = True
                    inv["ec2_instances"].append({
                        "id": i["InstanceId"], "name": name, "region": rg, "state": state,
                        "public_ip": i.get("PublicIpAddress"),
                        "security_groups": [g["GroupId"] for g in i.get("SecurityGroups", [])],
                        "imdsv2_required": i.get("MetadataOptions", {}).get("HttpTokens") == "required",
                        "instance_profile_role": (i.get("IamInstanceProfile", {}).get("Arn") or "").split("/")[-1] or None,
                        "ebs_encrypted": ebs})

        rds = client("rds", rg)
        dbs = safe("rds:DescribeDBInstances", lambda: _pages(rds, "describe_db_instances", "DBInstances"), region=rg)
        if dbs is not UNSET:
            for d in dbs:
                inv["rds_instances"].append({"id": d["DBInstanceIdentifier"], "engine": d.get("Engine"), "region": rg,
                                             "publicly_accessible": d.get("PubliclyAccessible", False),
                                             "storage_encrypted": d.get("StorageEncrypted", False),
                                             "backup_retention_days": d.get("BackupRetentionPeriod", 0),
                                             "security_groups": [g["VpcSecurityGroupId"] for g in
                                                                 d.get("VpcSecurityGroups", [])]})

        kms = client("kms", rg)
        key_list = safe("kms:ListKeys", lambda: _pages(kms, "list_keys", "Keys"), region=rg)
        if key_list is not UNSET:
            for k in key_list:
                meta = safe("kms:DescribeKey", lambda: kms.describe_key(KeyId=k["KeyId"])["KeyMetadata"], {}, region=rg)
                if meta.get("KeyManager") == "CUSTOMER" and meta.get("KeySpec", "SYMMETRIC_DEFAULT") == "SYMMETRIC_DEFAULT" \
                        and meta.get("KeyState") == "Enabled":
                    rot = safe("kms:GetKeyRotationStatus",
                               lambda: kms.get_key_rotation_status(KeyId=k["KeyId"])["KeyRotationEnabled"], region=rg)
                    inv["kms_keys"].append({"id": k["KeyId"], "region": rg,
                                            "rotation_enabled": None if rot is UNSET else rot})

        gdc = client("guardduty", rg)
        det_ids = safe("guardduty:ListDetectors", lambda: _pages(gdc, "list_detectors", "DetectorIds"), region=rg)
        if det_ids is not UNSET and det_ids is not None:
            statuses = []
            for did in det_ids:
                st = safe("guardduty:GetDetector", lambda did=did: gdc.get_detector(DetectorId=did).get("Status"),
                          region=rg)
                statuses.append(None if st is UNSET else st)
            if not det_ids:
                enabled = False  # no detector at all in this region
            elif any(st == "ENABLED" for st in statuses):
                enabled = True
            elif any(st is None for st in statuses):
                enabled = None  # detector exists, status unreadable: unknown, not "on"
            else:
                enabled = False  # every detector is suspended (Status=DISABLED)
            inv["guardduty"].append({"region": rg, "enabled": enabled, "detectors": len(det_ids),
                                     "statuses": statuses})

    # ---------------------------------------------------------------- CloudTrail (account level, home region)
    ct = client("cloudtrail", region)
    trails = safe("cloudtrail:DescribeTrails", lambda: ct.describe_trails()["trailList"])
    if trails is not UNSET and trails is not None:
        tlist = []
        for t in trails:
            st = safe("cloudtrail:GetTrailStatus", lambda t=t: ct.get_trail_status(Name=t["TrailARN"])["IsLogging"])
            tlist.append({"name": t.get("Name"), "arn": t.get("TrailARN"),
                          "multi_region": bool(t.get("IsMultiRegionTrail")),
                          "log_file_validation": bool(t.get("LogFileValidationEnabled")),
                          "logging": None if st is UNSET else bool(st)})
        compliant = [t for t in tlist if t["multi_region"] and t["log_file_validation"] and t["logging"]]
        maybe = [t for t in tlist if t["multi_region"] and t["log_file_validation"] and t["logging"] is None]
        inv["cloudtrail"] = {
            "trails": tlist,
            # True only when ONE trail is multi-region AND logging AND log-validated; None = cannot tell
            "compliant_trail": True if compliant else (None if maybe else False),
            # aggregate view kept for the UI / older consumers (per-trail data above is what the rule uses)
            "enabled": None if (tlist and all(t["logging"] is None for t in tlist)) else any(t["logging"] for t in tlist),
            "multi_region": any(t["multi_region"] for t in tlist),
            "log_file_validation": any(t["log_file_validation"] for t in tlist)}

    # back-compat single flag for the home region (UI / older snapshots)
    home = next((g for g in inv["guardduty"] if g["region"] == region), None)
    if home is not None and home["enabled"] is not None:
        inv["guardduty_enabled"] = home["enabled"]

    inv["_errors"] = errors  # every recorded entry is a genuine read failure (legit-absent is not recorded)
    attempted = ("iam", "s3", "s3control", "ec2", "rds", "cloudtrail", "kms", "guardduty")
    failed_services = {e["call"].split(":", 1)[0] for e in errors}
    inv["_coverage"] = {svc: ("partial" if svc in failed_services else "ok") for svc in attempted}
    return inv
