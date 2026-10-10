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


def _session(creds):
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
        kw["profile_name"] = creds["profile"]
    return boto3.Session(**kw)


def collect(creds: dict, session=None) -> dict:
    s = session or _session(creds)
    errors = []

    def record(label, exc):
        code, status = _sanitize(exc)
        errors.append({"call": label, "code": code, "status": status, "kind": _kind(code)})
        return code

    def safe(label, fn, default=UNSET):
        """Run one read-only call. On failure, record a sanitized error and return `default`
        (UNSET when no default is given) so callers can tell "read failed" from "really empty"."""
        try:
            return fn()
        except Exception as exc:  # AccessDenied etc. -> recorded, scan continues
            record(label, exc)
            return default

    try:
        ident = s.client("sts").get_caller_identity()
    except Exception as exc:
        raise CollectorError(f"AWS credentials rejected ({exc.__class__.__name__}). Check the keys/profile.")
    region = s.region_name
    inv = {"account_id": ident["Account"], "region": region, "_source": "aws-live", "account": {},
           "s3_buckets": [], "iam_users": [], "iam_roles": [], "security_groups": [], "ec2_instances": [],
           "rds_instances": [], "kms_keys": []}
    now = datetime.now(timezone.utc)

    iam = s.client("iam")
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
    users = safe("iam:ListUsers", lambda: iam.list_users(MaxItems=200)["Users"])
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
            mfa = safe("iam:ListMFADevices", lambda: bool(iam.list_mfa_devices(UserName=name)["MFADevices"]))
            keys = safe("iam:ListAccessKeys", lambda: iam.list_access_keys(UserName=name)["AccessKeyMetadata"])
            pols = safe("iam:ListAttachedUserPolicies",
                        lambda: [p["PolicyName"] for p in
                                 iam.list_attached_user_policies(UserName=name)["AttachedPolicies"]])
            inv["iam_users"].append({
                "name": name,
                "console_access": console,
                "mfa_enabled": None if mfa is UNSET else mfa,
                "attached_policies": None if pols is UNSET else pols,
                "access_keys": None if keys is UNSET else [
                    {"id": k["AccessKeyId"][:4] + "****" + k["AccessKeyId"][-4:],
                     "age_days": (now - k["CreateDate"]).days,
                     "active": k["Status"] == "Active"} for k in keys]})
    roles = safe("iam:ListRoles", lambda: iam.list_roles(MaxItems=200)["Roles"])
    if roles is not UNSET:
        for r in roles:
            if r.get("Path", "/").startswith("/aws-service-role/"):
                continue
            pols = safe("iam:ListAttachedRolePolicies",
                        lambda: [p["PolicyName"] for p in
                                 iam.list_attached_role_policies(RoleName=r["RoleName"])["AttachedPolicies"]])
            inv["iam_roles"].append({"name": r["RoleName"], "policies": None if pols is UNSET else pols})

    s3 = s.client("s3")
    buckets = safe("s3:ListBuckets", lambda: s3.list_buckets()["Buckets"])
    if buckets is not UNSET:
        for b in buckets:
            n = b["Name"]
            unknown = []
            try:
                cfg = s3.get_public_access_block(Bucket=n)["PublicAccessBlockConfiguration"]
                pab = {k: bool(cfg.get(w)) for k, w in
                       (("block_public_acls", "BlockPublicAcls"), ("ignore_public_acls", "IgnorePublicAcls"),
                        ("block_public_policy", "BlockPublicPolicy"),
                        ("restrict_public_buckets", "RestrictPublicBuckets"))}
            except Exception as exc:
                code, _ = _sanitize(exc)
                if _is_absent("s3:GetPublicAccessBlock", code):
                    # genuinely not configured: all four settings are effectively off
                    pab = {"block_public_acls": False, "ignore_public_acls": False,
                           "block_public_policy": False, "restrict_public_buckets": False}
                else:
                    record("s3:GetPublicAccessBlock", exc)
                    pab = None
                    unknown.append("public_access_block")
            grants = safe("s3:GetBucketAcl", lambda: s3.get_bucket_acl(Bucket=n)["Grants"])
            if grants is UNSET:
                acl_public = None
                unknown.append("acl_public")
            else:
                acl_public = any("AllUsers" in (g.get("Grantee", {}).get("URI") or "") for g in grants or [])
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
                     "acl_public": acl_public, "public_access_block": pab}
            if unknown:
                entry["_unknown"] = unknown
            inv["s3_buckets"].append(entry)

    ec2 = s.client("ec2")
    sgs = safe("ec2:DescribeSecurityGroups", lambda: ec2.describe_security_groups()["SecurityGroups"])
    if sgs is not UNSET:
        for g in sgs:
            ingress = []
            for p in g.get("IpPermissions", []):
                for rng in p.get("IpRanges", []) + [{"CidrIp": r["CidrIpv6"]} for r in p.get("Ipv6Ranges", [])]:
                    ingress.append({"protocol": p.get("IpProtocol"), "from": p.get("FromPort", 0),
                                    "to": p.get("ToPort", 65535), "cidr": rng.get("CidrIp")})
            inv["security_groups"].append({"id": g["GroupId"], "name": g.get("GroupName"), "ingress": ingress})
    vols_raw = safe("ec2:DescribeVolumes", lambda: ec2.describe_volumes()["Volumes"])
    vols = None if vols_raw is UNSET else {v["VolumeId"]: v.get("Encrypted") for v in vols_raw}
    res = safe("ec2:DescribeInstances", lambda: ec2.describe_instances()["Reservations"])
    if res is not UNSET:
        for reservation in res:
            for i in reservation.get("Instances", []):
                name = next((t["Value"] for t in i.get("Tags", []) if t["Key"] == "Name"), i["InstanceId"])
                vol_ids = [m["Ebs"]["VolumeId"] for m in i.get("BlockDeviceMappings", []) if "Ebs" in m]
                if vols is None and vol_ids:
                    ebs = None  # volume data could not be read: encryption state unknown
                else:
                    ebs = all((vols or {}).get(v, False) for v in vol_ids) if vol_ids else True
                inv["ec2_instances"].append({
                    "id": i["InstanceId"], "name": name, "public_ip": i.get("PublicIpAddress"),
                    "security_groups": [g["GroupId"] for g in i.get("SecurityGroups", [])],
                    "imdsv2_required": i.get("MetadataOptions", {}).get("HttpTokens") == "required",
                    "instance_profile_role": (i.get("IamInstanceProfile", {}).get("Arn") or "").split("/")[-1] or None,
                    "ebs_encrypted": ebs})

    rds = s.client("rds")
    dbs = safe("rds:DescribeDBInstances", lambda: rds.describe_db_instances()["DBInstances"])
    if dbs is not UNSET:
        for d in dbs:
            inv["rds_instances"].append({"id": d["DBInstanceIdentifier"], "engine": d.get("Engine"),
                                         "publicly_accessible": d.get("PubliclyAccessible", False),
                                         "storage_encrypted": d.get("StorageEncrypted", False),
                                         "backup_retention_days": d.get("BackupRetentionPeriod", 0),
                                         "security_groups": [g["VpcSecurityGroupId"] for g in
                                                             d.get("VpcSecurityGroups", [])]})

    ct = s.client("cloudtrail")
    trails = safe("cloudtrail:DescribeTrails", lambda: ct.describe_trails()["trailList"])
    if trails is not UNSET and trails is not None:
        statuses = [st for st in (safe("cloudtrail:GetTrailStatus",
                                       lambda t=t: ct.get_trail_status(Name=t["TrailARN"])["IsLogging"])
                                  for t in trails) if st is not UNSET]
        # trails exist but every status read failed -> logging state unknown, not "disabled";
        # an account with no trails at all genuinely fails the check (enabled=False)
        enabled = None if (trails and not statuses) else any(statuses)
        inv["cloudtrail"] = {"enabled": enabled,
                             "multi_region": any(t.get("IsMultiRegionTrail") for t in trails),
                             "log_file_validation": any(t.get("LogFileValidationEnabled") for t in trails)}

    kms = s.client("kms")
    key_list = safe("kms:ListKeys", lambda: kms.list_keys(Limit=100)["Keys"])
    if key_list is not UNSET:
        for k in key_list:
            meta = safe("kms:DescribeKey", lambda: kms.describe_key(KeyId=k["KeyId"])["KeyMetadata"], {})
            if meta.get("KeyManager") == "CUSTOMER" and meta.get("KeySpec", "SYMMETRIC_DEFAULT") == "SYMMETRIC_DEFAULT" \
                    and meta.get("KeyState") == "Enabled":
                rot = safe("kms:GetKeyRotationStatus",
                           lambda: kms.get_key_rotation_status(KeyId=k["KeyId"])["KeyRotationEnabled"])
                inv["kms_keys"].append({"id": k["KeyId"], "rotation_enabled": None if rot is UNSET else rot})

    gd = safe("guardduty:ListDetectors", lambda: s.client("guardduty").list_detectors()["DetectorIds"])
    if gd is not UNSET and gd is not None:
        inv["guardduty_enabled"] = bool(gd)

    inv["_errors"] = errors  # every recorded entry is a genuine read failure (legit-absent is not recorded)
    attempted = ("iam", "s3", "ec2", "rds", "cloudtrail", "kms", "guardduty")
    failed_services = {e["call"].split(":", 1)[0] for e in errors}
    inv["_coverage"] = {svc: ("partial" if svc in failed_services else "ok") for svc in attempted}
    return inv
