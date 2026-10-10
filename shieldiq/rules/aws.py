"""AWS rules (read-only checks against the normalized AWS inventory)."""
from .engine import CheckResult, fixer, find, open_to_world, port_in, rule

ADMIN_PORTS = {22: "SSH", 3389: "RDP"}


def _buckets(inv):
    return inv.get("s3_buckets", [])


@rule("AWS-S3-001", "aws", "S3", "S3 bucket Block Public Access is not fully enabled", "critical",
      "All four S3 Block Public Access settings should be on for every bucket.",
      ["public_data"],
      "One or more of BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy and RestrictPublicBuckets is off, so a "
      "bucket policy or object ACL can make data readable by anyone on the internet.",
      "Anonymous users could list or download objects (backups, customer exports, logs). Public S3 buckets are one "
      "of the most common causes of cloud data leaks.",
      ["Confirm no application depends on anonymous reads (use CloudFront with OAC instead).",
       "Enable all four Block Public Access settings on the bucket.",
       "Enable account-level Block Public Access so new buckets are protected by default."],
      terraform='''
resource "aws_s3_bucket_public_access_block" "{resource}" {
  bucket                  = "{resource}"
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}''',
      cli="aws s3api put-public-access-block --bucket {resource} --public-access-block-configuration "
          "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
      refs=["CIS AWS 2.1.4"], asset="datastore")
def s3_block_public(inv):
    for b in _buckets(inv):
        if "public_access_block" in b.get("_unknown", ()):
            continue  # the PAB read failed: unknown is neither pass nor fail
        pab = b.get("public_access_block") or {}
        missing = [k for k in ("block_public_acls", "ignore_public_acls", "block_public_policy",
                               "restrict_public_buckets") if not pab.get(k)]
        yield CheckResult(f"arn:aws:s3:::{b['name']}", not missing,
                          f"Disabled settings: {', '.join(missing)}" if missing else "All settings enabled",
                          {"missing": missing})


@fixer("AWS-S3-001")
def _fix_s3_block(inv, rid):
    b = find(_buckets(inv), "name", rid.split(":::")[-1])
    if not b:
        return False
    b["public_access_block"] = {k: True for k in ("block_public_acls", "ignore_public_acls",
                                                  "block_public_policy", "restrict_public_buckets")}
    b["acl_public"] = False
    b["policy_public"] = False
    return True


@rule("AWS-S3-002", "aws", "S3", "S3 bucket is publicly readable via ACL or bucket policy", "critical",
      "Bucket ACL or policy grants access to AllUsers / Principal '*'.",
      ["public_data"],
      "The bucket policy uses \"Principal\": \"*\" without conditions, or the ACL grants READ to the AllUsers group.",
      "Every object in the bucket can be fetched by anyone who knows or guesses the bucket name.",
      ["Remove the AllUsers / AuthenticatedUsers grants from the bucket ACL.",
       "Replace Principal \"*\" statements with specific IAM principals or a CloudFront origin access control.",
       "Set Object Ownership to 'Bucket owner enforced' to disable ACLs entirely."],
      terraform='''
resource "aws_s3_bucket_ownership_controls" "{resource}" {
  bucket = "{resource}"
  rule { object_ownership = "BucketOwnerEnforced" }   # disables ACLs
}''',
      cli="aws s3api delete-bucket-policy --bucket {resource} && aws s3api put-bucket-ownership-controls "
          "--bucket {resource} --ownership-controls Rules=[{ObjectOwnership=BucketOwnerEnforced}]",
      refs=["CIS AWS 2.1.4"], asset="datastore")
def s3_public_acl(inv):
    for b in _buckets(inv):
        unknown = set(b.get("_unknown", ()))
        known = {k: b.get(k) for k in ("acl_public", "policy_public") if k not in unknown}
        if not any(bool(v) for v in known.values()) and (len(known) < 2 or any(v is None for v in known.values())):
            continue  # "not public" needs both grants read; a known public grant still reports
        public = any(bool(v) for v in known.values())
        how = [w for w, v in (("ACL", known.get("acl_public")), ("bucket policy", known.get("policy_public"))) if v]
        yield CheckResult(f"arn:aws:s3:::{b['name']}", not public,
                          f"Public via {' and '.join(how)}" if public else "Not public")


@fixer("AWS-S3-002")
def _fix_s3_acl(inv, rid):
    b = find(_buckets(inv), "name", rid.split(":::")[-1])
    if not b:
        return False
    b["acl_public"] = False
    b["policy_public"] = False
    return True


@rule("AWS-S3-003", "aws", "S3", "S3 bucket default encryption is not enabled", "medium",
      "Buckets should encrypt objects at rest with SSE-S3 or SSE-KMS.",
      ["encryption_rest"],
      "No server-side encryption configuration is set on the bucket.",
      "Objects written by older clients may be stored unencrypted, which fails PCI-DSS 3.5 and HIPAA encryption "
      "requirements.",
      ["Enable default encryption (SSE-KMS with a customer managed key for sensitive data).",
       "Add a bucket policy that denies PutObject without encryption headers (optional, defense in depth)."],
      terraform='''
resource "aws_s3_bucket_server_side_encryption_configuration" "{resource}" {
  bucket = "{resource}"
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "aws:kms" }
    bucket_key_enabled = true
  }
}''',
      cli="aws s3api put-bucket-encryption --bucket {resource} --server-side-encryption-configuration "
          "'{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"aws:kms\"}}]}'",
      asset="datastore")
def s3_encryption(inv):
    for b in _buckets(inv):
        if "encryption" in b.get("_unknown", ()):
            continue  # the encryption read failed: unknown is neither pass nor fail
        enc = b.get("encryption")
        yield CheckResult(f"arn:aws:s3:::{b['name']}", bool(enc),
                          f"Encryption: {enc}" if enc else "No default encryption")


@fixer("AWS-S3-003")
def _fix_s3_enc(inv, rid):
    b = find(_buckets(inv), "name", rid.split(":::")[-1])
    if b:
        b["encryption"] = "aws:kms"
    return bool(b)


@rule("AWS-S3-004", "aws", "S3", "S3 bucket versioning is disabled", "low",
      "Versioning protects against accidental deletion and ransomware overwrite.",
      ["backup"],
      "Versioning is Suspended or was never enabled on the bucket.",
      "A deleted or overwritten object cannot be recovered; ransomware that rewrites objects is unrecoverable.",
      ["Enable versioning on the bucket.", "Add a lifecycle rule to expire non-current versions after N days."],
      terraform='''
resource "aws_s3_bucket_versioning" "{resource}" {
  bucket = "{resource}"
  versioning_configuration { status = "Enabled" }
}''',
      cli="aws s3api put-bucket-versioning --bucket {resource} --versioning-configuration Status=Enabled",
      asset="datastore")
def s3_versioning(inv):
    for b in _buckets(inv):
        if "versioning" in b.get("_unknown", ()):
            continue  # the versioning read failed: unknown is neither pass nor fail
        yield CheckResult(f"arn:aws:s3:::{b['name']}", bool(b.get("versioning")),
                          "Versioning enabled" if b.get("versioning") else "Versioning disabled")


@fixer("AWS-S3-004")
def _fix_s3_ver(inv, rid):
    b = find(_buckets(inv), "name", rid.split(":::")[-1])
    if b:
        b["versioning"] = True
    return bool(b)


@rule("AWS-IAM-001", "aws", "IAM", "Root account does not have MFA enabled", "critical",
      "The AWS root user must be protected with MFA.",
      ["mfa"],
      "The root user signs in with a password only.",
      "Root has unrestricted access to every resource and billing. A phished root password means total account "
      "takeover.",
      ["Sign in as root and register a hardware or virtual MFA device.",
       "Store the root credentials offline and use IAM Identity Center for daily work."],
      cli="# Root MFA must be enabled from the console: IAM > Security credentials > Assign MFA device",
      refs=["CIS AWS 1.5"], asset="identity")
def root_mfa(inv):
    acct = inv.get("account") or {}
    if "root_mfa" in acct:
        yield CheckResult(f"arn:aws:iam::{inv.get('account_id', 'account')}:root", bool(acct["root_mfa"]),
                          "Root MFA enabled" if acct["root_mfa"] else "Root MFA disabled")


@fixer("AWS-IAM-001")
def _fix_root_mfa(inv, rid):
    inv.setdefault("account", {})["root_mfa"] = True
    return True


@rule("AWS-IAM-002", "aws", "IAM", "Root account has active access keys", "critical",
      "The root user should never have programmatic access keys.",
      ["credentials"],
      "Access keys were created for the root user.",
      "A leaked root key gives an attacker full, unrestricted API access that IAM policies cannot limit.",
      ["Delete the root access keys.", "Use IAM roles for any automation that was using them."],
      cli="# Delete from console: IAM > Security credentials (root) > Access keys > Delete",
      refs=["CIS AWS 1.4"], asset="identity")
def root_keys(inv):
    acct = inv.get("account") or {}
    if "root_access_keys" in acct:
        yield CheckResult(f"arn:aws:iam::{inv.get('account_id', 'account')}:root", not acct["root_access_keys"],
                          "Root has access keys" if acct["root_access_keys"] else "No root access keys")


@fixer("AWS-IAM-002")
def _fix_root_keys(inv, rid):
    inv.setdefault("account", {})["root_access_keys"] = False
    return True


@rule("AWS-IAM-003", "aws", "IAM", "IAM user with console access has no MFA", "high",
      "Every IAM user that can sign in to the console should use MFA.",
      ["mfa"],
      "The user has a login profile (console password) but no MFA device.",
      "Password reuse or phishing gives an attacker interactive console access with all of this user's permissions.",
      ["Require the user to register an MFA device.",
       "Attach a policy that denies all actions unless aws:MultiFactorAuthPresent is true.",
       "Prefer IAM Identity Center (SSO) over long-lived IAM users."],
      terraform='''
# Deny everything except MFA self-service until MFA is present
data "aws_iam_policy_document" "force_mfa" {
  statement {
    effect      = "Deny"
    not_actions = ["iam:CreateVirtualMFADevice", "iam:EnableMFADevice", "iam:ListMFADevices", "sts:GetSessionToken"]
    resources   = ["*"]
    condition {
      test     = "BoolIfExists"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["false"]
    }
  }
}
resource "aws_iam_user_policy" "{resource}_force_mfa" {
  name   = "force-mfa"
  user   = "{resource}"
  policy = data.aws_iam_policy_document.force_mfa.json
}''',
      cli="aws iam create-virtual-mfa-device --virtual-mfa-device-name {resource} --outfile qr.png "
          "--bootstrap-method QRCodePNG",
      refs=["CIS AWS 1.10"], asset="identity")
def user_mfa(inv):
    for u in inv.get("iam_users", []):
        if u.get("console_access") and u.get("mfa_enabled") is not None:
            yield CheckResult(f"arn:aws:iam::{inv.get('account_id', 'account')}:user/{u['name']}",
                              bool(u.get("mfa_enabled")), "MFA enabled" if u.get("mfa_enabled") else "No MFA device")


@fixer("AWS-IAM-003")
def _fix_user_mfa(inv, rid):
    u = find(inv.get("iam_users"), "name", rid.split("/")[-1])
    if u:
        u["mfa_enabled"] = True
    return bool(u)


@rule("AWS-IAM-004", "aws", "IAM", "IAM access key older than 90 days", "medium",
      "Active access keys should be rotated at least every 90 days.",
      ["credentials"],
      "A long-lived static access key has not been rotated.",
      "Old keys are more likely to have leaked (laptops, CI logs, git history) and stay valid until someone notices.",
      ["Create a second access key for the user.", "Roll the new key out to every workload.",
       "Deactivate, then delete the old key.", "Move workloads to IAM roles so no static key is needed."],
      cli="aws iam create-access-key --user-name {resource} && aws iam update-access-key --user-name {resource} "
          "--access-key-id <OLD_KEY_ID> --status Inactive",
      refs=["CIS AWS 1.14"], asset="identity")
def key_age(inv):
    for u in inv.get("iam_users", []):
        old = [k for k in u.get("access_keys") or [] if k.get("active", True) and k.get("age_days", 0) > 90]
        if u.get("access_keys"):
            oldest = max((k.get("age_days", 0) for k in u["access_keys"]), default=0)
            yield CheckResult(f"arn:aws:iam::{inv.get('account_id', 'account')}:user/{u['name']}", not old,
                              f"Oldest active key is {oldest} days old", {"oldest_days": oldest})


@fixer("AWS-IAM-004")
def _fix_key_age(inv, rid):
    u = find(inv.get("iam_users"), "name", rid.split("/")[-1])
    if not u:
        return False
    for k in u.get("access_keys", []):
        k["age_days"] = 0
    return True


@rule("AWS-IAM-005", "aws", "IAM", "IAM principal has full administrator privileges", "high",
      "Avoid attaching AdministratorAccess (or Action * on Resource *) directly to users and roles.",
      ["access"],
      "The AdministratorAccess managed policy, or an inline policy allowing *:*, is attached.",
      "Anyone who compromises this identity (or a workload using the role) controls the whole account.",
      ["Identify the actions this principal actually uses (IAM Access Analyzer / last accessed data).",
       "Replace AdministratorAccess with a scoped policy.",
       "Keep break-glass admin access behind MFA and SSO."],
      cli="aws iam detach-role-policy --role-name {resource} --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
      refs=["CIS AWS 1.16"], asset="identity")
def admin_policy(inv):
    acct = inv.get("account_id", "account")
    for u in inv.get("iam_users", []):
        if u.get("attached_policies") is None:
            continue  # the policy read failed: unknown is neither admin nor scoped
        adm = "AdministratorAccess" in u["attached_policies"]
        yield CheckResult(f"arn:aws:iam::{acct}:user/{u['name']}", not adm,
                          "AdministratorAccess attached" if adm else "Scoped permissions")
    for r in inv.get("iam_roles", []):
        if r.get("policies") is None:
            continue
        adm = "AdministratorAccess" in r["policies"]
        yield CheckResult(f"arn:aws:iam::{acct}:role/{r['name']}", not adm,
                          "AdministratorAccess attached" if adm else "Scoped permissions")


@fixer("AWS-IAM-005")
def _fix_admin(inv, rid):
    name = rid.split("/")[-1]
    for coll, key in (("iam_users", "attached_policies"), ("iam_roles", "policies")):
        it = find(inv.get(coll), "name", name)
        if it and "AdministratorAccess" in (it.get(key) or []):
            it[key] = [p for p in it[key] if p != "AdministratorAccess"] + ["ReadOnlyAccess"]
            return True
    return False


@rule("AWS-IAM-006", "aws", "IAM", "Account password policy is weak", "medium",
      "Password policy should require at least 14 characters and prevent reuse.",
      ["credentials"],
      "The IAM account password policy is missing or allows short passwords.",
      "Short passwords are easy to brute-force or guess.",
      ["Set minimum length to 14+.", "Prevent reuse of the last 24 passwords."],
      cli="aws iam update-account-password-policy --minimum-password-length 14 --password-reuse-prevention 24 "
          "--require-symbols --require-numbers --require-uppercase-characters --require-lowercase-characters",
      refs=["CIS AWS 1.8", "CIS AWS 1.9"])
def password_policy(inv):
    acct = inv.get("account") or {}
    if "password_policy" in acct:
        pp = acct.get("password_policy") or {}
        ok = pp.get("min_length", 0) >= 14 and pp.get("reuse_prevention", 0) >= 24
        yield CheckResult(f"arn:aws:iam::{inv.get('account_id', 'account')}:password-policy", ok,
                          f"min length {pp.get('min_length', 'not set')}, reuse prevention "
                          f"{pp.get('reuse_prevention', 'not set')}")


@fixer("AWS-IAM-006")
def _fix_pp(inv, rid):
    inv.setdefault("account", {})["password_policy"] = {"min_length": 14, "reuse_prevention": 24}
    return True


@rule("AWS-EC2-001", "aws", "EC2", "Security group allows SSH/RDP from the internet", "critical",
      "Administrative ports (22, 3389) must not be open to 0.0.0.0/0.",
      ["network"],
      "An inbound rule allows TCP 22 or 3389 from 0.0.0.0/0 or ::/0.",
      "Internet-wide scanners find open SSH/RDP within minutes and start brute-force and exploit attempts. This is "
      "usually the first hop of a cloud attack path.",
      ["Remove the 0.0.0.0/0 rule for port 22/3389.",
       "Use AWS Systems Manager Session Manager (no inbound ports) or restrict to a VPN / office CIDR."],
      terraform='''
resource "aws_vpc_security_group_ingress_rule" "{resource}_ssh_vpn_only" {
  security_group_id = "{resource}"
  cidr_ipv4         = "10.0.0.0/8"   # VPN / bastion range only
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
}''',
      cli="aws ec2 revoke-security-group-ingress --group-id {resource} --protocol tcp --port 22 --cidr 0.0.0.0/0",
      refs=["CIS AWS 5.2", "CIS AWS 5.3"], asset="network")
def sg_admin_ports(inv):
    for sg in inv.get("security_groups", []):
        bad = []
        for r in sg.get("ingress", []):
            if open_to_world(r.get("cidr")):
                for p, name in ADMIN_PORTS.items():
                    if port_in(p, r.get("from", 0), r.get("to", 65535)):
                        bad.append(f"{name} ({p})")
        yield CheckResult(f"{sg['id']}", not bad,
                          f"Open to 0.0.0.0/0: {', '.join(sorted(set(bad)))}" if bad else "No admin ports open",
                          {"ports": sorted(set(bad)), "name": sg.get("name")})


@fixer("AWS-EC2-001")
def _fix_sg(inv, rid):
    sg = find(inv.get("security_groups"), "id", rid)
    if not sg:
        return False
    for r in sg.get("ingress", []):
        if open_to_world(r.get("cidr")) and any(port_in(p, r.get("from", 0), r.get("to", 65535)) for p in ADMIN_PORTS):
            r["cidr"] = "10.0.0.0/8"
    return True


def _all_open(r):
    try:
        wide = int(r.get("from", 1)) <= 0 and int(r.get("to", 0)) >= 65535
    except (TypeError, ValueError):
        wide = False
    return open_to_world(r.get("cidr")) and (str(r.get("protocol")) == "-1" or wide)


@rule("AWS-EC2-002", "aws", "EC2", "Security group allows all traffic from the internet", "high",
      "No security group should allow all ports/protocols from 0.0.0.0/0.",
      ["network"],
      "An inbound rule allows protocol -1 (all) or port range 0-65535 from anywhere.",
      "Every service on the instance (databases, admin panels, debug ports) becomes reachable from the internet.",
      ["Replace the allow-all rule with only the ports the workload needs (e.g. 443).",
       "Put public services behind a load balancer."],
      cli="aws ec2 revoke-security-group-ingress --group-id {resource} --ip-permissions "
          "IpProtocol=-1,IpRanges=[{CidrIp=0.0.0.0/0}]",
      asset="network")
def sg_all_open(inv):
    for sg in inv.get("security_groups", []):
        bad = any(_all_open(r) for r in sg.get("ingress", []))
        yield CheckResult(sg["id"], not bad, "All traffic allowed from 0.0.0.0/0" if bad else "Restricted",
                          {"name": sg.get("name")})


@fixer("AWS-EC2-002")
def _fix_sg_all(inv, rid):
    sg = find(inv.get("security_groups"), "id", rid)
    if not sg:
        return False
    sg["ingress"] = [r for r in sg.get("ingress", []) if not _all_open(r)]
    return True


@rule("AWS-EC2-003", "aws", "EC2", "EC2 instance allows IMDSv1 (metadata v2 not required)", "high",
      "Require IMDSv2 tokens to block SSRF-based credential theft.",
      ["hardening"],
      "HttpTokens is 'optional', so the instance metadata service answers plain GET requests.",
      "An SSRF bug in any app on the instance lets an attacker read the instance role's temporary credentials "
      "(the pattern behind the 2019 Capital One breach).",
      ["Confirm your SDKs support IMDSv2 (all current AWS SDKs do).", "Set HttpTokens=required on the instance.",
       "Set the account default to IMDSv2 for new instances."],
      terraform='''
resource "aws_instance" "{resource}" {
  # ...existing arguments...
  metadata_options {
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }
}''',
      cli="aws ec2 modify-instance-metadata-options --instance-id {resource} --http-tokens required "
          "--http-endpoint enabled",
      refs=["CIS AWS 5.6"], asset="compute")
def imdsv2(inv):
    for i in inv.get("ec2_instances", []):
        yield CheckResult(i["id"], bool(i.get("imdsv2_required")),
                          "IMDSv2 required" if i.get("imdsv2_required") else "IMDSv1 allowed", {"name": i.get("name")})


@fixer("AWS-EC2-003")
def _fix_imds(inv, rid):
    i = find(inv.get("ec2_instances"), "id", rid)
    if i:
        i["imdsv2_required"] = True
    return bool(i)


@rule("AWS-EC2-004", "aws", "EC2", "EBS volume is not encrypted", "medium",
      "EBS volumes and snapshots should be encrypted at rest.",
      ["encryption_rest"],
      "The instance's EBS volume was created without encryption.",
      "Snapshots of the volume can be shared or copied in cleartext; fails encryption-at-rest controls.",
      ["Enable EBS encryption by default for the region.",
       "Snapshot the volume, copy the snapshot with encryption, and replace the volume."],
      terraform='''
resource "aws_ebs_encryption_by_default" "this" {
  enabled = true
}''',
      cli="aws ec2 enable-ebs-encryption-by-default",
      refs=["CIS AWS 2.2.1"])
def ebs_enc(inv):
    for i in inv.get("ec2_instances", []):
        if "ebs_encrypted" in i and i["ebs_encrypted"] is not None:
            yield CheckResult(i["id"], bool(i["ebs_encrypted"]),
                              "Encrypted" if i["ebs_encrypted"] else "Root volume unencrypted", {"name": i.get("name")})


@fixer("AWS-EC2-004")
def _fix_ebs(inv, rid):
    i = find(inv.get("ec2_instances"), "id", rid)
    if i:
        i["ebs_encrypted"] = True
    return bool(i)


@rule("AWS-RDS-001", "aws", "RDS", "RDS database is publicly accessible", "critical",
      "Databases should not have a public endpoint.",
      ["network", "public_data"],
      "PubliclyAccessible is true, so the DB gets a public DNS name/IP.",
      "The database login is exposed to internet-wide brute force and to any leaked credentials.",
      ["Set PubliclyAccessible=false.", "Reach the DB from inside the VPC (app subnets, VPN, or SSM port forwarding)."],
      terraform='''
resource "aws_db_instance" "{resource}" {
  # ...existing arguments...
  publicly_accessible = false
}''',
      cli="aws rds modify-db-instance --db-instance-identifier {resource} --no-publicly-accessible --apply-immediately",
      refs=["CIS AWS 2.3.3"], asset="datastore")
def rds_public(inv):
    for d in inv.get("rds_instances", []):
        yield CheckResult(d["id"], not d.get("publicly_accessible"),
                          "Public endpoint" if d.get("publicly_accessible") else "Private")


@fixer("AWS-RDS-001")
def _fix_rds_pub(inv, rid):
    d = find(inv.get("rds_instances"), "id", rid)
    if d:
        d["publicly_accessible"] = False
    return bool(d)


@rule("AWS-RDS-002", "aws", "RDS", "RDS storage is not encrypted", "high",
      "RDS instances should use storage encryption.",
      ["encryption_rest"],
      "StorageEncrypted is false.",
      "Database files, automated backups and snapshots are stored unencrypted.",
      ["Take a snapshot, copy it with encryption enabled, restore a new instance, and cut over."],
      terraform='''
resource "aws_db_instance" "{resource}" {
  # ...existing arguments...
  storage_encrypted = true
  kms_key_id        = aws_kms_key.rds.arn
}''',
      cli="aws rds copy-db-snapshot --source-db-snapshot-identifier <snap> --target-db-snapshot-identifier "
          "{resource}-enc --kms-key-id alias/aws/rds",
      refs=["CIS AWS 2.3.1"], asset="datastore")
def rds_enc(inv):
    for d in inv.get("rds_instances", []):
        yield CheckResult(d["id"], bool(d.get("storage_encrypted")),
                          "Encrypted" if d.get("storage_encrypted") else "Unencrypted")


@fixer("AWS-RDS-002")
def _fix_rds_enc(inv, rid):
    d = find(inv.get("rds_instances"), "id", rid)
    if d:
        d["storage_encrypted"] = True
    return bool(d)


@rule("AWS-RDS-003", "aws", "RDS", "RDS automated backup retention below 7 days", "medium",
      "Keep at least 7 days of automated backups.",
      ["backup"],
      "BackupRetentionPeriod is 0 (disabled) or under 7 days.",
      "Point-in-time recovery after corruption, a bad deploy or ransomware may be impossible.",
      ["Set the backup retention period to 7-35 days."],
      terraform='''
resource "aws_db_instance" "{resource}" {
  # ...existing arguments...
  backup_retention_period = 7
}''',
      cli="aws rds modify-db-instance --db-instance-identifier {resource} --backup-retention-period 7 "
          "--apply-immediately", asset="datastore")
def rds_backup(inv):
    for d in inv.get("rds_instances", []):
        days = d.get("backup_retention_days", 0)
        yield CheckResult(d["id"], days >= 7, f"Retention: {days} days")


@fixer("AWS-RDS-003")
def _fix_rds_bk(inv, rid):
    d = find(inv.get("rds_instances"), "id", rid)
    if d:
        d["backup_retention_days"] = 7
    return bool(d)


@rule("AWS-LOG-001", "aws", "CloudTrail", "CloudTrail is not enabled in all regions", "high",
      "A multi-region trail with log file validation should record all API activity.",
      ["logging"],
      "No trail exists, it is single-region, or log file validation is off.",
      "Without an audit trail you cannot investigate an incident or prove who changed what.",
      ["Create a multi-region trail with log file validation.", "Send it to a dedicated, locked-down S3 bucket."],
      terraform='''
resource "aws_cloudtrail" "org_trail" {
  name                          = "shieldiq-org-trail"
  s3_bucket_name                = aws_s3_bucket.audit_logs.id
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  include_global_service_events = true
}''',
      cli="aws cloudtrail create-trail --name shieldiq-org-trail --s3-bucket-name <audit-bucket> "
          "--is-multi-region-trail --enable-log-file-validation && aws cloudtrail start-logging --name shieldiq-org-trail",
      refs=["CIS AWS 3.1", "CIS AWS 3.2"])
def cloudtrail(inv):
    ct = inv.get("cloudtrail")
    if ct is not None and ct.get("enabled") is not None:
        ok = ct.get("enabled") and ct.get("multi_region") and ct.get("log_file_validation")
        detail = "enabled={}, multi-region={}, log validation={}".format(
            ct.get("enabled"), ct.get("multi_region"), ct.get("log_file_validation"))
        yield CheckResult(f"arn:aws:cloudtrail:{inv.get('region', 'us-east-1')}:{inv.get('account_id', 'account')}:trail",
                          bool(ok), detail)


@fixer("AWS-LOG-001")
def _fix_ct(inv, rid):
    inv["cloudtrail"] = {"enabled": True, "multi_region": True, "log_file_validation": True}
    return True


@rule("AWS-KMS-001", "aws", "KMS", "KMS customer managed key rotation disabled", "low",
      "Enable automatic yearly rotation for symmetric customer managed keys.",
      ["encryption_rest"],
      "EnableKeyRotation is false.",
      "Key material is never rotated, increasing the impact of a key compromise.",
      ["Enable automatic key rotation."],
      terraform='''
resource "aws_kms_key" "{resource}" {
  # ...existing arguments...
  enable_key_rotation = true
}''',
      cli="aws kms enable-key-rotation --key-id {resource}", refs=["CIS AWS 3.6"])
def kms_rotation(inv):
    for k in inv.get("kms_keys", []):
        if k.get("rotation_enabled") is None:
            continue  # the rotation read failed: unknown is neither on nor off
        yield CheckResult(k["id"], bool(k.get("rotation_enabled")),
                          "Rotation on" if k.get("rotation_enabled") else "Rotation off")


@fixer("AWS-KMS-001")
def _fix_kms(inv, rid):
    k = find(inv.get("kms_keys"), "id", rid)
    if k:
        k["rotation_enabled"] = True
    return bool(k)


@rule("AWS-MON-001", "aws", "GuardDuty", "GuardDuty threat detection is disabled", "medium",
      "GuardDuty should be enabled to detect compromised credentials and instances.",
      ["monitoring"],
      "No GuardDuty detector is enabled in the region.",
      "Crypto-mining, credential exfiltration and recon activity go unnoticed.",
      ["Enable GuardDuty in every region (or via AWS Organizations delegated admin)."],
      terraform='''
resource "aws_guardduty_detector" "main" {
  enable = true
}''',
      cli="aws guardduty create-detector --enable")
def guardduty(inv):
    if "guardduty_enabled" in inv:
        yield CheckResult(f"arn:aws:guardduty:{inv.get('region', 'us-east-1')}:{inv.get('account_id', 'account')}",
                          bool(inv["guardduty_enabled"]), "Enabled" if inv["guardduty_enabled"] else "Disabled")


@fixer("AWS-MON-001")
def _fix_gd(inv, rid):
    inv["guardduty_enabled"] = True
    return True
