"""IAM authorization-data collection for the effective-permission engine (v2.3). Read-only.

Collected (every call paginated, every failure recorded as a structured error with the API, the affected resource,
the AWS error code and a kind: denied / throttled / not_found / error):
- iam:GetAccountAuthorizationDetails - users (group membership, attached + inline policies, permissions boundary,
  tags), groups, roles (trust policy, boundary, instance profiles) and customer-managed policies with their
  default version document. AWS-managed policies that are attached are read with GetPolicy + GetPolicyVersion.
- When GetAccountAuthorizationDetails is not allowed, the per-call data the legacy collector already read is used
  and boundaries are read with iam:GetUser / iam:GetRole (unknown when those fail).
- AWS Organizations SCPs (organizations:DescribeOrganization, ListRoots, ListParents, ListPoliciesForTarget,
  DescribePolicy) when the account is in an organization and the credentials may read them. Member accounts
  usually cannot: SCPs are then "unavailable" and every Allowed decision that depends on them is Indeterminate.
- S3 bucket policies (s3:GetBucketPolicy) as resource-based policies.

These sources are reported in `inv["iam"]["sources"]` (and the scan-wide `inv["_sources"]` completeness indicator).
They are not added to `inv["_errors"]`: their absence never produces a pass - the evaluator turns it into an
Indeterminate decision and the UI shows the gap - and the core v2.2 coverage semantics stay unchanged.
"""
import json

THROTTLE = ("throttl", "requestlimitexceeded", "toomanyrequests", "slowdown")


def _sanitize(exc):
    code = exc.__class__.__name__
    status = None
    resp = getattr(exc, "response", None)
    if isinstance(resp, dict):
        code = (resp.get("Error") or {}).get("Code") or code
        status = (resp.get("ResponseMetadata") or {}).get("HTTPStatusCode")
    return code, status


def kind_of(code):
    cl = (code or "").lower()
    if any(t in cl for t in THROTTLE):
        return "throttled"
    if any(t in cl for t in ("accessdenied", "unauthorized", "authfailure", "forbidden", "notauthorized")):
        return "denied"
    if any(t in cl for t in ("nosuchentity", "notfound", "nosuch")):
        return "not_found"
    return "error"


def _doc(d):
    if isinstance(d, dict) or d is None:
        return d
    from urllib.parse import unquote
    for cand in (d, unquote(str(d))):
        try:
            return json.loads(cand)
        except ValueError:
            continue
    return None


def _pages(client, method, key, **kw):
    can = getattr(client, "can_paginate", None)
    try:
        paginated = callable(can) and can(method) is True
    except TypeError:
        paginated = False
    if paginated:
        out = []
        for page in client.get_paginator(method).paginate(**kw):
            out.extend(page.get(key) or [])
        return out
    # manual Marker pagination for duck-typed clients
    out, marker = [], None
    for _ in range(1000):
        resp = getattr(client, method)(**({**kw, "Marker": marker} if marker else kw))
        out.extend(resp.get(key) or [])
        if resp.get("IsTruncated") and resp.get("Marker"):
            marker = resp["Marker"]
        else:
            break
    return out


class _Rec:
    def __init__(self):
        self.errors = []

    def __call__(self, api, exc, resource=None):
        code, status = _sanitize(exc)
        e = {"api": api, "resource": resource, "code": code, "status": status, "kind": kind_of(code)}
        self.errors.append(e)
        return e


def _gaad(iam):
    """All four lists, paginated (keys differ per list, so pages are merged manually)."""
    out = {"UserDetailList": [], "GroupDetailList": [], "RoleDetailList": [], "Policies": []}
    flt = ["User", "Role", "Group", "LocalManagedPolicy"]
    can = getattr(iam, "can_paginate", None)
    try:
        paginated = callable(can) and can("get_account_authorization_details") is True
    except TypeError:
        paginated = False
    if paginated:
        pages = iam.get_paginator("get_account_authorization_details").paginate(Filter=flt)
    else:
        def gen():
            marker = None
            for _ in range(1000):
                kw = {"Filter": flt}
                if marker:
                    kw["Marker"] = marker
                r = iam.get_account_authorization_details(**kw)
                yield r
                if not (r.get("IsTruncated") and r.get("Marker")):
                    return
                marker = r["Marker"]
        pages = gen()
    for page in pages:
        for k in out:
            out[k].extend(page.get(k) or [])
    return out


def _boundary(pb):
    if not pb:
        return {"status": "none"}
    arn = pb.get("PermissionsBoundaryArn")
    return {"status": "present", "arn": arn, "name": (arn or "").split("/")[-1]}


def collect_authorization(iam, account_id, legacy_users=None, legacy_roles=None, managed_doc=None, rec=None):
    """Returns the rich `inv["iam"]` dict, or None when GetAccountAuthorizationDetails is not readable (the caller
    then enriches the legacy entries instead, see enrich_legacy)."""
    rec = rec or _Rec()
    try:
        g = _gaad(iam)
    except Exception as exc:
        rec("iam:GetAccountAuthorizationDetails", exc)
        return None
    policies = {}
    for p in g["Policies"]:
        default = next((v for v in p.get("PolicyVersionList") or [] if v.get("IsDefaultVersion")), None)
        policies[p["Arn"]] = {"name": p.get("PolicyName"), "default_version": p.get("DefaultVersionId"),
                              "document": _doc(default.get("Document")) if default else None,
                              "versions": [{"id": v.get("VersionId"), "is_default": bool(v.get("IsDefaultVersion"))}
                                           for v in p.get("PolicyVersionList") or []]}

    def attached(lst):
        out = []
        for a in lst or []:
            arn = a.get("PolicyArn")
            if arn and arn not in policies and managed_doc is not None:
                doc = managed_doc(arn)
                policies[arn] = {"name": a.get("PolicyName"), "document": doc, "default_version": None,
                                 "aws_managed": arn.startswith("arn:aws:iam::aws:policy/")}
            out.append({"name": a.get("PolicyName"), "arn": arn})
        return out

    def inline(lst):
        return [{"name": i.get("PolicyName"), "document": _doc(i.get("PolicyDocument"))} for i in lst or []]

    def tags(lst):
        return {t.get("Key"): t.get("Value") for t in lst or [] if isinstance(t, dict)}

    users = [{"name": u["UserName"], "arn": u.get("Arn"), "id": u.get("UserId"), "path": u.get("Path", "/"),
              "groups": list(u.get("GroupList") or []), "attached": attached(u.get("AttachedManagedPolicies")),
              "inline": inline(u.get("UserPolicyList")), "boundary": _boundary(u.get("PermissionsBoundary")),
              "tags": tags(u.get("Tags"))} for u in g["UserDetailList"]]
    groups = [{"name": x["GroupName"], "arn": x.get("Arn"), "attached": attached(x.get("AttachedManagedPolicies")),
               "inline": inline(x.get("GroupPolicyList"))} for x in g["GroupDetailList"]]
    roles = [{"name": r["RoleName"], "arn": r.get("Arn"), "path": r.get("Path", "/"),
              "service_linked": (r.get("Path") or "").startswith("/aws-service-role/"),
              "trust_policy": _doc(r.get("AssumeRolePolicyDocument")),
              "attached": attached(r.get("AttachedManagedPolicies")), "inline": inline(r.get("RolePolicyList")),
              "boundary": _boundary(r.get("PermissionsBoundary")), "tags": tags(r.get("Tags")),
              "instance_profiles": [ip.get("InstanceProfileName") for ip in r.get("InstanceProfileList") or []]}
             for r in g["RoleDetailList"]]
    # boundary policies may be customer-managed policies that are not attached to anyone: make sure we have them
    for p in users + roles:
        b = p["boundary"]
        if b.get("status") == "present" and b.get("arn") not in policies and managed_doc is not None:
            policies[b["arn"]] = {"name": b.get("name"), "document": managed_doc(b["arn"]), "default_version": None}
    return {"origin": "aws-live", "account_id": account_id, "collected_with": "iam:GetAccountAuthorizationDetails",
            "users": users, "groups": groups, "roles": roles, "policies": policies}


def enrich_legacy(iam, inv, rec, managed_doc=None):
    """GAAD not readable: add boundary status (GetUser/GetRole) to the legacy entries."""
    for coll, method, key, label in (("iam_users", "get_user", "User", "UserName"),
                                     ("iam_roles", "get_role", "Role", "RoleName")):
        for p in inv.get(coll) or []:
            try:
                obj = getattr(iam, method)(**{label: p["name"]})[key]
                b = _boundary(obj.get("PermissionsBoundary"))
                if b["status"] == "present" and managed_doc is not None:
                    b["document"] = managed_doc(b["arn"])
                p["permissions_boundary"] = b
                if coll == "iam_roles" and "trust_policy" not in p and obj.get("AssumeRolePolicyDocument"):
                    p["trust_policy"] = _doc(obj["AssumeRolePolicyDocument"])
            except Exception as exc:
                rec("iam:" + method.title().replace("_", ""), exc, resource=p.get("name"))
                p["permissions_boundary"] = {"status": "unknown"}


def collect_scps(org, account_id, rec):
    """SCP levels that apply to this account. status: collected | not_applicable | management_account |
    disabled | unavailable."""
    try:
        o = org.describe_organization()["Organization"]
    except Exception as exc:
        code, _ = _sanitize(exc)
        if code == "AWSOrganizationsNotInUseException":
            return {"status": "not_applicable", "levels": [], "note": "the account is not in an AWS Organization"}
        rec("organizations:DescribeOrganization", exc)
        return {"status": "unavailable", "levels": [],
                "note": "could not read AWS Organizations (" + code + "); SCPs may restrict permissions"}
    if o.get("MasterAccountId") == account_id:
        return {"status": "management_account", "levels": [],
                "note": "management account: SCPs do not apply to it"}
    try:
        roots = _pages(org, "list_roots", "Roots")
        enabled = any(pt.get("Type") == "SERVICE_CONTROL_POLICY" and pt.get("Status") == "ENABLED"
                      for r in roots for pt in r.get("PolicyTypes") or [])
        if not enabled:
            return {"status": "disabled", "levels": [], "note": "SCP policy type is not enabled in the organization"}
        chain, child = [account_id], account_id
        for _ in range(10):
            parents = _pages(org, "list_parents", "Parents", ChildId=child)
            if not parents:
                break
            child = parents[0]["Id"]
            chain.append(child)
            if parents[0].get("Type") == "ROOT":
                break
        levels = []
        for target in reversed(chain):
            pols = _pages(org, "list_policies_for_target", "Policies", TargetId=target, Filter="SERVICE_CONTROL_POLICY")
            lvl = {"target": target, "policies": []}
            for p in pols:
                content = org.describe_policy(PolicyId=p["Id"])["Policy"].get("Content")
                lvl["policies"].append({"name": p.get("Name"), "arn": p.get("Arn"), "document": _doc(content)})
            levels.append(lvl)
        return {"status": "collected", "levels": levels, "note": f"{len(levels)} level(s) evaluated"}
    except Exception as exc:
        e = rec("organizations:ListPoliciesForTarget", exc, resource=account_id)
        return {"status": "unavailable", "levels": [],
                "note": f"SCPs could not be read ({e['code']}); member accounts usually need delegated access"}


def collect_bucket_policies(s3, bucket_names, rec):
    out = {}
    for n in bucket_names:
        arn = f"arn:aws:s3:::{n}"
        try:
            pol = s3.get_bucket_policy(Bucket=n).get("Policy")
            doc = _doc(pol)
            out[arn] = {"status": "collected" if doc is not None else "unknown", "document": doc, "name": n}
            out[arn + "/*"] = out[arn]
        except Exception as exc:
            code, _ = _sanitize(exc)
            if code == "NoSuchBucketPolicy":
                out[arn] = {"status": "none", "document": None, "name": n}
            else:
                rec("s3:GetBucketPolicy", exc, resource=n)
                out[arn] = {"status": "unknown", "document": None, "name": n}
            out[arn + "/*"] = out[arn]
    return out


def collect(session_client, region, inv, managed_doc=None):
    """Entry point used by aws_live.collect. session_client(svc, region) -> client. Mutates `inv`."""
    rec = _Rec()
    acct = inv.get("account_id")
    sources = {}
    try:
        iam = session_client("iam", None)
    except Exception as exc:  # pragma: no cover - client creation does not call AWS
        rec("iam:client", exc)
        iam = None
    rich = collect_authorization(iam, acct, managed_doc=managed_doc, rec=rec) if iam is not None else None
    if rich is not None:
        sources["authorization_details"] = {"status": "collected", "api": "iam:GetAccountAuthorizationDetails",
                                            "detail": f"{len(rich['users'])} users, {len(rich['groups'])} groups, "
                                                      f"{len(rich['roles'])} roles, {len(rich['policies'])} policies"}
        unread = [a for a, p in rich["policies"].items() if p.get("document") is None]
        sources["managed_policy_documents"] = {"status": "partial" if unread else "collected",
                                               "detail": f"{len(unread)} unreadable" if unread else "all read"}
        sources["permissions_boundaries"] = {"status": "collected"}
        sources["trust_policies"] = {"status": "collected"}
    else:
        sources["authorization_details"] = {"status": "denied" if rec.errors and rec.errors[-1]["kind"] == "denied"
                                            else "error", "api": "iam:GetAccountAuthorizationDetails",
                                            "detail": "fell back to per-principal reads"}
        if iam is not None:
            enrich_legacy(iam, inv, rec, managed_doc)
        known = [p for c in ("iam_users", "iam_roles") for p in inv.get(c) or []]
        unk = [p for p in known if (p.get("permissions_boundary") or {}).get("status") == "unknown"]
        sources["permissions_boundaries"] = {"status": "collected" if not unk else ("unavailable" if len(unk) == len(known)
                                                                                    else "partial"),
                                             "detail": f"{len(unk)} of {len(known)} principals unknown"}
        sources["trust_policies"] = {"status": "collected" if all(r.get("trust_policy") for r in inv.get("iam_roles") or [])
                                     else "partial"}
    try:
        org = session_client("organizations", None)
        scps = collect_scps(org, acct, rec)
    except Exception as exc:  # pragma: no cover
        rec("organizations:client", exc)
        scps = {"status": "unavailable", "levels": [], "note": "organizations client unavailable"}
    sources["scps"] = {"status": scps["status"], "detail": scps.get("note")}
    try:
        s3 = session_client("s3", None)
        rps = collect_bucket_policies(s3, [b["name"] for b in inv.get("s3_buckets") or []], rec)
    except Exception as exc:  # pragma: no cover
        rec("s3:client", exc)
        rps = {}
    bad = [k for k, v in rps.items() if v["status"] == "unknown" and not k.endswith("/*")]
    sources["resource_policies"] = {"status": "partial" if bad else "collected",
                                    "detail": f"S3 bucket policies; {len(bad)} unreadable. Other resource types "
                                              f"(KMS, SQS, SNS, Lambda, Secrets Manager) are not collected"}
    ctx = {"scps": scps, "resource_policies": rps, "sources": sources, "errors": rec.errors}
    if rich is not None:
        rich.update(ctx)
        inv["iam"] = rich
    else:
        inv["iam_context"] = ctx
    return inv
