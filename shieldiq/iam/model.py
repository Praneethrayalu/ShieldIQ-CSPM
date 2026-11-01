"""Normalized IAM authorization model built from a scan inventory.

Two inputs are supported:
- `inv["iam"]` - the authorization model the live collector writes (v2.3): users, groups, roles, managed
  policies (default version document), inline policies, group membership, permissions boundaries, role trust
  policies, SCPs and resource policies, each with an explicit collection status.
- older inventories (v2.2 live scans, demo data, JSON snapshots) that only carry `iam_users` / `iam_roles` with
  `policy_documents` and/or policy *names*. These are converted; anything they do not carry (boundaries, SCPs,
  trust policies) is marked UNKNOWN, never "none".

A policy known only by its name has no document: it is UNKNOWN, not proof of a permission (the one exception is an
AWS-managed policy referenced by its `arn:aws:iam::aws:policy/...` ARN whose content ShieldIQ ships, see
KNOWN_AWS_MANAGED; the evidence says so).
"""
from dataclasses import dataclass, field
from typing import List, Optional

# Content of a few AWS-managed policies that matter for privilege analysis (AWS documents these; they are
# effectively immutable). Only used when the policy is referenced by its AWS-managed ARN and no document was read.
KNOWN_AWS_MANAGED = {
    "arn:aws:iam::aws:policy/AdministratorAccess": {
        "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]},
    "arn:aws:iam::aws:policy/IAMFullAccess": {
        "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["iam:*", "organizations:DescribeAccount",
                                                                               "organizations:DescribeOrganization",
                                                                               "organizations:DescribeOrganizationalUnit",
                                                                               "organizations:DescribePolicy",
                                                                               "organizations:ListChildren",
                                                                               "organizations:ListParents",
                                                                               "organizations:ListPoliciesForTarget",
                                                                               "organizations:ListRoots",
                                                                               "organizations:ListPolicies",
                                                                               "organizations:ListTargetsForPolicy"],
                                                "Resource": "*"}]},
    "arn:aws:iam::aws:policy/PowerUserAccess": {
        "Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "NotAction": ["iam:*", "organizations:*", "account:*"], "Resource": "*"},
            {"Effect": "Allow", "Action": ["account:GetAccountInformation", "account:GetPrimaryEmail",
                                           "account:ListRegions", "iam:CreateServiceLinkedRole",
                                           "iam:DeleteServiceLinkedRole", "iam:ListRoles",
                                           "organizations:DescribeOrganization"], "Resource": "*"}]},
}


@dataclass
class PolicyRef:
    name: str
    arn: Optional[str]
    kind: str            # managed | aws-managed | inline | boundary | scp | resource | trust
    via: str             # direct | group:<name> | role | boundary | scp:<target> | resource
    document: Optional[dict]
    origin: str = "collected"   # collected | builtin-aws-managed | unreadable | name-only
    version: Optional[str] = None

    def label(self):
        v = f" {self.version}" if self.version else ""
        return f"{self.kind} policy {self.name}{v} ({self.via})"

    def to_dict(self):
        return {"name": self.name, "arn": self.arn, "kind": self.kind, "via": self.via, "origin": self.origin,
                "version": self.version, "readable": self.document is not None}


@dataclass
class Principal:
    kind: str            # user | role
    name: str
    arn: str
    account_id: str
    identity: List[PolicyRef] = field(default_factory=list)
    identity_complete: Optional[bool] = True  # every attached/inline/group policy LIST was read
    groups: Optional[List[str]] = None        # None = membership unknown
    boundary_status: str = "unknown"          # none | present | unknown
    boundary: Optional[PolicyRef] = None
    trust_policy: Optional[dict] = None       # roles only
    trust_status: str = "unknown"             # collected | unknown (roles)
    service_linked: bool = False
    tags: dict = field(default_factory=dict)
    path: str = "/"

    def sources_summary(self):
        out = {"direct": [], "group": [], "role": []}
        for p in self.identity:
            key = "group" if p.via.startswith("group:") else ("role" if self.kind == "role" else "direct")
            out[key].append(p.to_dict())
        return out


def _doc(d):
    if isinstance(d, dict):
        return d
    if isinstance(d, str):
        import json
        from urllib.parse import unquote
        for cand in (d, unquote(d)):
            try:
                return json.loads(cand)
            except ValueError:
                continue
    return None


class AuthzModel:
    """Everything the evaluator needs about one AWS account."""

    def __init__(self, account_id):
        self.account_id = account_id or "000000000000"
        self.principals = {}          # arn -> Principal
        self.groups = {}              # name -> {"arn", "policies": [PolicyRef], "complete": bool}
        self.scp = {"status": "unknown", "levels": [], "note": "SCP data not collected"}
        self.resource_policies = {}   # resource arn -> {"status", "document", "name"}
        self.sources = {}             # data source -> {"status", "errors": [...], "detail"}
        self.errors = []
        self.origin = "unknown"

    # convenience
    def users(self):
        return [p for p in self.principals.values() if p.kind == "user"]

    def roles(self):
        return [p for p in self.principals.values() if p.kind == "role"]

    def get(self, kind, name):
        for p in self.principals.values():
            if p.kind == kind and p.name == name:
                return p
        return None

    def managed_policy_arns(self):
        out = {}
        for p in self.principals.values():
            for r in p.identity:
                if r.kind in ("managed", "aws-managed") and r.arn:
                    out.setdefault(r.arn, r)
        return out

    def completeness(self):
        return {"origin": self.origin, "sources": self.sources, "errors": self.errors[:200],
                "scp_status": self.scp.get("status"), "scp_note": self.scp.get("note")}


# ------------------------------------------------------------------ builders
def _managed_ref(name, arn, via, policies):
    pol = (policies or {}).get(arn) if arn else None
    aws_managed = bool(arn and arn.startswith("arn:aws:iam::aws:policy/"))
    kind = "aws-managed" if aws_managed else "managed"
    if pol is not None and pol.get("document") is not None:
        return PolicyRef(name, arn, kind, via, _doc(pol["document"]), "collected", pol.get("default_version"))
    if arn in KNOWN_AWS_MANAGED:
        return PolicyRef(name, arn, kind, via, KNOWN_AWS_MANAGED[arn], "builtin-aws-managed")
    return PolicyRef(name, arn, kind, via, None, "unreadable" if pol is not None else "name-only")


def from_rich(iam, account_id):
    """inv["iam"] (v2.3 collector) -> AuthzModel."""
    m = AuthzModel(iam.get("account_id") or account_id)
    m.origin = iam.get("origin", "aws-live")
    pols = iam.get("policies") or {}
    for g in iam.get("groups") or []:
        refs, complete = [], True
        if g.get("attached") is None or g.get("inline") is None:
            complete = False
        for a in g.get("attached") or []:
            refs.append(_managed_ref(a.get("name"), a.get("arn"), "group:" + g["name"], pols))
        for i in g.get("inline") or []:
            refs.append(PolicyRef(i.get("name"), None, "inline", "group:" + g["name"], _doc(i.get("document")),
                                  "collected" if i.get("document") is not None else "unreadable"))
        m.groups[g["name"]] = {"arn": g.get("arn"), "policies": refs, "complete": complete}

    def boundary(p):
        b = p.get("boundary") or {"status": "unknown"}
        st = b.get("status", "unknown")
        if st != "present":
            return st, None
        return "present", _managed_ref(b.get("name") or (b.get("arn") or "").split("/")[-1], b.get("arn"),
                                       "boundary", pols)

    for kind, coll in (("user", "users"), ("role", "roles")):
        for p in iam.get(coll) or []:
            pr = Principal(kind, p["name"], p.get("arn") or f"arn:aws:iam::{m.account_id}:{kind}/{p['name']}",
                           m.account_id, path=p.get("path") or "/", tags=p.get("tags") or {})
            complete = p.get("attached") is not None and p.get("inline") is not None
            for a in p.get("attached") or []:
                pr.identity.append(_managed_ref(a.get("name"), a.get("arn"), "direct" if kind == "user" else "role",
                                                pols))
            for i in p.get("inline") or []:
                pr.identity.append(PolicyRef(i.get("name"), None, "inline", "direct" if kind == "user" else "role",
                                             _doc(i.get("document")),
                                             "collected" if i.get("document") is not None else "unreadable"))
            if kind == "user":
                pr.groups = p.get("groups")
                if pr.groups is None:
                    complete = False
                for gname in pr.groups or []:
                    g = m.groups.get(gname)
                    if g is None:
                        complete = False
                        continue
                    pr.identity.extend(g["policies"])
                    complete = complete and g["complete"]
            else:
                pr.trust_policy = _doc(p.get("trust_policy"))
                pr.trust_status = "collected" if pr.trust_policy is not None else "unknown"
                pr.service_linked = bool(p.get("service_linked")) or (pr.path or "").startswith("/aws-service-role/")
            # complete = every list was read AND every document in it is readable
            pr.identity_complete = complete and all(r.document is not None for r in pr.identity)
            pr.boundary_status, pr.boundary = boundary(p)
            m.principals[pr.arn] = pr
    m.scp = iam.get("scps") or m.scp
    for arn, rp in (iam.get("resource_policies") or {}).items():
        m.resource_policies[arn] = {"status": rp.get("status", "unknown"), "document": _doc(rp.get("document")),
                                    "name": rp.get("name") or arn}
    m.sources = iam.get("sources") or {}
    m.errors = iam.get("errors") or []
    return m


def from_legacy(inv):
    """v2.2-and-older inventories -> AuthzModel. Missing layers are UNKNOWN."""
    acct = str(inv.get("account_id") or "000000000000")
    m = AuthzModel(acct)
    src = inv.get("_source") or ("aws-live" if inv.get("_errors") is not None else "snapshot")
    m.origin = f"legacy:{src}"
    for kind, coll, names_key in (("user", "iam_users", "attached_policies"), ("role", "iam_roles", "policies")):
        for p in inv.get(coll) or []:
            arn = p.get("arn") or f"arn:aws:iam::{acct}:{kind}/{p.get('name')}"
            pr = Principal(kind, p.get("name"), arn, acct)
            docs = p.get("policy_documents")
            names = p.get(names_key)
            if docs is not None and ("policies_complete" in p or docs):
                for d in docs:
                    s = str(d.get("source") or "inline")
                    via, kindp, parn = "direct" if kind == "user" else "role", "inline", None
                    if s.startswith("managed:"):
                        kindp, parn = "managed", s.split(":", 1)[1]
                    elif s.startswith("group-managed:"):
                        _, g, parn = s.split(":", 2)
                        kindp, via = "managed", "group:" + g
                    elif s.startswith("group-inline:"):
                        via = "group:" + s.split(":", 1)[1]
                    if parn and parn.startswith("arn:aws:iam::aws:policy/"):
                        kindp = "aws-managed"
                    pr.identity.append(PolicyRef(d.get("name"), parn, kindp, via, _doc(d.get("document"))))
                pr.identity_complete = bool(p.get("policies_complete", False))
            else:
                # names only (demo data / old snapshots): the documents are unknown
                for n in names or []:
                    parn = f"arn:aws:iam::aws:policy/{n}" if f"arn:aws:iam::aws:policy/{n}" in KNOWN_AWS_MANAGED else None
                    # a bare name is NOT proof: even "AdministratorAccess" may be a customer policy with that name
                    pr.identity.append(PolicyRef(n, parn, "managed", "direct" if kind == "user" else "role", None,
                                                 "name-only"))
                pr.identity_complete = False
            pr.groups = p.get("groups")
            if kind == "role":
                pr.trust_policy = _doc(p.get("trust_policy"))
                pr.trust_status = "collected" if pr.trust_policy is not None else "unknown"
                pr.service_linked = bool(p.get("service_linked"))
            b = p.get("permissions_boundary") or {"status": "unknown"}
            pr.boundary_status = b.get("status", "unknown")
            if pr.boundary_status == "present":
                pr.boundary = PolicyRef(b.get("name") or (b.get("arn") or "").split("/")[-1], b.get("arn"), "boundary",
                                        "boundary", _doc(b.get("document")) or KNOWN_AWS_MANAGED.get(b.get("arn")),
                                        "collected" if b.get("document") is not None else "unreadable")
            m.principals[arn] = pr
    for g, meta in (inv.get("iam_groups") or {}).items() if isinstance(inv.get("iam_groups"), dict) else []:
        m.groups[g] = {"arn": meta.get("arn"), "policies": [], "complete": False}
    ctx = inv.get("iam_context") if isinstance(inv.get("iam_context"), dict) else None
    m.scp = {"status": "unknown", "levels": [], "note": "this inventory carries no Organizations/SCP data"}
    if ctx is not None:
        m.scp = ctx.get("scps") or m.scp
        for arn, rp in (ctx.get("resource_policies") or {}).items():
            m.resource_policies[arn] = {"status": rp.get("status", "unknown"), "document": _doc(rp.get("document")),
                                        "name": rp.get("name") or arn}
        m.sources = dict(ctx.get("sources") or {})
        m.errors = list(ctx.get("errors") or [])
        m.sources.setdefault("identity_policies", {
            "status": "partial" if any(not p.identity_complete for p in m.principals.values()) else "collected",
            "detail": "per-principal reads (ListAttached*/List*Policies/GetPolicyVersion)"})
        return m
    m.sources = {"identity_policies": {"status": "partial" if any(not p.identity_complete for p in m.principals.values())
                                       else "collected", "detail": "from the legacy inventory"},
                 "permissions_boundaries": {"status": "not_collected", "detail": "not present in this inventory"},
                 "scps": {"status": "not_collected", "detail": "not present in this inventory"},
                 "trust_policies": {"status": "not_collected" if not any(p.trust_policy for p in m.roles())
                                    else "collected"},
                 "resource_policies": {"status": "not_collected"}}
    return m


def build_model(inv):
    inv = inv or {}
    if isinstance(inv.get("iam"), dict) and (inv["iam"].get("users") is not None or inv["iam"].get("roles") is not None):
        return from_rich(inv["iam"], str(inv.get("account_id") or ""))
    return from_legacy(inv)
