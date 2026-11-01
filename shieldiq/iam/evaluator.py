"""Effective-permission evaluator (single account, identity principals).

Implements the documented AWS evaluation order for a request made by an IAM user or role in its own account:

  1. an explicit Deny in ANY applicable policy (identity, permissions boundary, SCP, resource policy) -> Denied
  2. SCPs: every level (root, each OU, the account) must Allow (not applied to the management account or to
     service-linked roles)
  3. a resource-based policy that names the principal directly can grant on its own (same account). For an IAM
     user this grant is not limited by the user's permissions boundary; for a role ARN it is (AWS docs:
     "Evaluating policies within a single account").
  4. otherwise an identity-based Allow is needed, AND the permissions boundary (if any) must Allow too.

Every input layer is tri-state. Unreadable documents, an unknown boundary, SCPs that could not be read, policy
variables or condition keys without values, and unsupported operators make the result *Indeterminate*, with the
missing pieces listed. Indeterminate is never reported as safe.

NOT modelled (documented in docs/IAM_ANALYSIS.md): session policies and role-session tags, cross-account access
(both sides), resource control policies (RCPs), VPC endpoint policies, ACLs, service-specific authorization
(e.g. KMS grants, S3 Object Ownership), the implicit "aws:SecureTransport"/request properties, and ABAC tags
unless supplied in the request context. "Allowed" therefore means "allowed by every layer ShieldIQ collected and
evaluated", not "AWS will authorize every request".
"""
from dataclasses import dataclass, field
from typing import List, Optional

from .policy import (RequestContext, eval_conditions, principal_match, statements, stmt_matches_action,
                     stmt_matches_resource, t_and, t_not, t_or)

ALLOWED, DENIED, INDETERMINATE = "Allowed", "Denied", "Indeterminate"

NOT_MODELLED = ["session policies / session tags", "cross-account access", "resource control policies (RCPs)",
                "VPC endpoint policies", "S3/ACL and KMS-grant specific authorization",
                "request-context keys not supplied (source IP, MFA, tags, time)"]


@dataclass
class Decision:
    principal: str
    action: str
    resource: str
    decision: str
    reason: str
    evidence: List[dict] = field(default_factory=list)
    layers: dict = field(default_factory=dict)
    missing: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    @property
    def allowed(self):
        return self.decision == ALLOWED

    @property
    def possible(self):
        """Allowed or Indeterminate: cannot be ruled out."""
        return self.decision in (ALLOWED, INDETERMINATE)

    def to_dict(self):
        return {"principal": self.principal, "action": self.action, "resource": self.resource,
                "decision": self.decision, "reason": self.reason, "evidence": self.evidence,
                "layers": {k: _tri(v) for k, v in self.layers.items()}, "missing": self.missing,
                "notes": self.notes, "not_modelled": NOT_MODELLED}


def _tri(v):
    return "yes" if v is True else "no" if v is False else "unknown"


def _ev(ref, idx, stmt, effect, match):
    return {"policy": ref.name, "policy_arn": ref.arn, "policy_kind": ref.kind, "via": ref.via,
            "origin": ref.origin, "version": ref.version, "statement_index": idx, "sid": stmt.get("Sid"),
            "effect": effect, "match": _tri(match), "statement": stmt}


def _context_for(principal, ctx):
    vals = dict(ctx.values) if ctx else {}
    base = {"aws:principalarn": principal.arn, "aws:principalaccount": principal.account_id,
            "aws:principaltype": "User" if principal.kind == "user" else "AssumedRole"}
    if principal.kind == "user":
        base["aws:username"] = principal.name
    for k, v in (principal.tags or {}).items():
        base[f"aws:principaltag/{k}".lower()] = v
    for k, v in base.items():
        vals.setdefault(k, v)
    return RequestContext(vals, complete=bool(ctx and ctx.complete))


def _stmt_applies(stmt, action, resource, ctx, notes, check_resource=True):
    if not stmt_matches_action(stmt, action):
        return False
    r = stmt_matches_resource(stmt, resource, ctx) if check_resource else True
    if r is False:
        return False
    c, cn = eval_conditions(stmt.get("Condition"), ctx)
    for n in cn:
        if n not in notes:
            notes.append(n)
    return t_and(r, c)


def _scan_refs(refs, effect, action, resource, ctx, evidence, missing, notes, layer):
    """OR of matching statements with the given effect across policy refs. Unreadable documents -> UNKNOWN."""
    result = False
    for ref in refs:
        if ref.document is None:
            result = t_or(result, None)
            msg = f"{layer}: document of {ref.kind} policy '{ref.name}' ({ref.via}) not available [{ref.origin}]"
            if msg not in missing:
                missing.append(msg)
            continue
        for i, st in enumerate(statements(ref.document)):
            if str(st.get("Effect", "")).lower() != effect:
                continue
            m = _stmt_applies(st, action, resource, ctx, notes)
            if m is not False:
                evidence.append(dict(_ev(ref, i, st, st.get("Effect"), m), layer=layer))
                result = t_or(result, m)
    return result


def evaluate(model, principal, action, resource="*", context=None, resource_policy=None):
    """Decision for `principal` (model.Principal) performing `action` on `resource` (an ARN or "*").

    resource_policy: optional {"status": "none"|"collected"|"unknown"|"not_collected", "document": {...}}; when
    omitted, the model's resource_policies entry for `resource` is used if present."""
    ctx = _context_for(principal, context)
    evidence, missing, notes = [], [], []
    layers = {}

    # ---- identity
    if principal.identity_complete is not True:
        missing.append("identity: not every attached / inline / group policy (list or document) could be read")
    id_allow = _scan_refs(principal.identity, "allow", action, resource, ctx, evidence, missing, notes, "identity")
    id_deny = _scan_refs(principal.identity, "deny", action, resource, ctx, evidence, missing, notes, "identity")
    if principal.identity_complete is not True:
        id_allow = t_or(id_allow, None)
        id_deny = t_or(id_deny, None)
    layers["identity_allow"] = id_allow
    layers["identity_deny"] = id_deny

    # ---- permissions boundary
    if principal.boundary_status == "none":
        b_allow, b_deny = True, False
    elif principal.boundary_status == "present" and principal.boundary is not None:
        b_allow = _scan_refs([principal.boundary], "allow", action, resource, ctx, evidence, missing, notes, "boundary")
        b_deny = _scan_refs([principal.boundary], "deny", action, resource, ctx, evidence, missing, notes, "boundary")
    else:
        b_allow, b_deny = None, None
        missing.append("permissions boundary: unknown whether one is set (not collected / not readable)")
    layers["boundary_allow"] = b_allow

    # ---- SCPs
    scp = model.scp or {}
    st = scp.get("status", "unknown")
    if principal.service_linked:
        scp_allow, scp_deny = True, False
        notes.append("SCPs do not apply to service-linked roles")
    elif st in ("not_applicable", "management_account", "disabled"):
        scp_allow, scp_deny = True, False
    elif st == "collected":
        scp_allow, scp_deny = True, False
        for lvl in scp.get("levels") or []:
            from .model import PolicyRef
            refs = [PolicyRef(p.get("name"), p.get("arn"), "scp", "scp:" + str(lvl.get("target")),
                              p.get("document"), "collected" if p.get("document") is not None else "unreadable")
                    for p in lvl.get("policies") or []]
            if not refs:
                scp_allow = False  # a level with no SCP attached denies everything (cannot happen with FullAWSAccess)
                continue
            scp_allow = t_and(scp_allow, _scan_refs(refs, "allow", action, resource, ctx, evidence, missing, notes,
                                                    "scp:" + str(lvl.get("target"))))
            scp_deny = t_or(scp_deny, _scan_refs(refs, "deny", action, resource, ctx, evidence, missing, notes,
                                                 "scp:" + str(lvl.get("target"))))
    else:
        scp_allow, scp_deny = None, None
        missing.append("SCPs: " + (scp.get("note") or "Organizations SCP data unavailable"))
    layers["scp_allow"] = scp_allow

    # ---- resource-based policy
    rp = resource_policy if resource_policy is not None else model.resource_policies.get(resource)
    rp_grant, rp_deny = False, False
    if rp is not None:
        rst = rp.get("status")
        if rst == "collected" and rp.get("document") is not None:
            from .model import PolicyRef
            ref = PolicyRef(rp.get("name") or resource, resource, "resource", "resource", rp["document"])
            for i, s in enumerate(statements(rp["document"])):
                pm, pkind = principal_match(s, principal.arn, principal.account_id)
                if pm is False:
                    continue
                m = _stmt_applies(s, action, resource, ctx, notes)
                if m is False:
                    continue
                if pm is None:
                    notes.append(f"resource policy: principal element not evaluated ({pkind})")
                eff = str(s.get("Effect", "")).lower()
                m = t_and(m, pm)
                evidence.append(dict(_ev(ref, i, s, s.get("Effect"), m), layer="resource"))
                if eff == "deny":
                    rp_deny = t_or(rp_deny, m)
                elif eff == "allow" and pkind == "direct":
                    rp_grant = t_or(rp_grant, m)
                # pkind == "account": the account delegates to IAM; the identity layer decides
        elif rst in ("unknown",):
            rp_grant, rp_deny = None, None
            missing.append("resource policy: could not be read")
    layers["resource_grant"] = rp_grant

    deny = t_or(id_deny, b_deny, scp_deny, rp_deny)
    layers["explicit_deny"] = deny
    identity_path = t_and(id_allow, b_allow)
    if principal.kind == "user":
        resource_path = rp_grant  # not limited by the user's boundary (same account)
    else:
        resource_path = t_and(rp_grant, b_allow)  # a grant to the role ARN is limited by the role's boundary
    grant = t_or(identity_path, resource_path)
    final = t_and(t_not(deny), scp_allow, grant)

    if deny is True:
        decision, reason = DENIED, "explicit_deny"
    elif final is True:
        decision, reason = ALLOWED, "allowed_by_resource_policy" if identity_path is not True else "allowed"
    elif final is False:
        decision = DENIED
        if scp_allow is False:
            reason = "implicit_deny_scp"
        elif id_allow is True and b_allow is False and resource_path is not True:
            reason = "implicit_deny_boundary"
        else:
            reason = "implicit_deny_no_allow"
    else:
        decision = INDETERMINATE
        parts = []
        if deny is None:
            parts.append("a Deny may apply")
        if scp_allow is None:
            parts.append("SCPs unknown")
        if grant is None:
            parts.append("grant depends on unknown data")
        reason = "indeterminate: " + ", ".join(parts or ["unknown layer"])
    # keep only relevant evidence: for Denied-explicit the deny statements first
    evidence.sort(key=lambda e: (0 if e["effect"] == "Deny" else 1))
    return Decision(principal.arn, action, resource, decision, reason, evidence, layers, missing, notes)


def evaluate_custom(document, action, resource="*", context=None, principal_arn="arn:aws:iam::000000000000:user/custom"):
    """Evaluate one identity policy on its own (no boundary / SCP), e.g. to check a proposed policy."""
    from .model import PolicyRef, Principal
    p = Principal("user", principal_arn.split("/")[-1], principal_arn, principal_arn.split(":")[4] or "000000000000",
                  identity=[PolicyRef("proposed", None, "inline", "direct", document)], boundary_status="none")

    class _M:
        scp = {"status": "not_applicable"}
        resource_policies = {}
    return evaluate(_M(), p, action, resource, context)
