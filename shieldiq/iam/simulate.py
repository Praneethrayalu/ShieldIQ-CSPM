"""Optional cross-check with AWS's own IAM policy simulator (read-only API calls).

- iam:SimulatePrincipalPolicy - evaluates a real principal's identity policies, group policies, permissions boundary and
  (for accounts in an organization) SCPs, for given actions / resources / context keys.
- iam:SimulateCustomPolicy   - evaluates policy documents you pass in (used to check a *proposed* remediation policy
  before anyone applies it).

The simulator is authoritative for what it covers, but it is not the full runtime either (AWS docs: it does not
evaluate session policies, some service-specific checks, and it only uses resource policies you pass in). Its output
is reported as evidence next to ShieldIQ's own decision; disagreements are reported, never hidden.

Required permissions: iam:SimulatePrincipalPolicy, iam:SimulateCustomPolicy, iam:GetContextKeysForPrincipalPolicy
(not part of the SecurityAudit managed policy - see validation/policies/shieldiq-scanner-policy.json).
"""
import json

from .evaluator import ALLOWED, DENIED, INDETERMINATE

_MAP = {"allowed": ALLOWED, "explicitDeny": DENIED, "implicitDeny": DENIED}


def _context_entries(context):
    out = []
    for k, v in (context or {}).items():
        vals = v if isinstance(v, (list, tuple)) else [v]
        typ = "boolean" if all(isinstance(x, bool) for x in vals) else "string"
        out.append({"ContextKeyName": k, "ContextKeyValues": [str(x).lower() if isinstance(x, bool) else str(x)
                                                               for x in vals],
                    "ContextKeyType": typ + ("List" if len(vals) > 1 else "")})
    return out


def _results(pages):
    out = []
    for r in pages:
        orgs = (r.get("OrganizationsDecisionDetail") or {}).get("AllowedByOrganizations")
        pb = (r.get("PermissionsBoundaryDecisionDetail") or {}).get("AllowedByPermissionsBoundary")
        out.append({"action": r.get("EvalActionName"), "resource": r.get("EvalResourceName"),
                    "aws_decision": r.get("EvalDecision"), "decision": _MAP.get(r.get("EvalDecision"), INDETERMINATE),
                    "missing_context": list(r.get("MissingContextValues") or []),
                    "allowed_by_organizations": orgs, "allowed_by_boundary": pb,
                    "matched_statements": [m.get("SourcePolicyId") for m in r.get("MatchedStatements") or []]})
    return out


def _paged(iam, method, key, **kw):
    can = getattr(iam, "can_paginate", None)
    try:
        if callable(can) and can(method) is True:
            res = []
            for page in iam.get_paginator(method).paginate(**kw):
                res.extend(page.get(key) or [])
            return res
    except TypeError:
        pass
    res, marker = [], None
    for _ in range(200):
        resp = getattr(iam, method)(**({**kw, "Marker": marker} if marker else kw))
        res.extend(resp.get(key) or [])
        if resp.get("IsTruncated") and resp.get("Marker"):
            marker = resp["Marker"]
        else:
            break
    return res


def simulate_principal(iam, principal_arn, actions, resource="*", context=None, resource_policy=None):
    kw = {"PolicySourceArn": principal_arn, "ActionNames": list(actions), "ResourceArns": [resource]}
    if context:
        kw["ContextEntries"] = _context_entries(context)
    if resource_policy:
        kw["ResourcePolicy"] = json.dumps(resource_policy)
    return _results(_paged(iam, "simulate_principal_policy", "EvaluationResults", **kw))


def simulate_custom(iam, policy_documents, actions, resource="*", context=None, boundary_documents=None):
    kw = {"PolicyInputList": [json.dumps(d) for d in policy_documents], "ActionNames": list(actions),
          "ResourceArns": [resource]}
    if boundary_documents:
        kw["PermissionsBoundaryPolicyInputList"] = [json.dumps(d) for d in boundary_documents]
    if context:
        kw["ContextEntries"] = _context_entries(context)
    return _results(_paged(iam, "simulate_custom_policy", "EvaluationResults", **kw))


def compare(shieldiq_decision, aws):
    """-> match | mismatch | shieldiq-indeterminate | aws-missing-context"""
    if aws is None:
        return "aws-not-run"
    if shieldiq_decision == INDETERMINATE:
        return "shieldiq-indeterminate"
    if aws.get("missing_context") and aws["decision"] != shieldiq_decision:
        return "aws-missing-context"
    return "match" if aws["decision"] == shieldiq_decision else "mismatch"
