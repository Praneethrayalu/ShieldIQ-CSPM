"""IAM policy-document analysis: full admin and common privilege-escalation paths.

Input: the policy documents the collector read for one principal (its own attached managed and inline
policies plus those of its groups). Output: which documents grant full admin (Action "*" on Resource "*")
and which privilege-escalation permissions/combinations the principal holds.

Scope, stated honestly: identity-based policies only. Permission boundaries, SCPs, session policies and
resource-based policies are NOT evaluated, and conditions are not interpreted (a conditional Allow is
still reported, flagged as conditional). Unconditional Deny statements on Resource "*" are honoured.
The escalation catalogue follows the well-known Rhino Security Labs list.
"""
from fnmatch import fnmatchcase

# single permissions that let a principal grant itself (or take over) more privilege
ESCALATION_SINGLE = {
    "iam:CreatePolicyVersion": "create a new default version of a managed policy it is attached to",
    "iam:SetDefaultPolicyVersion": "switch a managed policy to a more permissive existing version",
    "iam:AttachUserPolicy": "attach any managed policy (e.g. AdministratorAccess) to a user",
    "iam:AttachGroupPolicy": "attach any managed policy to a group it belongs to",
    "iam:AttachRolePolicy": "attach any managed policy to a role it can use",
    "iam:PutUserPolicy": "write an arbitrary inline policy on a user",
    "iam:PutGroupPolicy": "write an arbitrary inline policy on a group",
    "iam:PutRolePolicy": "write an arbitrary inline policy on a role",
    "iam:AddUserToGroup": "add itself to a more privileged group",
    "iam:UpdateAssumeRolePolicy": "rewrite a role's trust policy so it can assume that role",
    "iam:CreateAccessKey": "create access keys for another (more privileged) user",
    "iam:CreateLoginProfile": "set a console password on another user",
    "iam:UpdateLoginProfile": "reset another user's console password",
}

# iam:PassRole + a service that runs code with the passed role
ESCALATION_PASSROLE = {
    "ec2:RunInstances": "launch an EC2 instance with a privileged instance profile",
    "lambda:CreateFunction": "create a Lambda function that runs as a privileged role",
    "cloudformation:CreateStack": "create a CloudFormation stack that runs as a privileged role",
    "glue:CreateDevEndpoint": "create a Glue dev endpoint with a privileged role",
    "datapipeline:CreatePipeline": "create a Data Pipeline that runs as a privileged role",
}


def _as_list(v):
    if v is None:
        return []
    return [v] if isinstance(v, str) else list(v)


def _match(patterns, action):
    a = action.lower()
    return any(fnmatchcase(a, str(p).lower()) for p in patterns)


def _statements(doc):
    st = (doc or {}).get("Statement", [])
    return [st] if isinstance(st, dict) else [s for s in st if isinstance(s, dict)]


def _grants(stmt, action):
    if "Action" in stmt:
        return _match(_as_list(stmt["Action"]), action)
    if "NotAction" in stmt:  # Allow everything except NotAction
        return not _match(_as_list(stmt["NotAction"]), action)
    return False


def _all_resources(stmt):
    return "*" in _as_list(stmt.get("Resource")) and "NotResource" not in stmt


def analyze(documents):
    """documents: [{"name", "source", "document"}] -> dict(admin=[...], escalation=[...], conditional=bool)."""
    allows, denies = [], []
    for d in documents or []:
        for stmt in _statements(d.get("document")):
            eff = str(stmt.get("Effect", "")).lower()
            if eff == "allow":
                allows.append((d, stmt))
            elif eff == "deny" and _all_resources(stmt) and not stmt.get("Condition"):
                denies.append(stmt)

    def denied(action):
        return any(_grants(s, action) for s in denies)

    def holders(action):
        """policies that allow `action` (and are not overridden by an unconditional Deny)."""
        if denied(action):
            return []
        return [(d, s) for d, s in allows if _grants(s, action)]

    admin = []
    for d, s in allows:
        acts = _as_list(s.get("Action"))
        if _all_resources(s) and any(str(a) in ("*", "*:*") for a in acts) \
                and not any("*" in [str(x) for x in _as_list(dn.get("Action"))] for dn in denies):
            admin.append({"policy": d.get("name"), "source": d.get("source"), "conditional": bool(s.get("Condition"))})

    escalation = []
    for action, why in ESCALATION_SINGLE.items():
        h = holders(action)
        if h:
            escalation.append({"path": action, "why": why, "via": sorted({x[0].get("name") for x in h}),
                               "conditional": all(bool(x[1].get("Condition")) for x in h)})
    pr = holders("iam:PassRole")
    if pr:
        for action, why in ESCALATION_PASSROLE.items():
            h = holders(action)
            if h:
                escalation.append({"path": "iam:PassRole + " + action, "why": why,
                                   "via": sorted({x[0].get("name") for x in pr + h}),
                                   "conditional": all(bool(x[1].get("Condition")) for x in pr + h)})
    return {"admin": admin, "escalation": escalation,
            "conditional": bool(admin or escalation) and all(a["conditional"] for a in admin + escalation)}
