"""In-memory stand-in for the AWS APIs the validation kit touches - for the offline (mock) run only.

It stores IAM users / groups / roles / managed policies / boundaries / tags created by `setup`, answers the read
APIs ShieldIQ's collector calls (including GetAccountAuthorizationDetails), and deletes them in `cleanup`.

IMPORTANT - what the mock does NOT do: it does not evaluate IAM policies. Its iam:SimulatePrincipalPolicy answers are
the *documented expected AWS decisions* written in cases.json (field `aws_expected`, else `expected`). A mock run
therefore proves the kit's plumbing (guards, setup, collection, ShieldIQ evaluation, comparison, report, cleanup)
end to end. It is NOT evidence that ShieldIQ agrees with real AWS - only a live run in a test account is.
"""
import copy
import json


class MockClientError(Exception):
    def __init__(self, code, status=400, op=""):
        super().__init__(f"{code} ({op})")
        self.response = {"Error": {"Code": code, "Message": code}, "ResponseMetadata": {"HTTPStatusCode": status}}


class _State:
    def __init__(self, account, cases):
        self.account = account
        self.cases = cases
        self.users, self.groups, self.roles, self.policies = {}, {}, {}, {}
        self.calls = []


def _arn(st, kind, path, name):
    return f"arn:aws:iam::{st.account}:{kind}{path}{name}"


class MockIAM:
    def __init__(self, st):
        self.s = st

    def _rec(self, op, **kw):
        self.s.calls.append(op)

    def _ent(self, coll, name, op):
        d = getattr(self.s, coll)
        if name not in d:
            raise MockClientError("NoSuchEntity", 404, op)
        return d[name]

    # ---------------- writes (setup / cleanup)
    def create_policy(self, PolicyName, PolicyDocument, Path="/", Tags=None, **kw):
        arn = _arn(self.s, "policy", Path, PolicyName)
        if arn in self.s.policies:
            raise MockClientError("EntityAlreadyExists", 409, "CreatePolicy")
        self.s.policies[arn] = {"name": PolicyName, "path": Path, "versions": {"v1": json.loads(PolicyDocument)},
                                "default": "v1", "tags": Tags or []}
        return {"Policy": {"Arn": arn, "PolicyName": PolicyName, "DefaultVersionId": "v1"}}

    def create_user(self, UserName, Path="/", Tags=None, PermissionsBoundary=None):
        if UserName in self.s.users:
            raise MockClientError("EntityAlreadyExists", 409, "CreateUser")
        self.s.users[UserName] = {"path": Path, "tags": Tags or [], "inline": {}, "managed": [], "groups": [],
                                  "boundary": PermissionsBoundary}
        return {"User": {"UserName": UserName, "Arn": _arn(self.s, "user", Path, UserName)}}

    def create_group(self, GroupName, Path="/"):
        if GroupName in self.s.groups:
            raise MockClientError("EntityAlreadyExists", 409, "CreateGroup")
        self.s.groups[GroupName] = {"path": Path, "inline": {}, "managed": []}
        return {"Group": {"GroupName": GroupName}}

    def create_role(self, RoleName, AssumeRolePolicyDocument, Path="/", Tags=None, **kw):
        if RoleName in self.s.roles:
            raise MockClientError("EntityAlreadyExists", 409, "CreateRole")
        self.s.roles[RoleName] = {"path": Path, "tags": Tags or [], "trust": json.loads(AssumeRolePolicyDocument),
                                  "inline": {}, "managed": [], "boundary": None}
        return {"Role": {"RoleName": RoleName, "Arn": _arn(self.s, "role", Path, RoleName)}}

    def add_user_to_group(self, GroupName, UserName):
        self._ent("groups", GroupName, "AddUserToGroup")
        self._ent("users", UserName, "AddUserToGroup")["groups"].append(GroupName)
        return {}

    def remove_user_from_group(self, GroupName, UserName):
        u = self._ent("users", UserName, "RemoveUserFromGroup")
        u["groups"] = [g for g in u["groups"] if g != GroupName]
        return {}

    def _put(self, coll, key, name, PolicyName, PolicyDocument):
        self._ent(coll, name, "Put")["inline"][PolicyName] = json.loads(PolicyDocument)
        return {}

    def put_user_policy(self, UserName, PolicyName, PolicyDocument):
        return self._put("users", "UserName", UserName, PolicyName, PolicyDocument)

    def put_group_policy(self, GroupName, PolicyName, PolicyDocument):
        return self._put("groups", "GroupName", GroupName, PolicyName, PolicyDocument)

    def put_role_policy(self, RoleName, PolicyName, PolicyDocument):
        return self._put("roles", "RoleName", RoleName, PolicyName, PolicyDocument)

    def _attach(self, coll, name, arn):
        if not arn.startswith("arn:aws:iam::aws:policy/") and arn not in self.s.policies:
            raise MockClientError("NoSuchEntity", 404, "Attach")
        self._ent(coll, name, "Attach")["managed"].append(arn)
        return {}

    def attach_user_policy(self, UserName, PolicyArn):
        return self._attach("users", UserName, PolicyArn)

    def attach_group_policy(self, GroupName, PolicyArn):
        return self._attach("groups", GroupName, PolicyArn)

    def attach_role_policy(self, RoleName, PolicyArn):
        return self._attach("roles", RoleName, PolicyArn)

    def _detach(self, coll, name, arn):
        e = self._ent(coll, name, "Detach")
        e["managed"] = [a for a in e["managed"] if a != arn]
        return {}

    def detach_user_policy(self, UserName, PolicyArn):
        return self._detach("users", UserName, PolicyArn)

    def detach_group_policy(self, GroupName, PolicyArn):
        return self._detach("groups", GroupName, PolicyArn)

    def detach_role_policy(self, RoleName, PolicyArn):
        return self._detach("roles", RoleName, PolicyArn)

    def put_user_permissions_boundary(self, UserName, PermissionsBoundary):
        self._ent("users", UserName, "PutUserPermissionsBoundary")["boundary"] = PermissionsBoundary
        return {}

    def delete_user_permissions_boundary(self, UserName):
        self._ent("users", UserName, "DeleteUserPermissionsBoundary")["boundary"] = None
        return {}

    def delete_user_policy(self, UserName, PolicyName):
        self._ent("users", UserName, "DeleteUserPolicy")["inline"].pop(PolicyName, None)
        return {}

    def delete_group_policy(self, GroupName, PolicyName):
        self._ent("groups", GroupName, "DeleteGroupPolicy")["inline"].pop(PolicyName, None)
        return {}

    def delete_role_policy(self, RoleName, PolicyName):
        self._ent("roles", RoleName, "DeleteRolePolicy")["inline"].pop(PolicyName, None)
        return {}

    def delete_user(self, UserName):
        u = self._ent("users", UserName, "DeleteUser")
        if u["inline"] or u["managed"] or u["groups"]:
            raise MockClientError("DeleteConflict", 409, "DeleteUser")
        del self.s.users[UserName]
        return {}

    def delete_group(self, GroupName):
        g = self._ent("groups", GroupName, "DeleteGroup")
        if g["inline"] or g["managed"] or any(GroupName in u["groups"] for u in self.s.users.values()):
            raise MockClientError("DeleteConflict", 409, "DeleteGroup")
        del self.s.groups[GroupName]
        return {}

    def delete_role(self, RoleName):
        r = self._ent("roles", RoleName, "DeleteRole")
        if r["inline"] or r["managed"]:
            raise MockClientError("DeleteConflict", 409, "DeleteRole")
        del self.s.roles[RoleName]
        return {}

    def delete_policy(self, PolicyArn):
        if any(PolicyArn in e["managed"] for c in (self.s.users, self.s.groups, self.s.roles) for e in c.values()) or \
                any(u.get("boundary") == PolicyArn for u in self.s.users.values()):
            raise MockClientError("DeleteConflict", 409, "DeletePolicy")
        self.s.policies.pop(PolicyArn, None)
        return {}

    def list_policy_versions(self, PolicyArn):
        p = self.s.policies[PolicyArn]
        return {"Versions": [{"VersionId": v, "IsDefaultVersion": v == p["default"]} for v in p["versions"]]}

    def delete_policy_version(self, PolicyArn, VersionId):
        self.s.policies[PolicyArn]["versions"].pop(VersionId, None)
        return {}

    def list_account_aliases(self):
        return {"AccountAliases": ["shieldiq-sandbox"]}

    # ---------------- reads
    def _filter(self, coll, PathPrefix="/"):
        return {n: e for n, e in getattr(self.s, coll).items() if e["path"].startswith(PathPrefix)}

    def list_users(self, PathPrefix="/", **kw):
        return {"Users": [{"UserName": n, "Path": e["path"], "Arn": _arn(self.s, "user", e["path"], n)}
                          for n, e in self._filter("users", PathPrefix).items()]}

    def list_roles(self, PathPrefix="/", **kw):
        return {"Roles": [{"RoleName": n, "Path": e["path"], "Arn": _arn(self.s, "role", e["path"], n),
                           "AssumeRolePolicyDocument": e["trust"]} for n, e in self._filter("roles", PathPrefix).items()]}

    def list_groups(self, PathPrefix="/", **kw):
        return {"Groups": [{"GroupName": n, "Path": e["path"]} for n, e in self._filter("groups", PathPrefix).items()]}

    def list_policies(self, Scope="Local", PathPrefix="/", **kw):
        return {"Policies": [{"PolicyName": p["name"], "Arn": a, "Path": p["path"]} for a, p in self.s.policies.items()
                             if p["path"].startswith(PathPrefix)]}

    def list_user_tags(self, UserName):
        return {"Tags": self._ent("users", UserName, "ListUserTags")["tags"]}

    def list_role_tags(self, RoleName):
        return {"Tags": self._ent("roles", RoleName, "ListRoleTags")["tags"]}

    def get_login_profile(self, UserName):
        raise MockClientError("NoSuchEntity", 404, "GetLoginProfile")

    def list_mfa_devices(self, UserName):
        return {"MFADevices": []}

    def list_access_keys(self, UserName):
        return {"AccessKeyMetadata": []}

    def list_attached_user_policies(self, UserName):
        return {"AttachedPolicies": [self._att(a) for a in self._ent("users", UserName, "x")["managed"]]}

    def list_attached_group_policies(self, GroupName):
        return {"AttachedPolicies": [self._att(a) for a in self._ent("groups", GroupName, "x")["managed"]]}

    def list_attached_role_policies(self, RoleName):
        return {"AttachedPolicies": [self._att(a) for a in self._ent("roles", RoleName, "x")["managed"]]}

    def _att(self, arn):
        return {"PolicyArn": arn, "PolicyName": arn.split("/")[-1]}

    def list_user_policies(self, UserName):
        return {"PolicyNames": list(self._ent("users", UserName, "x")["inline"])}

    def list_group_policies(self, GroupName):
        return {"PolicyNames": list(self._ent("groups", GroupName, "x")["inline"])}

    def list_role_policies(self, RoleName):
        return {"PolicyNames": list(self._ent("roles", RoleName, "x")["inline"])}

    def get_user_policy(self, UserName, PolicyName):
        return {"PolicyDocument": self._ent("users", UserName, "x")["inline"][PolicyName]}

    def get_group_policy(self, GroupName, PolicyName):
        return {"PolicyDocument": self._ent("groups", GroupName, "x")["inline"][PolicyName]}

    def get_role_policy(self, RoleName, PolicyName):
        return {"PolicyDocument": self._ent("roles", RoleName, "x")["inline"][PolicyName]}

    def list_groups_for_user(self, UserName):
        return {"Groups": [{"GroupName": g} for g in self._ent("users", UserName, "x")["groups"]]}

    AWS_MANAGED = {"arn:aws:iam::aws:policy/AdministratorAccess":
                   {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}}

    def get_policy(self, PolicyArn):
        if PolicyArn in self.AWS_MANAGED:
            return {"Policy": {"Arn": PolicyArn, "DefaultVersionId": "v1"}}
        p = self.s.policies.get(PolicyArn)
        if p is None:
            raise MockClientError("NoSuchEntity", 404, "GetPolicy")
        return {"Policy": {"Arn": PolicyArn, "DefaultVersionId": p["default"]}}

    def get_policy_version(self, PolicyArn, VersionId):
        if PolicyArn in self.AWS_MANAGED:
            return {"PolicyVersion": {"Document": self.AWS_MANAGED[PolicyArn], "VersionId": VersionId}}
        return {"PolicyVersion": {"Document": self.s.policies[PolicyArn]["versions"][VersionId], "VersionId": VersionId}}

    def get_account_summary(self):
        return {"SummaryMap": {"AccountMFAEnabled": 1, "AccountAccessKeysPresent": 0}}

    def get_account_password_policy(self):
        return {"PasswordPolicy": {"MinimumPasswordLength": 14, "PasswordReusePrevention": 24}}

    def get_user(self, UserName):
        u = self._ent("users", UserName, "GetUser")
        out = {"UserName": UserName}
        if u["boundary"]:
            out["PermissionsBoundary"] = {"PermissionsBoundaryArn": u["boundary"]}
        return {"User": out}

    def get_role(self, RoleName):
        r = self._ent("roles", RoleName, "GetRole")
        return {"Role": {"RoleName": RoleName, "AssumeRolePolicyDocument": r["trust"]}}

    def get_account_authorization_details(self, Filter=None, Marker=None):
        st = self.s
        def att(lst):
            return [self._att(a) for a in lst]
        users = [{"UserName": n, "Arn": _arn(st, "user", e["path"], n), "Path": e["path"], "GroupList": list(e["groups"]),
                  "AttachedManagedPolicies": att(e["managed"]),
                  "UserPolicyList": [{"PolicyName": k, "PolicyDocument": v} for k, v in e["inline"].items()],
                  "Tags": e["tags"], **({"PermissionsBoundary": {"PermissionsBoundaryType": "Policy",
                                                                "PermissionsBoundaryArn": e["boundary"]}}
                                        if e["boundary"] else {})} for n, e in st.users.items()]
        groups = [{"GroupName": n, "Arn": _arn(st, "group", e["path"], n), "AttachedManagedPolicies": att(e["managed"]),
                   "GroupPolicyList": [{"PolicyName": k, "PolicyDocument": v} for k, v in e["inline"].items()]}
                  for n, e in st.groups.items()]
        roles = [{"RoleName": n, "Arn": _arn(st, "role", e["path"], n), "Path": e["path"],
                  "AssumeRolePolicyDocument": e["trust"], "AttachedManagedPolicies": att(e["managed"]),
                  "RolePolicyList": [{"PolicyName": k, "PolicyDocument": v} for k, v in e["inline"].items()],
                  "Tags": e["tags"]} for n, e in st.roles.items()]
        pols = [{"PolicyName": p["name"], "Arn": a, "DefaultVersionId": p["default"],
                 "PolicyVersionList": [{"VersionId": v, "IsDefaultVersion": v == p["default"], "Document": d}
                                       for v, d in p["versions"].items()]} for a, p in st.policies.items()]
        # two pages, to exercise pagination
        if Marker is None:
            return {"UserDetailList": users[: len(users) // 2], "GroupDetailList": groups, "RoleDetailList": [],
                    "Policies": pols, "IsTruncated": True, "Marker": "page-2"}
        return {"UserDetailList": users[len(users) // 2:], "GroupDetailList": [], "RoleDetailList": roles,
                "Policies": [], "IsTruncated": False}

    # ---------------- simulator: DOCUMENTED expectations, not an evaluation (see module docstring)
    def simulate_principal_policy(self, PolicySourceArn, ActionNames, ResourceArns, ContextEntries=None, **kw):
        out = []
        for c in self.s.cases["checks"]:
            if c["type"] != "decision" or c["principal"] != PolicySourceArn or c["action"] not in ActionNames:
                continue
            if c["resource"] not in ResourceArns or bool(c.get("context")) != bool(ContextEntries):
                continue
            exp = c.get("aws_expected", c["expected"])
            out.append({"EvalActionName": c["action"], "EvalResourceName": c["resource"],
                        "EvalDecision": c.get("aws_raw") or {"Allowed": "allowed", "Denied": "implicitDeny"}.get(exp, "implicitDeny"),
                        "MatchedStatements": [], "MissingContextValues": []})
        return {"EvaluationResults": out, "IsTruncated": False}


class _Generic:
    """Other services: empty, readable answers (an isolated test account has nothing else in it)."""

    def __init__(self, name, st):
        self.name, self.s = name, st

    def get_caller_identity(self):
        return {"Account": self.s.account, "Arn": f"arn:aws:iam::{self.s.account}:role/shieldiq-validator"}

    def describe_organization(self):
        raise MockClientError("AWSOrganizationsNotInUseException", 400, "DescribeOrganization")

    def list_account_aliases(self):
        return {"AccountAliases": ["shieldiq-sandbox"]}

    def __getattr__(self, op):
        if op.startswith(("list_", "describe_")):
            return lambda **kw: {}
        def denied(**kw):
            raise MockClientError("AccessDenied", 403, op)
        return denied


class MockSession:
    region_name = "us-east-1"

    def __init__(self, account, cases):
        self.state = _State(account, cases)
        self._iam = MockIAM(self.state)

    def client(self, name, region_name=None, **kw):
        return self._iam if name == "iam" else _Generic(name, self.state)
