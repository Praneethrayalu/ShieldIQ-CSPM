#!/usr/bin/env python3
"""ShieldIQ IAM validation kit - compare ShieldIQ's effective-permission results with AWS's own policy simulator in a
DEDICATED, ISOLATED AWS test account.

  python validation/shieldiq_validate.py plan                      # what setup would create (no AWS calls)
  python validation/shieldiq_validate.py setup   --profile P --account-id 123456789012 [--apply]
  python validation/shieldiq_validate.py run     --profile P --account-id 123456789012 [--out DIR]
  python validation/shieldiq_validate.py cleanup --profile P --account-id 123456789012 [--apply]
  python validation/shieldiq_validate.py mock    [--out DIR]       # whole cycle against an in-memory mock

Safety (enforced in code, see guard()):
- the caller's account must equal --account-id AND the env var SHIELDIQ_VALIDATION_ACCOUNT;
- refuses the AWS Organizations management account and any account whose alias contains "prod";
- setup/cleanup are dry runs unless --apply is given;
- everything is created under IAM path /shieldiq-validation/, named siqv-*, tagged shieldiq-validation=true;
- no access keys, console passwords or other credentials are ever created; roles trust only the credential-less
  validation users or an AWS service;
- cleanup touches only resources under that path (users/roles must also carry the tag).
"""
import argparse
import copy
import json
import os
import sys
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

PATH = "/shieldiq-validation/"
TAG = {"Key": "shieldiq-validation", "Value": "true"}
ORDER = {"confirmed": 0, "likely": 1, "unverified": 2}


class GuardError(Exception):
    pass


def load_cases(account):
    with open(os.path.join(HERE, "cases.json")) as fh:
        text = fh.read()
    return json.loads(text.replace("${ACCOUNT}", account))


# ------------------------------------------------------------------ guards
def guard(session, account_id, env=os.environ):
    if not account_id or not account_id.isdigit() or len(account_id) != 12:
        raise GuardError("--account-id must be the 12-digit id of the dedicated test account")
    if env.get("SHIELDIQ_VALIDATION_ACCOUNT") != account_id:
        raise GuardError("Set SHIELDIQ_VALIDATION_ACCOUNT=<the same account id> to confirm this is the test account")
    ident = session.client("sts").get_caller_identity()
    if ident.get("Account") != account_id:
        raise GuardError(f"Credentials belong to account {ident.get('Account')}, not {account_id}: refusing")
    try:
        org = session.client("organizations").describe_organization()["Organization"]
        if org.get("MasterAccountId") == account_id:
            raise GuardError("This is the AWS Organizations management account: never run validation there")
    except GuardError:
        raise
    except Exception:
        pass  # not in an organization / not allowed to tell: fine for a standalone sandbox account
    try:
        aliases = session.client("iam").list_account_aliases().get("AccountAliases") or []
        if any("prod" in a.lower() for a in aliases):
            raise GuardError(f"Account alias {aliases} looks like production: refusing")
    except GuardError:
        raise
    except Exception:
        pass
    return ident


# ------------------------------------------------------------------ setup
def plan(cases, account):
    acts = []
    for p in cases["managed_policies"]:
        acts.append(("iam:CreatePolicy", f"{PATH}{p['name']}"))
    for g in cases["groups"]:
        acts.append(("iam:CreateGroup", f"{PATH}{g['name']}"))
        acts += [("iam:AttachGroupPolicy", f"{g['name']} <- {m}") for m in g.get("managed", [])]
        acts += [("iam:PutGroupPolicy", f"{g['name']} <- {k}") for k in g.get("inline", {})]
    for u in cases["users"]:
        acts.append(("iam:CreateUser", f"{PATH}{u['name']} (tagged, NO credentials)"))
        if u.get("boundary"):
            acts.append(("iam:PutUserPermissionsBoundary", f"{u['name']} <- {u['boundary']}"))
        acts += [("iam:AddUserToGroup", f"{u['name']} -> {g}") for g in u.get("groups", [])]
        acts += [("iam:AttachUserPolicy", f"{u['name']} <- {m}") for m in u.get("managed", [])]
        acts += [("iam:PutUserPolicy", f"{u['name']} <- {k}") for k in u.get("inline", {})]
    for r in cases["roles"]:
        acts.append(("iam:CreateRole", f"{PATH}{r['name']} (trust: {json.dumps(r['trust']['Statement'][0]['Principal'])})"))
        acts += [("iam:AttachRolePolicy", f"{r['name']} <- {m}") for m in r.get("aws_managed", [])]
        acts += [("iam:PutRolePolicy", f"{r['name']} <- {k}") for k in r.get("inline", {})]
    return acts


def setup(iam, cases, account, apply=False, log=print):
    if not apply:
        for a, t in plan(cases, account):
            log(f"[dry-run] {a:32s} {t}")
        log("Dry run only. Re-run with --apply to create these resources in the test account.")
        return []

    def pa(n):
        return f"arn:aws:iam::{account}:policy{PATH}{n}"
    done = []

    def call(desc, fn, **kw):
        try:
            fn(**kw)
            done.append(desc)
        except Exception as exc:
            code = getattr(exc, "response", {}).get("Error", {}).get("Code") if hasattr(exc, "response") else None
            if code == "EntityAlreadyExists":
                done.append(desc + " (already existed)")
            else:
                raise
    for p in cases["managed_policies"]:
        call(f"policy {p['name']}", iam.create_policy, PolicyName=p["name"], Path=PATH,
             PolicyDocument=json.dumps(p["document"]), Tags=[TAG])
    for g in cases["groups"]:
        call(f"group {g['name']}", iam.create_group, GroupName=g["name"], Path=PATH)
        for m in g.get("managed", []):
            call(f"attach {m} to {g['name']}", iam.attach_group_policy, GroupName=g["name"], PolicyArn=pa(m))
        for k, d in g.get("inline", {}).items():
            call(f"inline {k} on {g['name']}", iam.put_group_policy, GroupName=g["name"], PolicyName=k,
                 PolicyDocument=json.dumps(d))
    for u in cases["users"]:
        kw = {"UserName": u["name"], "Path": PATH, "Tags": [TAG]}
        if u.get("boundary"):
            kw["PermissionsBoundary"] = pa(u["boundary"])
        call(f"user {u['name']}", iam.create_user, **kw)
        for g in u.get("groups", []):
            call(f"{u['name']} -> {g}", iam.add_user_to_group, GroupName=g, UserName=u["name"])
        for m in u.get("managed", []):
            call(f"attach {m} to {u['name']}", iam.attach_user_policy, UserName=u["name"], PolicyArn=pa(m))
        for k, d in u.get("inline", {}).items():
            call(f"inline {k} on {u['name']}", iam.put_user_policy, UserName=u["name"], PolicyName=k,
                 PolicyDocument=json.dumps(d))
    for r in cases["roles"]:
        call(f"role {r['name']}", iam.create_role, RoleName=r["name"], Path=PATH,
             AssumeRolePolicyDocument=json.dumps(r["trust"]), Tags=[TAG])
        for m in r.get("aws_managed", []):
            call(f"attach {m} to {r['name']}", iam.attach_role_policy, RoleName=r["name"], PolicyArn=m)
        for k, d in r.get("inline", {}).items():
            call(f"inline {k} on {r['name']}", iam.put_role_policy, RoleName=r["name"], PolicyName=k,
                 PolicyDocument=json.dumps(d))
    for d in done:
        log("[created] " + d)
    return done


# ------------------------------------------------------------------ cleanup
def _tagged(tags):
    return any(t.get("Key") == TAG["Key"] and t.get("Value") == TAG["Value"] for t in tags or [])


def cleanup(iam, apply=False, log=print):
    actions, skipped = [], []

    def do(desc, fn, **kw):
        actions.append(desc)
        if apply:
            fn(**kw)
    users = iam.list_users(PathPrefix=PATH).get("Users") or []
    for u in users:
        n = u["UserName"]
        if u.get("Path") != PATH or not _tagged(iam.list_user_tags(UserName=n).get("Tags")):
            skipped.append(f"user {n} (path/tag mismatch: left alone)")
            continue
        for g in iam.list_groups_for_user(UserName=n).get("Groups") or []:
            do(f"remove {n} from {g['GroupName']}", iam.remove_user_from_group, GroupName=g["GroupName"], UserName=n)
        for p in iam.list_user_policies(UserName=n).get("PolicyNames") or []:
            do(f"delete inline {p} of {n}", iam.delete_user_policy, UserName=n, PolicyName=p)
        for a in iam.list_attached_user_policies(UserName=n).get("AttachedPolicies") or []:
            do(f"detach {a['PolicyArn']} from {n}", iam.detach_user_policy, UserName=n, PolicyArn=a["PolicyArn"])
        if (iam.get_user(UserName=n).get("User") or {}).get("PermissionsBoundary"):
            do(f"remove boundary of {n}", iam.delete_user_permissions_boundary, UserName=n)
        do(f"delete user {n}", iam.delete_user, UserName=n)
    for g in iam.list_groups(PathPrefix=PATH).get("Groups") or []:
        n = g["GroupName"]
        if g.get("Path") != PATH:
            skipped.append(f"group {n}")
            continue
        for p in iam.list_group_policies(GroupName=n).get("PolicyNames") or []:
            do(f"delete inline {p} of {n}", iam.delete_group_policy, GroupName=n, PolicyName=p)
        for a in iam.list_attached_group_policies(GroupName=n).get("AttachedPolicies") or []:
            do(f"detach {a['PolicyArn']} from {n}", iam.detach_group_policy, GroupName=n, PolicyArn=a["PolicyArn"])
        do(f"delete group {n}", iam.delete_group, GroupName=n)
    for r in iam.list_roles(PathPrefix=PATH).get("Roles") or []:
        n = r["RoleName"]
        if r.get("Path") != PATH or not _tagged(iam.list_role_tags(RoleName=n).get("Tags")):
            skipped.append(f"role {n} (path/tag mismatch: left alone)")
            continue
        for p in iam.list_role_policies(RoleName=n).get("PolicyNames") or []:
            do(f"delete inline {p} of {n}", iam.delete_role_policy, RoleName=n, PolicyName=p)
        for a in iam.list_attached_role_policies(RoleName=n).get("AttachedPolicies") or []:
            do(f"detach {a['PolicyArn']} from {n}", iam.detach_role_policy, RoleName=n, PolicyArn=a["PolicyArn"])
        do(f"delete role {n}", iam.delete_role, RoleName=n)
    for p in iam.list_policies(Scope="Local", PathPrefix=PATH).get("Policies") or []:
        for v in iam.list_policy_versions(PolicyArn=p["Arn"]).get("Versions") or []:
            if not v.get("IsDefaultVersion"):
                do(f"delete version {v['VersionId']} of {p['PolicyName']}", iam.delete_policy_version,
                   PolicyArn=p["Arn"], VersionId=v["VersionId"])
        do(f"delete policy {p['PolicyName']}", iam.delete_policy, PolicyArn=p["Arn"])
    for a in actions:
        log(("[deleted] " if apply else "[dry-run] ") + a)
    for s in skipped:
        log("[skipped] " + s)
    return actions, skipped


# ------------------------------------------------------------------ run + compare
def run(session, cases, region="us-east-1", simulate=True):
    from shieldiq.collectors import aws_live
    from shieldiq.iam import RequestContext, build_model, evaluate
    from shieldiq.iam.analysis import Analyzer
    from shieldiq.iam.simulate import compare, simulate_principal
    from shieldiq.rules import evaluate as run_rules

    inv = aws_live.collect({"regions": [region]}, session=session)
    model = build_model(inv)
    an = Analyzer(model)
    paths = an.paths()
    rule_results = {}
    for e in run_rules("aws", inv):
        if e.rule.id in ("AWS-IAM-005", "AWS-IAM-007"):
            for r in e.results:
                rule_results[(e.rule.id, r.resource_id)] = "Secure" if r.passed else "Finding"
            for r in e.unknown:
                rule_results[(e.rule.id, r.resource_id)] = "Unknown"
    iam = session.client("iam")
    rows = []
    for c in cases["checks"]:
        p = model.principals.get(c["principal"])
        row = {"id": c["id"], "type": c["type"], "polarity": c["polarity"], "what": c["what"],
               "principal": c["principal"].split("/")[-1], "expected": c["expected"]}
        if p is None:
            row.update(actual="principal not collected", aws=None, comparison="n/a", result="FAIL")
            rows.append(row)
            continue
        if c["type"] == "decision":
            ctx = RequestContext(c.get("context") or {}, complete=bool(c.get("context")))
            d = evaluate(model, p, c["action"], c["resource"], ctx)
            row.update(action=c["action"], resource=c["resource"], actual=d.decision, reason=d.reason,
                       evidence=[f"{e['layer']}:{e['policy']}#{e['statement_index']}" for e in d.evidence][:4],
                       missing=d.missing)
            aws = None
            if simulate:
                try:
                    res = simulate_principal(iam, p.arn, [c["action"]], c["resource"], c.get("context"))
                    aws = res[0] if res else None
                except Exception as exc:
                    aws = {"decision": "error", "aws_decision": exc.__class__.__name__, "missing_context": []}
            row["aws"] = aws and aws.get("aws_decision")
            row["comparison"] = compare(d.decision, aws) if aws and aws.get("decision") != "error" else "aws-not-run"
            aws_exp = c.get("aws_expected", c["expected"])
            ok = d.decision == c["expected"] and (aws is None or aws.get("decision") == aws_exp)
            row["result"] = "PASS" if ok else "FAIL"
        elif c["type"] == "path":
            mine = [x for x in paths if x["start"]["arn"] == p.arn]
            row["actual"] = f"{len(mine)} path(s)" + (f", best {mine[0]['confidence']}" if mine else "")
            if c["expected"] == "no_path":
                ok = not mine and an.principal_report(p)["state"] != "Unknown"
            else:
                ok = bool(mine) and ORDER[mine[0]["confidence"]] <= ORDER[c["min_confidence"]] and \
                    (c["min_confidence"] != "likely" or mine[0]["confidence"] != "confirmed")
            row["aws"], row["comparison"] = None, "n/a (paths are ShieldIQ analysis; edges are checked by the decision cases)"
            row["result"] = "PASS" if ok else "FAIL"
        else:
            st = rule_results.get((c["rule"], p.arn), "not evaluated")
            row.update(actual=st, aws=None, comparison="n/a", result="PASS" if st == c["expected"] else "FAIL")
        rows.append(row)
    return {"rows": rows, "collection": inv.get("_sources"), "account": inv.get("account_id")}


LIMITATIONS = [
    "Single-account evaluation only: cross-account access, session policies / session tags, RCPs, VPC endpoint "
    "policies and service-specific authorization (KMS grants, S3 ACL/Object Ownership) are not modelled.",
    "Resource-based policies: only S3 bucket policies and role trust policies are collected.",
    "Condition keys absent from the request context are Indeterminate in ShieldIQ; AWS's simulator treats them as "
    "absent (usually not matching), so D09-style cases are expected to differ and are scored on that expectation.",
    "The simulator itself does not reproduce every runtime check (AWS documentation); agreement with it is strong "
    "evidence, not a proof of authorization equivalence.",
    "SCPs are evaluated only when the credentials can read AWS Organizations (member accounts usually cannot).",
]


def report(result, mode, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    rows = result["rows"]
    passed = sum(1 for r in rows if r["result"] == "PASS")
    acct = str(result.get("account") or "")
    meta = {"generated_at": datetime.now(timezone.utc).isoformat(), "mode": mode,
            "account": (acct[:4] + "****" + acct[-2:]) if acct else None, "passed": passed, "total": len(rows),
            "banner": ("LIVE AWS VALIDATION NOT EXECUTED - mock run: the simulator answers are the documented "
                       "expected AWS decisions from cases.json, not real AWS output.") if mode == "mock" else
            "Live run against the dedicated test account."}
    with open(os.path.join(out_dir, "validation_report.json"), "w") as fh:
        json.dump({"meta": meta, "rows": rows, "collection": result.get("collection"), "limitations": LIMITATIONS},
                  fh, indent=2, default=str)
    lines = [f"# ShieldIQ IAM validation report ({mode})", "", f"**{meta['banner']}**", "",
             f"Generated {meta['generated_at']} - account {meta['account']} - **{passed}/{len(rows)} PASS**", "",
             "| ID | Type | +/- | Principal | Check | Expected | ShieldIQ | AWS simulator | Comparison | Result |",
             "|---|---|---|---|---|---|---|---|---|---|"]
    for r in rows:
        chk = f"{r.get('action', '')} {r.get('resource', '')}".strip() or r["what"]
        lines.append(f"| {r['id']} | {r['type']} | {r['polarity']} | {r['principal']} | {chk} | {r['expected']} | "
                     f"{r.get('actual')} | {r.get('aws') or '-'} | {r.get('comparison')} | {r['result']} |")
    lines += ["", "## Data-source completeness", ""]
    for s in result.get("collection") or []:
        lines.append(f"- {s.get('label') or s.get('source')}: {s.get('status')}")
    lines += ["", "## Limitations", ""] + [f"- {x}" for x in LIMITATIONS]
    with open(os.path.join(out_dir, "validation_report.md"), "w") as fh:
        fh.write("\n".join(lines) + "\n")
    return meta


def mock_cycle(out_dir, log=print):
    from mock_aws import MockSession
    account = "000000000000"
    cases = load_cases(account)
    s = MockSession(account, cases)
    guard(s, account, env={"SHIELDIQ_VALIDATION_ACCOUNT": account})
    iam = s.client("iam")
    setup(iam, cases, account, apply=True, log=log)
    result = run(s, cases)
    meta = report(result, "mock", out_dir)
    actions, skipped = cleanup(iam, apply=True, log=log)
    left = {k: len(getattr(s.state, k)) for k in ("users", "groups", "roles", "policies")}
    log(f"cleanup: {len(actions)} actions, {len(skipped)} skipped, left behind: {left}")
    meta["cleanup_left"] = left
    return meta, result


def _session(args):
    import boto3
    return boto3.Session(profile_name=args.profile, region_name=args.region)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["plan", "setup", "run", "cleanup", "mock"])
    ap.add_argument("--profile")
    ap.add_argument("--account-id", default="")
    ap.add_argument("--region", default="us-east-1")
    ap.add_argument("--apply", action="store_true", help="really create/delete (default: dry run)")
    ap.add_argument("--no-simulate", action="store_true")
    ap.add_argument("--out", default=os.path.join(HERE, "out"))
    a = ap.parse_args(argv)
    if a.command == "mock":
        meta, _ = mock_cycle(a.out)
        print(json.dumps(meta, indent=2))
        return 0 if meta["passed"] == meta["total"] and not any(meta["cleanup_left"].values()) else 1
    if a.command == "plan":
        for act, t in plan(load_cases(a.account_id or "<ACCOUNT>"), a.account_id):
            print(f"{act:32s} {t}")
        return 0
    s = _session(a)
    guard(s, a.account_id)
    cases = load_cases(a.account_id)
    if a.command == "setup":
        setup(s.client("iam"), cases, a.account_id, apply=a.apply)
    elif a.command == "cleanup":
        cleanup(s.client("iam"), apply=a.apply)
    elif a.command == "run":
        meta = report(run(s, cases, a.region, simulate=not a.no_simulate), "live", a.out)
        print(json.dumps(meta, indent=2))
        return 0 if meta["passed"] == meta["total"] else 1
    return 0


if __name__ == "__main__":
    sys.path.insert(0, HERE)
    sys.exit(main())
