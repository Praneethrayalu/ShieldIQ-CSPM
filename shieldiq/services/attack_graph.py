"""Attack-path engine.

Builds a directed graph from each integration's inventory (internet -> exposed network rule ->
compute -> identity -> data store), keeps only edges that an open finding makes exploitable, then
enumerates every path from the internet to a crown-jewel asset. Paths are scored from the findings
on them, and the node that appears in the most paths is reported as the choke point (fix it once,
break the most paths). Remediating a finding and re-scanning removes the paths it enabled.
"""
import math
from collections import Counter, defaultdict

from ..models import SEVERITY_WEIGHT, Finding, Integration
from ..rules import get_rule

ADMIN_POLICIES = {"AdministratorAccess"}


class Graph:
    def __init__(self, provider, integ):
        self.provider, self.integ = provider, integ
        self.nodes, self.edges = {}, defaultdict(list)
        self.node("internet", "Internet (0.0.0.0/0)", "ingress")

    def node(self, nid, label, kind, resource_id=None, sensitive=False):
        self.nodes.setdefault(nid, {"id": nid, "label": label, "type": kind, "resource_id": resource_id,
                                    "sensitive": sensitive})
        return nid

    def edge(self, a, b, label):
        if b not in [x for x, _ in self.edges[a]]:
            self.edges[a].append((b, label))


def _sensitive(item):
    return (item.get("tags") or {}).get("data") == "sensitive"


def _aws(g, inv, bad):
    acct = inv.get("account_id", "account")
    buckets = {b["name"]: b for b in inv.get("s3_buckets", [])}
    dbs = {d["id"]: d for d in inv.get("rds_instances", [])}
    roles = {r["name"]: r for r in inv.get("iam_roles", [])}

    def bucket_node(b):
        rid = f"arn:aws:s3:::{b['name']}"
        return g.node(rid, f"S3 bucket {b['name']}", "datastore", rid, _sensitive(b))

    def db_node(d):
        return g.node(d["id"], f"RDS {d['id']} ({d.get('engine', 'db')})", "datastore", d["id"], _sensitive(d))

    def reach_data(src, policies):
        pol = set(policies or [])
        admin = bool(pol & ADMIN_POLICIES)
        if admin or any("S3" in p for p in pol):
            for b in buckets.values():
                g.edge(src, bucket_node(b), "s3:GetObject" if not admin else "full admin")
        if admin or any("RDS" in p for p in pol):
            for d in dbs.values():
                g.edge(src, db_node(d), "rds data access" if not admin else "full admin")

    for b in buckets.values():
        rid = f"arn:aws:s3:::{b['name']}"
        if bad(rid, "AWS-S3-002"):
            g.edge("internet", bucket_node(b), "anonymous HTTP GET")
    for d in dbs.values():
        if bad(d["id"], "AWS-RDS-001"):
            g.edge("internet", db_node(d), "public DB endpoint")
    for sg in inv.get("security_groups", []):
        open_rules = [r for r in ("AWS-EC2-001", "AWS-EC2-002") if bad(sg["id"], r)]
        if not open_rules:
            continue
        sgn = g.node(sg["id"], f"Security group {sg.get('name', sg['id'])}", "network", sg["id"])
        g.edge("internet", sgn, "SSH/RDP open" if "AWS-EC2-001" in open_rules else "all ports open")
        for i in inv.get("ec2_instances", []):
            if sg["id"] in i.get("security_groups", []):
                inode = g.node(i["id"], f"EC2 {i.get('name', i['id'])}", "compute", i["id"])
                g.edge(sgn, inode, "inbound access")
                role = roles.get(i.get("instance_profile_role") or "")
                if role:
                    rid = f"arn:aws:iam::{acct}:role/{role['name']}"
                    rnode = g.node(rid, f"IAM role {role['name']}", "identity", rid)
                    g.edge(inode, rnode, "IMDSv1 credential theft" if bad(i["id"], "AWS-EC2-003") else "instance role credentials")
                    reach_data(rnode, role.get("policies"))
    for u in inv.get("iam_users", []):
        rid = f"arn:aws:iam::{acct}:user/{u['name']}"
        if bad(rid, "AWS-IAM-003"):
            unode = g.node(rid, f"IAM user {u['name']} (no MFA)", "identity", rid)
            g.edge("internet", unode, "phished / reused password")
            reach_data(unode, u.get("attached_policies"))


def _gcp(g, inv, bad):
    proj = inv.get("project_id", "project")
    sas = {s["email"]: s for s in inv.get("service_accounts", [])}

    def reach(src, roles):
        broad = set(roles or []) & {"roles/owner", "roles/editor"}
        for b in inv.get("buckets", []):
            if broad or "roles/storage.objectAdmin" in (roles or []):
                rid = f"projects/{proj}/buckets/{b['name']}"
                g.edge(src, g.node(rid, f"GCS bucket {b['name']}", "datastore", rid, _sensitive(b)), "storage access")
        for s in inv.get("sql_instances", []):
            if broad:
                rid = f"projects/{proj}/instances/{s['name']}"
                g.edge(src, g.node(rid, f"Cloud SQL {s['name']}", "datastore", rid, _sensitive(s)), "cloudsql admin")

    for b in inv.get("buckets", []):
        rid = f"projects/{proj}/buckets/{b['name']}"
        if bad(rid, "GCP-GCS-001"):
            g.edge("internet", g.node(rid, f"GCS bucket {b['name']}", "datastore", rid, _sensitive(b)), "allUsers read")
    for s in inv.get("sql_instances", []):
        rid = f"projects/{proj}/instances/{s['name']}"
        if bad(rid, "GCP-SQL-001"):
            g.edge("internet", g.node(rid, f"Cloud SQL {s['name']}", "datastore", rid, _sensitive(s)), "0.0.0.0/0 authorized")
    for fw in inv.get("firewall_rules", []):
        rid = f"projects/{proj}/firewalls/{fw['name']}"
        if not bad(rid, "GCP-NET-001"):
            continue
        fnode = g.node(rid, f"Firewall {fw['name']}", "network", rid)
        g.edge("internet", fnode, "SSH/RDP open")
        tags = set(fw.get("target_tags") or [])
        for vm in inv.get("compute_instances", []):
            if not tags or tags & set(vm.get("network_tags") or []):
                vid = f"projects/{proj}/instances/{vm['name']}"
                vnode = g.node(vid, f"VM {vm['name']}", "compute", vid)
                g.edge(fnode, vnode, "inbound access")
                sa = sas.get(vm.get("service_account")) or {"email": vm.get("service_account"), "roles": []}
                if sa.get("email"):
                    snode = g.node(sa["email"], f"Service account {sa['email'].split('@')[0]}", "identity", sa["email"])
                    g.edge(vnode, snode, "metadata token" + (" (full scope)" if bad(vid, "GCP-GCE-001") else ""))
                    reach(snode, sa.get("roles"))


def _azure(g, inv, bad):
    sub = inv.get("subscription_id", "sub")
    rid = lambda kind, n: f"/subscriptions/{sub}/{kind}/{n}"  # noqa: E731
    for s in inv.get("storage_accounts", []):
        if bad(rid("storageAccounts", s["name"]), "AZ-STG-001"):
            g.edge("internet", g.node(rid("storageAccounts", s["name"]), f"Storage {s['name']}", "datastore",
                                      rid("storageAccounts", s["name"]), _sensitive(s)), "anonymous blob read")
    for s in inv.get("sql_servers", []):
        if bad(rid("sqlServers", s["name"]), "AZ-SQL-001"):
            g.edge("internet", g.node(rid("sqlServers", s["name"]), f"Azure SQL {s['name']}", "datastore",
                                      rid("sqlServers", s["name"]), _sensitive(s)), "allow-all firewall")
    for n in inv.get("nsgs", []):
        nid = rid("networkSecurityGroups", n["name"])
        if not bad(nid, "AZ-NET-001"):
            continue
        g.edge("internet", g.node(nid, f"NSG {n['name']}", "network", nid), "RDP/SSH open")
        for vm in inv.get("vms", []):
            if vm.get("nsg") == n["name"]:
                vid = rid("virtualMachines", vm["name"])
                g.edge(nid, g.node(vid, f"VM {vm['name']}", "compute", vid), "inbound access")
                if {"Owner", "Contributor"} & set(vm.get("managed_identity_roles") or []):
                    mid = f"{vid}/identity"
                    g.edge(vid, g.node(mid, f"Managed identity of {vm['name']} (Contributor)", "identity", mid),
                           "IMDS token")
                    for s in inv.get("storage_accounts", []) + inv.get("sql_servers", []):
                        kind = "storageAccounts" if s in inv.get("storage_accounts", []) else "sqlServers"
                        g.edge(mid, g.node(rid(kind, s["name"]), f"{'Storage' if kind == 'storageAccounts' else 'Azure SQL'} {s['name']}",
                                           "datastore", rid(kind, s["name"]), _sensitive(s)), "contributor access")
    for u in inv.get("users", []):
        uid = f"entra/users/{u['upn']}"
        if bad(uid, "AZ-ID-001"):
            g.edge("internet", g.node(uid, f"Admin {u['upn']} (no MFA)", "identity", uid), "phished password")
            tgt = g.node(f"/subscriptions/{sub}", "Entire Azure subscription", "datastore", f"/subscriptions/{sub}", True)
            g.edge(uid, tgt, "tenant admin")


def _k8s(g, inv, bad):
    bindings = {s.get("name"): b for b in inv.get("role_bindings", []) for s in b.get("subjects", [])
                if s.get("kind") == "ServiceAccount"}
    for svc in inv.get("services", []):
        sid = f"k8s/{svc.get('namespace', 'default')}/service/{svc['name']}"
        if not bad(sid, "K8S-007"):
            continue
        snode = g.node(sid, f"Service {svc['name']} ({svc.get('type')})", "network", sid)
        g.edge("internet", snode, f"ports {svc.get('ports')}")
        for w in inv.get("workloads", []):
            if w["name"] == svc.get("selector", svc["name"]) and w.get("namespace") == svc.get("namespace"):
                wid = f"k8s/{w.get('namespace', 'default')}/{w.get('kind', 'Deployment').lower()}/{w['name']}"
                wnode = g.node(wid, f"{w.get('kind')} {w['name']}", "compute", wid)
                g.edge(snode, wnode, "exposed pod")
                b = bindings.get(w.get("service_account"))
                if b and b.get("role") == "cluster-admin":
                    bid = f"k8s/cluster/clusterrolebinding/{b['name']}"
                    bnode = g.node(bid, f"SA {w.get('service_account')} -> cluster-admin", "identity", bid)
                    g.edge(wnode, bnode, "mounted SA token")
                    tgt = g.node("k8s/cluster", f"Cluster {inv.get('cluster', {}).get('name', '')} + all secrets",
                                 "datastore", "k8s/cluster", True)
                    g.edge(bnode, tgt, "cluster-admin API")
                if bad(wid, "K8S-006"):
                    g.edge(wnode, g.node(f"{wid}/env-secret", "Credential in env vars", "datastore", wid, True),
                           "read env")


def _github(g, inv, bad):
    org = inv.get("org", {}).get("name", "org")
    for r in inv.get("repos", []):
        rid = f"github.com/{org}/{r['name']}"
        if not r.get("private") and bad(rid, "GH-REPO-006"):
            rnode = g.node(rid, f"Public repo {r['name']}", "network", rid)
            g.edge("internet", rnode, "git clone")
            for s in (r.get("secrets_found") or [])[:3]:
                g.edge(rnode, g.node(f"{rid}#{s['path']}:{s['line']}", f"Leaked {s['type']}", "datastore", rid, True),
                       f"{s['path']}:{s['line']}")


BUILDERS = {"aws": _aws, "gcp": _gcp, "azure": _azure, "kubernetes": _k8s, "github": _github}


def _paths(g, max_depth=6):
    """Every simple path from the internet to a crown jewel: a sensitive data store, or any data store
    the internet reaches directly (public exposure)."""
    out = []

    def dfs(node, path):
        if len(path) > max_depth:
            return
        if g.nodes[node]["type"] == "datastore" and node != "internet":
            if g.nodes[node]["sensitive"] or len(path) == 2:
                out.append(list(path))
            return
        for nxt, _ in g.edges.get(node, []):
            if nxt not in path:
                dfs(nxt, path + [nxt])
    dfs("internet", ["internet"])
    return out


def build(org_id):
    findings = Finding.query.filter(Finding.org_id == org_id, Finding.status.in_(["open", "in_progress", "accepted"])).all()
    by_res = defaultdict(list)
    for f in findings:
        by_res[(f.integration_id, f.resource_id)].append(f)
    paths, all_nodes = [], {}
    for integ in Integration.query.filter_by(org_id=org_id).all():
        builder = BUILDERS.get(integ.provider)
        if not builder or not integ.snapshot:
            continue
        g = Graph(integ.provider, integ)
        builder(g, integ.snapshot, lambda rid, rule, _i=integ.id: any(f.rule_id == rule for f in by_res.get((_i, rid), [])))
        for p in _paths(g):
            nodes = []
            path_findings = []
            for nid in p:
                n = dict(g.nodes[nid])
                fs = by_res.get((integ.id, n["resource_id"]), []) if n["resource_id"] else []
                n["findings"] = [{"id": f.id, "title": f.title, "severity": f.severity, "rule_id": f.rule_id} for f in fs]
                path_findings += fs
                nodes.append(n)
            raw = sum(SEVERITY_WEIGHT[f.severity] for f in {f.id: f for f in path_findings}.values())
            raw += 10 if g.nodes[p[-1]]["sensitive"] else 0
            score = max(5, min(99, round(100 * (1 - math.exp(-raw / 25)))))
            edges = [{"source": a, "target": b, "label": next(lbl for x, lbl in g.edges[a] if x == b)}
                     for a, b in zip(p, p[1:])]
            sev = "critical" if score >= 80 else "high" if score >= 60 else "medium" if score >= 40 else "low"
            paths.append({"integration": integ.name, "integration_id": integ.id, "provider": integ.provider,
                          "nodes": nodes, "edges": edges, "risk_score": score, "severity": sev,
                          "title": f"{nodes[1]['label']} \u2192 {nodes[-1]['label']}",
                          "hops": len(p) - 1})
            for n in nodes:
                all_nodes[(integ.id, n["id"])] = n
    paths.sort(key=lambda p: -p["risk_score"])
    for i, p in enumerate(paths, 1):
        p["id"] = f"PATH-{i:03d}"

    # choke points: middle/entry nodes (not internet, not target) shared by the most paths
    counter = Counter()
    members = defaultdict(set)
    position = {}
    for p in paths:
        for idx, n in enumerate(p["nodes"][1:-1] or p["nodes"][-1:]):
            key = (p["integration_id"], n["id"])
            counter[key] += 1
            members[key].add(p["id"])
            position[key] = min(position.get(key, 99), idx)
    # nodes on exactly the same set of paths are one chain: keep the one closest to the internet
    best_of_chain = {}
    for key, ps in members.items():
        sig = (key[0], frozenset(ps))
        if sig not in best_of_chain or position[key] < position[best_of_chain[sig]]:
            best_of_chain[sig] = key
    keep = set(best_of_chain.values())
    chokes = []
    ranked = sorted((k for k in counter if k in keep and all_nodes[k]["findings"]), key=lambda k: (-counter[k], position[k]))
    for (iid, nid) in ranked[:5]:
        cnt = counter[(iid, nid)]
        n = all_nodes[(iid, nid)]
        fix = sorted(n["findings"], key=lambda f: -SEVERITY_WEIGHT[f["severity"]])
        chokes.append({"node": n, "paths": cnt, "fix": fix[0] if fix else None,
                       "fix_rule": get_rule(fix[0]["rule_id"]).steps[0] if fix else None})
    for p in paths:
        cands = [(counter[(p["integration_id"], n["id"])], -i, n) for i, n in enumerate(p["nodes"][1:-1] or p["nodes"][-1:])
                 if n["findings"]]
        best = max(cands, key=lambda t: (t[0], t[1]))[2] if cands else None
        p["choke_point"] = {"label": best["label"], "finding": sorted(best["findings"], key=lambda f: -SEVERITY_WEIGHT[f["severity"]])[0]} if best else None
    return {"paths": paths, "choke_points": chokes}


def impact_of_finding(org_id, finding_id):
    """How many attack paths run through this finding's resource (its blast radius)."""
    g = build(org_id)
    hits = [p for p in g["paths"] if any(any(f["id"] == finding_id for f in n["findings"]) for n in p["nodes"])]
    return {"paths": len(hits), "max_risk": max((p["risk_score"] for p in hits), default=0),
            "path_ids": [p["id"] for p in hits]}
