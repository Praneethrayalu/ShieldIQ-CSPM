"""Kubernetes workload & cluster rules (work on live-exported or uploaded manifests)."""
import re

from .engine import CheckResult, fixer, find, rule

SECRET_ENV = re.compile(r"(PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|ACCESS_KEY|PRIVATE_KEY)", re.I)


def _wid(w):
    return f"k8s/{w.get('namespace', 'default')}/{w.get('kind', 'Deployment').lower()}/{w['name']}"


def _w(inv, rid):
    parts = rid.split("/")
    for w in inv.get("workloads", []):
        if w["name"] == parts[-1] and w.get("namespace", "default") == parts[1]:
            return w
    return None


def _containers(w):
    return w.get("containers", [])


@rule("K8S-001", "kubernetes", "Workloads", "Container runs in privileged mode", "critical",
      "Containers must not run with securityContext.privileged: true.",
      ["hardening"],
      "privileged: true gives the container all Linux capabilities and access to host devices.",
      "A compromised container can trivially escape to the node and from there reach every pod on it.",
      ["Remove privileged: true.", "Grant only the specific capabilities needed (capabilities.add).",
       "Enforce the 'restricted' Pod Security Standard on the namespace."],
      terraform='''
# Kubernetes manifest patch
spec:
  template:
    spec:
      containers:
        - name: <container>
          securityContext:
            privileged: false
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]''',
      cli="kubectl label namespace <ns> pod-security.kubernetes.io/enforce=restricted",
      refs=["CIS Kubernetes 5.2.2"], asset="compute")
def k8s_priv(inv):
    for w in inv.get("workloads", []):
        bad = [c["name"] for c in _containers(w) if c.get("privileged")]
        yield CheckResult(_wid(w), not bad, f"Privileged: {', '.join(bad)}" if bad else "Not privileged")


@fixer("K8S-001")
def _fp(inv, rid):
    w = _w(inv, rid)
    if not w:
        return False
    for c in _containers(w):
        c["privileged"] = False
    return True


@rule("K8S-002", "kubernetes", "Workloads", "Container may run as root", "medium",
      "Set runAsNonRoot: true and a non-zero runAsUser.",
      ["hardening"],
      "securityContext.runAsNonRoot is not set, so the image's default (often root) is used.",
      "Root inside the container makes kernel exploits and volume tampering far easier.",
      ["Set runAsNonRoot: true and runAsUser: 10001.", "Build images with a non-root USER."],
      cli="kubectl patch deployment {resource} -p '{\"spec\":{\"template\":{\"spec\":{\"securityContext\":"
          "{\"runAsNonRoot\":true,\"runAsUser\":10001}}}}}'",
      refs=["CIS Kubernetes 5.2.6"])
def k8s_root(inv):
    for w in inv.get("workloads", []):
        bad = [c["name"] for c in _containers(w) if not c.get("run_as_non_root")]
        yield CheckResult(_wid(w), not bad, f"May run as root: {', '.join(bad)}" if bad else "Non-root enforced")


@fixer("K8S-002")
def _fr(inv, rid):
    w = _w(inv, rid)
    if not w:
        return False
    for c in _containers(w):
        c["run_as_non_root"] = True
    return True


@rule("K8S-003", "kubernetes", "Workloads", "Pod shares host network / PID namespace", "high",
      "hostNetwork and hostPID should be false.",
      ["hardening", "network"],
      "The pod uses hostNetwork: true or hostPID: true.",
      "The pod can sniff node traffic, reach node-local services (kubelet, metadata) and see host processes.",
      ["Remove hostNetwork/hostPID unless the workload is a vetted node agent."],
      cli="kubectl patch deployment {resource} -p '{\"spec\":{\"template\":{\"spec\":{\"hostNetwork\":false,\"hostPID\":false}}}}'",
      refs=["CIS Kubernetes 5.2.3", "CIS Kubernetes 5.2.5"], asset="compute")
def k8s_host(inv):
    for w in inv.get("workloads", []):
        bad = [k for k in ("host_network", "host_pid") if w.get(k)]
        yield CheckResult(_wid(w), not bad, f"Uses {', '.join(bad)}" if bad else "Isolated")


@fixer("K8S-003")
def _fh(inv, rid):
    w = _w(inv, rid)
    if not w:
        return False
    w["host_network"] = w["host_pid"] = False
    return True


@rule("K8S-004", "kubernetes", "Workloads", "Container has no CPU/memory limits", "low",
      "Set resource requests and limits on every container.",
      ["hardening"],
      "resources.limits is missing.",
      "One misbehaving or compromised pod can starve the node (denial of service) or mine crypto unchecked.",
      ["Add resources.requests and resources.limits.", "Add a LimitRange default per namespace."],
      cli="kubectl set resources deployment {resource} --limits=cpu=500m,memory=512Mi --requests=cpu=100m,memory=128Mi")
def k8s_limits(inv):
    for w in inv.get("workloads", []):
        bad = [c["name"] for c in _containers(w) if not (c.get("resources") or {}).get("limits")]
        yield CheckResult(_wid(w), not bad, f"No limits: {', '.join(bad)}" if bad else "Limits set")


@fixer("K8S-004")
def _fl(inv, rid):
    w = _w(inv, rid)
    if not w:
        return False
    for c in _containers(w):
        c["resources"] = {"limits": {"cpu": "500m", "memory": "512Mi"}}
    return True


@rule("K8S-005", "kubernetes", "Workloads", "Image uses the mutable :latest tag", "low",
      "Pin images to a version tag or digest.",
      ["code"],
      "The image reference has no tag or uses :latest.",
      "Deployments are not reproducible and a poisoned upstream image is pulled automatically.",
      ["Pin to an immutable version or sha256 digest.", "Scan images in CI before deployment."],
      cli="kubectl set image deployment/{resource} <container>=<image>@sha256:<digest>")
def k8s_latest(inv):
    for w in inv.get("workloads", []):
        bad = [c["image"] for c in _containers(w)
               if c.get("image") and (c["image"].endswith(":latest") or ":" not in c["image"].split("/")[-1])]
        yield CheckResult(_wid(w), not bad, f"Unpinned: {', '.join(bad)}" if bad else "Pinned")


@fixer("K8S-005")
def _fi(inv, rid):
    w = _w(inv, rid)
    if not w:
        return False
    for c in _containers(w):
        base = c.get("image", "app").split(":")[0]
        c["image"] = f"{base}:1.0.0"
    return True


@rule("K8S-006", "kubernetes", "Workloads", "Secret value hard-coded in container env", "high",
      "Load credentials from Kubernetes Secrets or an external secret store, not plain env values.",
      ["secrets"],
      "An env var named like PASSWORD/TOKEN/API_KEY has a literal value in the manifest.",
      "Anyone who can read the manifest, the repo or `kubectl get deploy -o yaml` gets the credential.",
      ["Move the value into a Secret and reference it with valueFrom.secretKeyRef.",
       "Rotate the exposed credential."],
      cli="kubectl create secret generic {resource}-secrets --from-literal=DB_PASSWORD=<new-value>",
      asset="identity")
def k8s_env_secrets(inv):
    for w in inv.get("workloads", []):
        bad = [f"{c['name']}:{e['name']}" for c in _containers(w) for e in c.get("env", [])
               if SECRET_ENV.search(e.get("name", "")) and e.get("value")]
        yield CheckResult(_wid(w), not bad, f"Literal secrets: {', '.join(bad)}" if bad else "No literal secrets")


@fixer("K8S-006")
def _fe(inv, rid):
    w = _w(inv, rid)
    if not w:
        return False
    for c in _containers(w):
        for e in c.get("env", []):
            if SECRET_ENV.search(e.get("name", "")) and e.get("value"):
                e.pop("value")
                e["value_from"] = "secretKeyRef"
    return True


@rule("K8S-007", "kubernetes", "Network", "Sensitive service exposed via LoadBalancer", "high",
      "Admin/database ports should not be exposed with type LoadBalancer.",
      ["network"],
      "A Service of type LoadBalancer/NodePort exposes a database or admin port to the internet.",
      "Internal services (databases, dashboards) become reachable from the internet.",
      ["Change the Service type to ClusterIP.", "Expose only HTTP(S) through an Ingress with auth."],
      cli="kubectl patch svc {resource} -p '{\"spec\":{\"type\":\"ClusterIP\"}}'", asset="network")
def k8s_lb(inv):
    sensitive = {22, 2379, 3306, 5432, 6379, 8443, 9200, 10250, 27017}
    for s in inv.get("services", []):
        exposed = s.get("type") in ("LoadBalancer", "NodePort")
        bad = sorted(p for p in s.get("ports", []) if int(p) in sensitive) if exposed else []
        yield CheckResult(f"k8s/{s.get('namespace', 'default')}/service/{s['name']}", not bad,
                          f"{s.get('type')} exposes ports {bad}" if bad else f"type {s.get('type', 'ClusterIP')}")


@fixer("K8S-007")
def _fs(inv, rid):
    s = find(inv.get("services"), "name", rid.split("/")[-1])
    if s:
        s["type"] = "ClusterIP"
    return bool(s)


@rule("K8S-008", "kubernetes", "RBAC", "cluster-admin bound to a service account", "critical",
      "Avoid binding cluster-admin to workload service accounts.",
      ["access"],
      "A ClusterRoleBinding grants cluster-admin to a ServiceAccount.",
      "Any pod using that service account can take over the whole cluster.",
      ["Replace with a namespaced Role granting only the verbs needed."],
      cli="kubectl delete clusterrolebinding {resource}", refs=["CIS Kubernetes 5.1.1"], asset="identity")
def k8s_rbac(inv):
    for b in inv.get("role_bindings", []):
        bad = b.get("role") == "cluster-admin" and any(s.get("kind") == "ServiceAccount" for s in b.get("subjects", []))
        yield CheckResult(f"k8s/cluster/clusterrolebinding/{b['name']}", not bad,
                          "cluster-admin to ServiceAccount" if bad else f"role {b.get('role')}")


@fixer("K8S-008")
def _fb(inv, rid):
    b = find(inv.get("role_bindings"), "name", rid.split("/")[-1])
    if b:
        b["role"] = "view"
    return bool(b)


@rule("K8S-009", "kubernetes", "Network", "Namespace has no NetworkPolicy", "medium",
      "Each application namespace should have a default-deny NetworkPolicy.",
      ["network"],
      "No NetworkPolicy selects pods in this namespace, so all pod-to-pod traffic is allowed.",
      "A single compromised pod can reach every other service in the cluster (lateral movement).",
      ["Add a default-deny ingress policy, then allow required flows explicitly."],
      terraform='''
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: {resource}
spec:
  podSelector: {}
  policyTypes: ["Ingress"]''',
      cli="kubectl apply -n {resource} -f default-deny.yaml")
def k8s_netpol(inv):
    namespaces = sorted({w.get("namespace", "default") for w in inv.get("workloads", [])})
    covered = set(inv.get("network_policies", []))
    for ns in namespaces:
        yield CheckResult(f"k8s/namespace/{ns}", ns in covered, "Has NetworkPolicy" if ns in covered else "No policy")


@fixer("K8S-009")
def _fn(inv, rid):
    inv.setdefault("network_policies", []).append(rid.split("/")[-1])
    return True
