"""Google Cloud rules."""
from .engine import CheckResult, fixer, find, open_to_world, port_in, rule


def _set(coll, key, field, value):
    def fn(inv, rid):
        it = find(inv.get(coll), key, rid.split("/")[-1])
        if it is None:
            return False
        it[field] = value
        return True
    return fn


@rule("GCP-GCS-001", "gcp", "Cloud Storage", "Cloud Storage bucket is public (allUsers / allAuthenticatedUsers)", "critical",
      "Buckets must not grant IAM roles to allUsers or allAuthenticatedUsers.",
      ["public_data"],
      "The bucket IAM policy binds a role (e.g. roles/storage.objectViewer) to allUsers or allAuthenticatedUsers.",
      "Anyone on the internet (or any Google account) can read the bucket's objects.",
      ["Remove the allUsers / allAuthenticatedUsers bindings.", "Enable Public Access Prevention on the bucket.",
       "Serve public assets through Cloud CDN with signed URLs instead."],
      terraform='''
resource "google_storage_bucket" "{resource}" {
  name                        = "{resource}"
  location                    = "US"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
}''',
      cli="gcloud storage buckets remove-iam-policy-binding gs://{resource} --member=allUsers "
          "--role=roles/storage.objectViewer && gcloud storage buckets update gs://{resource} --public-access-prevention",
      refs=["CIS GCP 5.1"], asset="datastore")
def gcs_public(inv):
    for b in inv.get("buckets", []):
        pub = [m for m in b.get("iam_members", []) if m in ("allUsers", "allAuthenticatedUsers")]
        yield CheckResult(f"projects/{inv.get('project_id', 'project')}/buckets/{b['name']}", not pub,
                          f"Public members: {', '.join(pub)}" if pub else "Private")


@fixer("GCP-GCS-001")
def _fix_gcs(inv, rid):
    b = find(inv.get("buckets"), "name", rid.split("/")[-1])
    if not b:
        return False
    b["iam_members"] = [m for m in b.get("iam_members", []) if m not in ("allUsers", "allAuthenticatedUsers")]
    return True


@rule("GCP-GCS-002", "gcp", "Cloud Storage", "Uniform bucket-level access is disabled", "medium",
      "Use uniform bucket-level access so object ACLs cannot bypass IAM.",
      ["access"],
      "Fine-grained (legacy ACL) access control is enabled.",
      "Individual objects can be made public with ACLs that IAM reviews will not show.",
      ["Enable uniform bucket-level access."],
      cli="gcloud storage buckets update gs://{resource} --uniform-bucket-level-access",
      refs=["CIS GCP 5.2"], asset="datastore")
def gcs_uniform(inv):
    for b in inv.get("buckets", []):
        yield CheckResult(f"projects/{inv.get('project_id', 'project')}/buckets/{b['name']}",
                          bool(b.get("uniform_access")), "Uniform access" if b.get("uniform_access") else "Legacy ACLs")


fixer("GCP-GCS-002")(_set("buckets", "name", "uniform_access", True))


@rule("GCP-NET-001", "gcp", "VPC", "Firewall rule allows SSH/RDP from 0.0.0.0/0", "critical",
      "Ingress firewall rules must not expose 22/3389 to the internet.",
      ["network"],
      "An INGRESS rule with sourceRanges 0.0.0.0/0 allows tcp:22 or tcp:3389.",
      "VMs on the network are exposed to internet-wide brute force and exploits.",
      ["Delete or narrow the rule.", "Use Identity-Aware Proxy (IAP) TCP forwarding (source 35.235.240.0/20)."],
      terraform='''
resource "google_compute_firewall" "{resource}" {
  name          = "{resource}"
  network       = "default"
  direction     = "INGRESS"
  source_ranges = ["35.235.240.0/20"]   # IAP only
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}''',
      cli="gcloud compute firewall-rules update {resource} --source-ranges=35.235.240.0/20",
      refs=["CIS GCP 3.6", "CIS GCP 3.7"], asset="network")
def gcp_fw(inv):
    for fw in inv.get("firewall_rules", []):
        if fw.get("direction", "INGRESS") != "INGRESS":
            continue
        world = any(open_to_world(s) for s in fw.get("source_ranges", []))
        bad = []
        for a in fw.get("allowed", []):
            for p in a.get("ports", ["0-65535"]) or ["0-65535"]:
                lo, _, hi = str(p).partition("-")
                for port in (22, 3389):
                    if port_in(port, lo, hi or lo):
                        bad.append(str(port))
        flagged = world and bad
        yield CheckResult(f"projects/{inv.get('project_id', 'project')}/firewalls/{fw['name']}", not flagged,
                          f"Ports {', '.join(sorted(set(bad)))} open to 0.0.0.0/0" if flagged else "Restricted")


@fixer("GCP-NET-001")
def _fix_fw(inv, rid):
    fw = find(inv.get("firewall_rules"), "name", rid.split("/")[-1])
    if not fw:
        return False
    fw["source_ranges"] = ["35.235.240.0/20"]
    return True


@rule("GCP-IAM-001", "gcp", "IAM", "Service account key older than 90 days", "medium",
      "User-managed service account keys should be rotated within 90 days (or avoided).",
      ["credentials"],
      "A user-managed JSON key exists and has not been rotated.",
      "JSON keys leak through repos and laptops and never expire on their own.",
      ["Switch workloads to Workload Identity / attached service accounts.", "Delete old keys."],
      cli="gcloud iam service-accounts keys delete <KEY_ID> --iam-account={resource}",
      refs=["CIS GCP 1.7"], asset="identity")
def sa_keys(inv):
    for sa in inv.get("service_accounts", []):
        if sa.get("keys"):
            oldest = max(k.get("age_days", 0) for k in sa["keys"])
            yield CheckResult(sa["email"], oldest <= 90, f"Oldest key {oldest} days")


@fixer("GCP-IAM-001")
def _fix_sak(inv, rid):
    sa = find(inv.get("service_accounts"), "email", rid)
    if not sa:
        return False
    sa["keys"] = []
    return True


@rule("GCP-IAM-002", "gcp", "IAM", "Service account has Owner/Editor primitive role", "high",
      "Service accounts should not hold project-wide primitive roles.",
      ["access"],
      "roles/owner or roles/editor is granted to a service account.",
      "Any VM or workload running as this account can modify almost everything in the project.",
      ["Replace the primitive role with narrowly scoped predefined roles."],
      cli="gcloud projects remove-iam-policy-binding <PROJECT> --member=serviceAccount:{resource} --role=roles/editor",
      refs=["CIS GCP 1.5"], asset="identity")
def sa_roles(inv):
    for sa in inv.get("service_accounts", []):
        bad = [r for r in sa.get("roles", []) if r in ("roles/owner", "roles/editor")]
        yield CheckResult(sa["email"], not bad, f"Has {', '.join(bad)}" if bad else "Scoped roles")


@fixer("GCP-IAM-002")
def _fix_sar(inv, rid):
    sa = find(inv.get("service_accounts"), "email", rid)
    if not sa:
        return False
    sa["roles"] = [r for r in sa.get("roles", []) if r not in ("roles/owner", "roles/editor")] + ["roles/viewer"]
    return True


@rule("GCP-SQL-001", "gcp", "Cloud SQL", "Cloud SQL instance is open to 0.0.0.0/0", "critical",
      "Cloud SQL authorized networks must not include 0.0.0.0/0.",
      ["network", "public_data"],
      "The instance has a public IP and 0.0.0.0/0 in authorized networks.",
      "The database port is reachable from anywhere on the internet.",
      ["Remove 0.0.0.0/0 from authorized networks.", "Use private IP and the Cloud SQL Auth Proxy."],
      cli="gcloud sql instances patch {resource} --clear-authorized-networks",
      refs=["CIS GCP 6.5"], asset="datastore")
def sql_open(inv):
    for s in inv.get("sql_instances", []):
        bad = s.get("public_ip") and any(open_to_world(n) for n in s.get("authorized_networks", []))
        yield CheckResult(f"projects/{inv.get('project_id', 'project')}/instances/{s['name']}", not bad,
                          "Public IP open to 0.0.0.0/0" if bad else "Restricted")


@fixer("GCP-SQL-001")
def _fix_sql(inv, rid):
    s = find(inv.get("sql_instances"), "name", rid.split("/")[-1])
    if not s:
        return False
    s["authorized_networks"] = []
    return True


@rule("GCP-SQL-002", "gcp", "Cloud SQL", "Cloud SQL does not require SSL/TLS", "medium",
      "Connections to Cloud SQL should require TLS.",
      ["encryption_transit"],
      "requireSsl / sslMode allows unencrypted connections.",
      "Credentials and query data can be sniffed in transit.",
      ["Set SSL mode to ENCRYPTED_ONLY (or TRUSTED_CLIENT_CERTIFICATE_REQUIRED)."],
      cli="gcloud sql instances patch {resource} --ssl-mode=ENCRYPTED_ONLY",
      refs=["CIS GCP 6.4"], asset="datastore")
def sql_ssl(inv):
    for s in inv.get("sql_instances", []):
        yield CheckResult(f"projects/{inv.get('project_id', 'project')}/instances/{s['name']}",
                          bool(s.get("require_ssl")), "TLS required" if s.get("require_ssl") else "TLS optional")


fixer("GCP-SQL-002")(_set("sql_instances", "name", "require_ssl", True))


@rule("GCP-GCE-001", "gcp", "Compute Engine", "VM uses default service account with full API scope", "high",
      "Instances should not run as the default compute SA with cloud-platform scope.",
      ["access", "hardening"],
      "The VM runs as PROJECT_NUMBER-compute@developer.gserviceaccount.com with the cloud-platform scope.",
      "Code execution on the VM yields an Editor-level token for the whole project.",
      ["Create a dedicated least-privilege service account.", "Attach it to the VM with minimal scopes."],
      cli="gcloud compute instances set-service-account {resource} --service-account=<app-sa> --scopes=cloud-platform",
      refs=["CIS GCP 4.1", "CIS GCP 4.2"], asset="compute")
def gce_default_sa(inv):
    for vm in inv.get("compute_instances", []):
        bad = str(vm.get("service_account", "")).endswith("-compute@developer.gserviceaccount.com") and \
            "cloud-platform" in vm.get("scopes", [])
        yield CheckResult(f"projects/{inv.get('project_id', 'project')}/instances/{vm['name']}", not bad,
                          "Default SA + full scope" if bad else "Dedicated SA")


@fixer("GCP-GCE-001")
def _fix_gce(inv, rid):
    vm = find(inv.get("compute_instances"), "name", rid.split("/")[-1])
    if not vm:
        return False
    vm["service_account"] = f"{vm['name']}-sa@{inv.get('project_id', 'project')}.iam.gserviceaccount.com"
    vm["scopes"] = ["logging-write", "monitoring-write"]
    return True


@rule("GCP-LOG-001", "gcp", "Logging", "Data Access audit logs are not enabled", "medium",
      "Enable Cloud Audit Logs (DATA_READ/DATA_WRITE) for all services.",
      ["logging"],
      "The project's audit config does not enable data access logs.",
      "Reads of sensitive data leave no trace for investigations.",
      ["Enable DATA_READ and DATA_WRITE audit logs for allServices."],
      cli="gcloud projects get-iam-policy <PROJECT> > policy.yaml  # add auditConfigs for allServices, then set-iam-policy",
      refs=["CIS GCP 2.1"])
def gcp_audit(inv):
    if "audit_logging_enabled" in inv:
        yield CheckResult(f"projects/{inv.get('project_id', 'project')}", bool(inv["audit_logging_enabled"]),
                          "Enabled" if inv["audit_logging_enabled"] else "Disabled")


@fixer("GCP-LOG-001")
def _fix_gal(inv, rid):
    inv["audit_logging_enabled"] = True
    return True
