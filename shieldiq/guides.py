"""Step-by-step setup guides shown at /guides and linked from the app.

Kept strictly to what the code supports: live connectors exist only for AWS (read-only, boto3) and GitHub
(REST API). GCP, Azure, Slack and Kubernetes are scanned from a JSON snapshot in ShieldIQ's inventory format
(or the built-in demo); Kubernetes YAML can also go straight into the IaC scanner."""

# Each step: (title, text, commands: list[str], mock: list[(label, value, highlight)] | None)
GUIDES = {
    "aws": {
        "mode": "live", "mode_label": "Live · read-only",
        "summary": "ShieldIQ reads your AWS account with read-only Describe/List/Get calls. It never changes anything in AWS.",
        "need": "An AWS account where you can create an IAM user, and Python packages from requirements-cloud.txt on the machine running ShieldIQ.",
        "platform": [
            ("Install the AWS add-on (once)", "On the computer that runs ShieldIQ, install the optional AWS library (boto3).",
             ["pip install -r requirements-cloud.txt"], None),
            ("Create a read-only user", "AWS console → IAM → Users → Create user. Name it e.g. shieldiq-readonly. Do not give it console access.",
             [], [("Service", "IAM", False), ("Users", "Create user", True), ("User name", "shieldiq-readonly", False)]),
            ("Attach the SecurityAudit policy", "Permissions → Attach policies directly → search SecurityAudit (AWS managed, read-only) → tick it → Create user.",
             [], [("Permissions", "Attach policies directly", False), ("Policy", "SecurityAudit", True), ("Type", "AWS managed · read-only", False)]),
            ("Create an access key", "Open the user → Security credentials → Create access key → “Application running outside AWS”. Copy the Access key ID and Secret access key now: AWS shows the secret only once.",
             [], [("Tab", "Security credentials", False), ("Action", "Create access key", True), ("Copy", "Access key ID + Secret", False)]),
            ("Or use a CLI profile instead", "If you already use the AWS CLI, create a profile and type its name in ShieldIQ instead of pasting keys.",
             ["aws configure --profile shieldiq"], None),
        ],
        "shieldiq": [
            ("Connect", "ShieldIQ → Integrations → Connect source → Amazon Web Services → Live. Paste the key and secret (or the profile name) and pick the region to scan, then Connect.",
             [], [("Provider", "Amazon Web Services", False), ("Mode", "Live", True), ("Region", "us-east-1", False)]),
            ("First scan runs by itself", "Connecting runs the first scan straight away. If AWS rejects the credentials, ShieldIQ says why and saves nothing.", [], None),
            ("Scan again any time", "Press Scan on the source card, or Scan all in the top bar.", [], None),
        ],
        "notes": ["Keys are encrypted at rest in ShieldIQ's database. Never commit them to Git.",
                  "Auto-fix only changes demo and imported sources. For a live AWS account, use the fix's CLI script or Terraform, or open a GitHub pull request.",
                  "The live AWS collector is covered by the test suite against a mocked AWS API."],
    },
    "github": {
        "mode": "live", "mode_label": "Live · read-only",
        "summary": "ShieldIQ reads repositories through the GitHub REST API: branch protection, SECURITY.md, Dependabot, outside collaborators, and a secret scan of up to 60 files per repo.",
        "need": "A GitHub owner (user or organization) or a single owner/repo. A token is optional for public repos.",
        "platform": [
            ("Public repos: nothing to do", "Public repositories scan without a token (GitHub allows 60 API requests per hour this way).", [], None),
            ("Optional: create a fine-grained token", "GitHub → Settings → Developer settings → Personal access tokens → Fine-grained tokens → Generate new token. Choose only the repositories to scan.",
             [], [("Token type", "Fine-grained", True), ("Repository access", "Only select repositories", False), ("Expiration", "30 days", False)]),
            ("Give it read-only permissions", "Repository permissions: Contents → Read-only, Metadata → Read-only, Administration → Read-only (lets ShieldIQ read branch-protection details and collaborators). Generate and copy the token.",
             [], [("Contents", "Read-only", False), ("Metadata", "Read-only", False), ("Administration", "Read-only", True)]),
        ],
        "shieldiq": [
            ("Connect", "ShieldIQ → Integrations → Connect source → GitHub → Live. Type an owner (octocat) or owner/repo (octocat/Hello-World), paste the token if you made one, then Connect.",
             [], [("Provider", "GitHub", False), ("Mode", "Live", True), ("Target", "owner/repo", False)]),
            ("What gets scanned", "For an owner, the 5 most recently pushed repositories (forks and archived repos skipped). For owner/repo, just that repository.", [], None),
            ("Scan again any time", "Press Scan on the source card, or Scan all in the top bar.", [], None),
        ],
        "notes": ["Secrets found in files are always shown masked.",
                  "To open fix pull requests, add a remediation repository and a token with Contents + Pull requests write access in Settings."],
    },
    "gcp": {
        "mode": "snapshot", "mode_label": "Snapshot import",
        "summary": "There is no live Google Cloud connector yet. You export your settings with read-only gcloud commands and import them as a JSON snapshot in ShieldIQ's format.",
        "need": "Access to the project in the Google Cloud console (Cloud Shell has gcloud built in).",
        "platform": [
            ("Download the template", "ShieldIQ → Integrations → Connect source → Google Cloud → Import JSON → Download a template. It shows the fields ShieldIQ reads: buckets, firewall_rules, service_accounts, sql_instances, compute_instances, audit_logging_enabled.",
             [], [("Provider", "Google Cloud", False), ("Mode", "Import JSON", True), ("Link", "Download a template", False)]),
            ("Open Cloud Shell", "In the Google Cloud console, click the Cloud Shell icon (>_) at the top right and select your project.",
             ["gcloud config set project YOUR_PROJECT_ID"], None),
            ("Export the raw settings (read-only)", "These commands only list resources. They print JSON you can copy from.",
             ["gcloud storage buckets list --format=json > buckets.json",
              "gcloud compute firewall-rules list --format=json > firewall.json",
              "gcloud iam service-accounts list --format=json > service-accounts.json",
              "gcloud sql instances list --format=json > sql.json",
              "gcloud compute instances list --format=json > instances.json"], None),
            ("Fill in the template", "Copy the values you need (names, source ranges, public IPs, IAM members) into the template's fields. ShieldIQ does not convert gcloud output automatically; the template shows the exact shape.", [], None),
        ],
        "shieldiq": [
            ("Import", "Integrations → Connect source → Google Cloud → Import JSON → choose your file → Connect. The first scan runs straight away.",
             [], [("Mode", "Import JSON", True), ("File", "gcp-snapshot.json", False)]),
            ("Or try the demo first", "Pick Demo instead of Import JSON to see a sample Google Cloud project with real findings.", [], None),
        ],
        "notes": ["Auto-fix works on imported snapshots: it fixes the stored copy and re-scans, so you can see the result before changing the real project."],
    },
    "azure": {
        "mode": "snapshot", "mode_label": "Snapshot import",
        "summary": "There is no live Azure connector yet. You export settings with read-only az commands and import them as a JSON snapshot in ShieldIQ's format.",
        "need": "Reader access to the subscription (Azure Cloud Shell has the az CLI built in).",
        "platform": [
            ("Download the template", "ShieldIQ → Integrations → Connect source → Microsoft Azure → Import JSON → Download a template. Fields: storage_accounts, nsgs, sql_servers, key_vaults, vms, users, defender_enabled.",
             [], [("Provider", "Microsoft Azure", False), ("Mode", "Import JSON", True), ("Link", "Download a template", False)]),
            ("Open Cloud Shell", "In the Azure portal, click the Cloud Shell icon (>_) in the top bar and choose Bash.",
             ["az account set --subscription YOUR_SUBSCRIPTION_ID"], None),
            ("Export the raw settings (read-only)", "These commands only list resources.",
             ["az storage account list -o json > storage.json",
              "az network nsg list -o json > nsgs.json",
              "az sql server list -o json > sql.json",
              "az keyvault list -o json > keyvaults.json",
              "az vm list -d -o json > vms.json"], None),
            ("Fill in the template", "Copy the values into the template's fields. For users and MFA, check Microsoft Entra admin center → Users. ShieldIQ does not convert az output automatically.", [], None),
        ],
        "shieldiq": [
            ("Import", "Integrations → Connect source → Microsoft Azure → Import JSON → choose your file → Connect.",
             [], [("Mode", "Import JSON", True), ("File", "azure-snapshot.json", False)]),
            ("Or try the demo first", "Pick Demo to see a sample Azure subscription.", [], None),
        ],
        "notes": ["Use a Reader role for exports. Nothing in these steps can change your subscription."],
    },
    "kubernetes": {
        "mode": "yaml", "mode_label": "YAML upload or snapshot",
        "summary": "No live cluster connection. The quickest route is to export your workloads as YAML with kubectl and drop the file into ShieldIQ's IaC scanner, which understands kubectl's List output.",
        "need": "kubectl access to the cluster (read-only is enough).",
        "platform": [
            ("Export the workloads (read-only)", "Run this where kubectl points at your cluster. Keep the file under 2 MB; add -n NAMESPACE to export one namespace if it is bigger.",
             ["kubectl get deployments,statefulsets,daemonsets,jobs,cronjobs,pods,services,rolebindings,clusterrolebindings,networkpolicies -A -o yaml > cluster.yaml"], None),
        ],
        "shieldiq": [
            ("Scan the file", "ShieldIQ → IaC & secret scan → Infrastructure as Code → drop cluster.yaml → Scan. Findings appear right on the page: privileged or root containers, host network, missing limits, :latest images, hard-coded secrets in env, LoadBalancer services, cluster-admin bindings and namespaces without a NetworkPolicy.",
             [], [("Page", "IaC & secret scan", False), ("Card", "Infrastructure as Code", False), ("File", "cluster.yaml", True)]),
            ("Or keep it as a source", "Integrations → Connect source → Kubernetes → Import JSON (template download) to track the cluster over time, or Demo to see a sample cluster.", [], None),
        ],
        "notes": ["The export contains your pod specs, including any plain-text env values (ShieldIQ flags those). It does not include Secret objects. Keep the file private."],
    },
    "slack": {
        "mode": "snapshot", "mode_label": "Snapshot import",
        "summary": "No live Slack connector. You note a few workspace settings and the installed apps' scopes from the Slack admin pages and import them as a small JSON snapshot.",
        "need": "Workspace admin or owner access.",
        "platform": [
            ("Download the template", "ShieldIQ → Integrations → Connect source → Slack → Import JSON → Download a template. Fields: workspace (two_factor_required, public_file_sharing, session_duration_hours, external_channel_approval) and apps (name, scopes).",
             [], [("Provider", "Slack", False), ("Mode", "Import JSON", True), ("Link", "Download a template", False)]),
            ("Read the workspace settings", "Slack → workspace name → Tools & settings → Workspace settings → Authentication (2FA, session duration) and Permissions (file sharing, Slack Connect approvals).",
             [], [("Menu", "Tools & settings", False), ("Page", "Workspace settings", True), ("Tab", "Authentication", False)]),
            ("List installed apps and scopes", "Tools & settings → Manage apps → open each app to see its permissions (scopes). Copy them into apps.", [], None),
        ],
        "shieldiq": [
            ("Import", "Integrations → Connect source → Slack → Import JSON → choose your file → Connect.",
             [], [("Mode", "Import JSON", True), ("File", "slack-snapshot.json", False)]),
        ],
        "notes": ["Slack checks: 2FA not required, public file links, sessions over 7 days, Slack Connect channels without approval, apps with broad data-access scopes."],
    },
}

AFTER = [
    ("Read the findings", "Findings lists everything worst first. Filter by severity or source; search by resource ID or rule ID.", "findings"),
    ("Open one finding", "Each finding explains what was found, why it matters, and the fix as steps, a CLI command and Terraform/YAML, with copy buttons.", "finding"),
    ("Fix it, and prove it", "Auto-fix & verify changes the stored configuration of a demo or imported source and scans again; it is marked resolved only if the check now passes. For live sources, download the fix script or open a GitHub pull request.", "fixed"),
    ("Cut attack paths first", "Attack paths shows chains of findings from the internet to sensitive data. Fix the step marked “Fix here” and every path through it breaks.", "paths"),
    ("Get a compliance PDF", "Compliance → pick a framework (CIS, SOC 2, ISO 27001, PCI DSS, GDPR, NIST, HIPAA) → PDF report. Every report is also kept on the Reports page.", "compliance"),
]
