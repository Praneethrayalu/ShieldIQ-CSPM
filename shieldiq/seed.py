"""Demo data: a sample organization with demo integrations, uploads and a few verified fixes.

Everything here is clearly labelled demo/sample data. The insecure sample code file is generated
at runtime so no secret-looking strings live in the repository."""
from .collectors import demo_inventory
from .collectors.iac import parse_kubernetes, parse_terraform
from .collectors import SAMPLE_DIR
from .extensions import db
from .models import Finding, Integration, Organization, User

DEMO_EMAIL = "demo@shieldiq.local"
DEMO_PASSWORD = "ShieldIQ@2026"


def sample_leaky_code() -> str:
    """An intentionally insecure config file for the secret scanner demo (fake, non-working values)."""
    k = "AKIA" + "ZT4M2N8QW5R7Y6PX"
    s = "wJal" + "rXUtnFEMI/K7MDENG/bPxRfiCY" + "9fakeKEY0z"
    gh = "ghp" + "_" + "R4nd0mFakeT0kenForDem0Purp0sesOnly1234"
    return "\n".join([
        "# settings.py  (sample file with hard-coded secrets for the ShieldIQ demo; values are fake)",
        "import os",
        "",
        "DEBUG = True",
        f'AWS_ACCESS_KEY_ID = "{k}"',
        f'aws_secret_access_key = "{s}"',
        f'GITHUB_TOKEN = "{gh}"',
        'DATABASE_URL = "postgres://admin:' + 'Pr0d-Db-Pa55' + '@db.acme.internal:5432/payments"',
        'SMTP_PASSWORD = "' + 'Wint3r!Mail#2026' + '"',
        'SAFE_EXAMPLE = os.getenv("API_KEY")  # correct: loaded from the environment',
        "",
        "-----BEGIN " + "RSA PRIVATE KEY-----",
        "MIIEowIBAAKCAQEA(truncated-demo-key)",
        "-----END " + "RSA PRIVATE KEY-----",
    ]) + "\n"


def seed_demo(with_fixes=True):
    from .services.remediation import apply_fix
    from .services.scanner import scan_integration

    if User.query.filter_by(email=DEMO_EMAIL).first():
        return None
    org = Organization(name="Acme Labs (Demo)", alert_min_severity="critical", alert_score_drop=5)
    db.session.add(org)
    db.session.flush()
    users = [("Dana Admin", DEMO_EMAIL, "admin"), ("Asha Analyst", "analyst@shieldiq.local", "analyst"),
             ("Vikram Viewer", "viewer@shieldiq.local", "viewer")]
    for name, email, role in users:
        u = User(org_id=org.id, full_name=name, email=email, role=role)
        u.set_password(DEMO_PASSWORD)
        db.session.add(u)
    names = {"aws": "AWS acme-production (demo)", "gcp": "GCP acme-analytics-prod (demo)",
             "azure": "Azure Acme subscription (demo)", "github": "GitHub acme-labs (demo)",
             "slack": "Slack acme-labs (demo)", "kubernetes": "EKS acme-prod (demo)"}
    integs = []
    for prov, name in names.items():
        integs.append(Integration(org_id=org.id, provider=prov, name=name, mode="demo", snapshot=demo_inventory(prov)))
    tf = (SAMPLE_DIR / "uploads" / "main.tf").read_text()
    k8 = (SAMPLE_DIR / "uploads" / "deployment.yaml").read_text()
    integs.append(Integration(org_id=org.id, provider="aws", name="Terraform: main.tf", mode="upload",
                              snapshot=parse_terraform(tf, "main.tf"), config={"filename": "main.tf"}))
    integs.append(Integration(org_id=org.id, provider="kubernetes", name="Manifests: deployment.yaml", mode="upload",
                              snapshot=parse_kubernetes(k8), config={"filename": "deployment.yaml"}))
    integs.append(Integration(org_id=org.id, provider="code", name="Code: settings.py", mode="upload",
                              snapshot={"files": [{"path": "settings.py", "content": sample_leaky_code()}]},
                              config={"filename": "settings.py"}))
    db.session.add_all(integs)
    db.session.commit()
    for integ in integs:
        scan_integration(integ, DEMO_EMAIL, deliver_alerts=False)
    if with_fixes:
        for rule_id in ("AWS-MON-001", "GCP-SQL-002", "SLK-003"):
            f = Finding.query.filter_by(org_id=org.id, rule_id=rule_id, status="open").first()
            if f:
                apply_fix(f, DEMO_EMAIL)
    return org
