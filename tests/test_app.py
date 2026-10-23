"""End-to-end tests through the Flask test client: auth, RBAC, tenancy, scans, remediation, reports, API."""
import io
import re

from conftest import login

from shieldiq.extensions import db
from shieldiq.models import Alert, AuditLog, Finding, Integration, Organization, Remediation, ScanRun, User
from shieldiq.services import attack_graph
from shieldiq.services.scanner import posture_score, scan_integration

PAGES = ["/", "/findings", "/findings?status=all&severity=critical", "/compliance", "/compliance?fw=HIPAA",
         "/attack-paths", "/integrations", "/scanners", "/copilot", "/reports", "/alerts", "/settings", "/rules",
         "/rules?provider=kubernetes", "/api-docs", "/audit", "/users"]


# ---------------------------------------------------------------- auth
def test_pages_require_login(client, demo):
    for p in ["/findings", "/settings", "/attack-paths", "/dashboard"]:
        r = client.get(p)
        assert r.status_code == 302 and "/login" in r.headers["Location"]
    assert client.get("/api/v1/summary").status_code == 401
    # "/" is the public landing page for visitors, never the dashboard
    r = client.get("/")
    assert r.status_code == 200 and b"Try live demo" in r.data and b"hero-title" in r.data and b"Security overview" not in r.data


def test_login_logout(client, demo):
    assert login(client, password="wrong").status_code == 401
    r = login(client)
    assert r.status_code == 302
    r = client.get("/")
    assert r.status_code == 200 and b"Security overview" in r.data
    client.post("/logout")
    assert client.get("/findings").status_code == 302
    assert b"Security overview" not in client.get("/").data


def test_lockout_after_failed_attempts(client, demo, app):
    for _ in range(app.config["LOGIN_MAX_ATTEMPTS"]):
        login(client, password="nope")
    assert login(client).status_code == 429  # correct password still refused while locked
    assert AuditLog.query.filter_by(action="auth.failed_login").count() >= 5


def test_open_redirect_blocked(client, demo):
    r = client.post("/login?next=https://evil.example/x", data={"email": "demo@shieldiq.local", "password": "ShieldIQ@2026"})
    assert r.headers["Location"] == "/"


def test_register_validation_and_new_org(client, demo):
    r = client.post("/register", data={"full_name": "A", "email": "bad", "org_name": "", "password": "short", "confirm": "x"})
    assert r.status_code == 400
    r = client.post("/register", data={"full_name": "New Admin", "email": "new@corp.io", "org_name": "Corp",
                                       "password": "GoodPassw0rd", "confirm": "GoodPassw0rd"})
    assert r.status_code == 302
    u = User.query.filter_by(email="new@corp.io").first()
    assert u.role == "admin" and u.org.name == "Corp" and u.password_hash != "GoodPassw0rd"
    # a brand-new org sees none of the demo org's data
    assert Finding.query.filter_by(org_id=u.org_id).count() == 0
    assert client.get("/").status_code == 200


def test_all_pages_render_for_admin(admin):
    for p in PAGES:
        r = admin.get(p)
        assert r.status_code == 200, p
        visible = re.sub(r"<script.*?</script>|<[^>]+>", " ", r.data.decode(), flags=re.S)
        assert not re.search(r"ShieldIQ\s*v\d|\bv2\.\d", visible), p  # the product is just "ShieldIQ"
    f = Finding.query.first()
    assert admin.get(f"/findings/{f.id}").status_code == 200


def test_security_headers(admin):
    r = admin.get("/")
    assert r.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'self'" in r.headers["Content-Security-Policy"]
    assert r.headers["X-Content-Type-Options"] == "nosniff"


# ---------------------------------------------------------------- landing page
def test_landing_page_for_visitors(client, demo):
    r = client.get("/")
    html = r.data.decode()
    assert r.status_code == 200
    assert "<title>Cloud security posture, with attack paths · ShieldIQ</title>" in html
    # live counts come from the code, not hard-coded copy
    from shieldiq.rules import RULES
    from shieldiq.services.compliance import FRAMEWORKS
    assert f'data-stat="{len(RULES)}"' in html and f'data-stat="{len(FRAMEWORKS)}"' in html
    # "Try live demo" is a CSRF-protected sign-in form for the public demo account
    assert 'action="/login"' in html and 'name="csrf_token"' in html and 'value="demo@shieldiq.local"' in html
    assert 'href="/login"' in html and "landing.js" in html and "landing.css" in html
    # CSP: no inline executable scripts, only JSON data blocks or external files
    for tag in re.findall(r"<script[^>]*>", html):
        assert "src=" in tag or 'type="application/json"' in tag, tag
    visible = re.sub(r"<script.*?</script>|<[^>]+>", " ", html, flags=re.S)
    assert not re.search(r"ShieldIQ\s*v\d|ShieldIQ\s+2\b", visible)  # the product is just "ShieldIQ" (finding titles may mention e.g. "metadata v2")
    # every static asset the page references exists
    for path in set(re.findall(r'(?:src|href)="(/static/[^"?]+)', html)):
        assert client.get(path).status_code == 200, path


def test_landing_demo_button_logs_in(client, demo):
    from flask import current_app
    current_app.config["WTF_CSRF_ENABLED"] = False
    r = client.post("/login", data={"email": "demo@shieldiq.local", "password": "ShieldIQ@2026"})
    assert r.status_code == 302 and r.headers["Location"] == "/"
    assert b"Security overview" in client.get("/").data


def test_landing_without_demo_account(client):
    html = client.get("/").data.decode()
    assert "demo@shieldiq.local" not in html and 'href="/register"' in html


def test_landing_reachable_when_signed_in(admin):
    r = admin.get("/welcome")
    assert r.status_code == 200 and b"Open your dashboard" in r.data
    assert admin.get("/dashboard").headers["Location"] == "/"
    assert admin.get("/login").status_code == 302


def test_theme_toggle_is_saved(admin):
    from shieldiq.models import User
    r = admin.post("/settings/theme", json={"theme": "light"})
    assert r.status_code == 200 and User.query.filter_by(email="demo@shieldiq.local").first().theme == "light"
    assert admin.post("/settings/theme", json={"theme": "pink"}).status_code == 400
    assert b'data-theme="light"' in admin.get("/").data


def test_login_demo_prefill(client, demo):
    html = client.get("/login?demo=1").data.decode()
    assert 'value="demo@shieldiq.local"' in html and 'value="ShieldIQ@2026"' in html
    assert 'value="ShieldIQ@2026"' not in client.get("/login").data.decode().split("demo-box")[0]


def test_error_page_styled(client):
    r = client.get("/no-such-page")
    assert r.status_code == 404 and b"err-code" in r.data


# ---------------------------------------------------------------- RBAC & tenancy
def test_viewer_is_read_only(viewer):
    f = Finding.query.filter_by(status="open").first()
    assert viewer.get("/").status_code == 200
    assert viewer.post("/scan-all").status_code == 403
    assert viewer.post(f"/findings/{f.id}/status", data={"status": "resolved"}).status_code == 403
    assert viewer.post(f"/findings/{f.id}/autofix").status_code == 403
    assert viewer.get("/users").status_code == 403
    assert viewer.get("/audit").status_code == 403


def test_analyst_can_triage_but_not_admin(analyst):
    f = Finding.query.filter_by(status="open").first()
    r = analyst.post(f"/findings/{f.id}/status", data={"status": "in_progress", "note": "on it"})
    assert r.status_code == 302 and db.session.get(Finding, f.id).status == "in_progress"
    assert analyst.get("/users").status_code == 403
    assert analyst.post("/integrations/new", data={"provider": "aws", "mode": "demo"}).status_code == 403


def test_tenant_isolation(client, demo):
    other = Organization(name="Other")
    db.session.add(other)
    db.session.flush()
    u = User(org_id=other.id, email="o@other.io", full_name="Other User", role="admin")
    u.set_password("OtherPassw0rd")
    db.session.add(u)
    db.session.commit()
    login(client, "o@other.io", "OtherPassw0rd")
    f = Finding.query.filter_by(org_id=demo.id).first()
    i = Integration.query.filter_by(org_id=demo.id).first()
    assert client.get(f"/findings/{f.id}").status_code == 404
    assert client.post(f"/integrations/{i.id}/scan").status_code == 404
    assert client.get(f"/integrations/{i.id}/inventory.json").status_code == 404
    assert client.get("/api/v1/findings").json["findings"] == []


# ---------------------------------------------------------------- scanning lifecycle
def test_seed_scans_and_scores(demo):
    assert Integration.query.filter_by(org_id=demo.id).count() == 9
    assert Finding.query.filter_by(org_id=demo.id).count() > 50
    s = posture_score(demo.id)
    assert 0 <= s <= 100
    assert ScanRun.query.filter_by(org_id=demo.id, status="completed").count() == 9


def test_rescan_is_idempotent(demo):
    integ = Integration.query.filter_by(org_id=demo.id, provider="aws", mode="demo").first()
    before = Finding.query.filter_by(integration_id=integ.id).count()
    run = scan_integration(integ, "t", deliver_alerts=False)
    assert run.new_findings == 0 and run.resolved_findings == 0
    assert Finding.query.filter_by(integration_id=integ.id).count() == before


def test_auto_resolve_and_regression(demo):
    integ = Integration.query.filter_by(org_id=demo.id, provider="slack").first()
    f = Finding.query.filter_by(integration_id=integ.id, rule_id="SLK-001").first()
    inv = dict(integ.snapshot)
    inv["workspace"] = dict(inv["workspace"], two_factor_required=True)
    integ.snapshot = inv
    run = scan_integration(integ, "t", deliver_alerts=False)
    assert run.resolved_findings >= 1 and db.session.get(Finding, f.id).status == "resolved"
    inv = dict(integ.snapshot)
    inv["workspace"] = dict(inv["workspace"], two_factor_required=False)
    integ.snapshot = inv
    scan_integration(integ, "t", deliver_alerts=False)
    assert db.session.get(Finding, f.id).status == "open"


def test_alerts_raised_for_new_critical_findings(admin, demo):
    before = Alert.query.filter_by(org_id=demo.id, kind="new_finding").count()
    r = admin.post("/integrations/new", data={"provider": "aws", "mode": "demo", "name": "AWS second"})
    assert r.status_code == 302
    assert Alert.query.filter_by(org_id=demo.id, kind="new_finding").count() > before


def test_snapshot_import_and_bad_json(admin):
    good = io.BytesIO(b'{"buckets": [{"name": "public-data", "iam_members": ["allUsers"], "uniform_access": true}]}')
    admin.post("/integrations/new", data={"provider": "gcp", "mode": "snapshot", "snapshot": (good, "s.json")},
               content_type="multipart/form-data")
    integ = Integration.query.filter_by(mode="snapshot").first()
    assert integ and Finding.query.filter_by(integration_id=integ.id, rule_id="GCP-GCS-001").count() == 1
    bad = io.BytesIO(b"{not json")
    r = admin.post("/integrations/new", data={"provider": "gcp", "mode": "snapshot", "snapshot": (bad, "b.json")},
                   content_type="multipart/form-data", follow_redirects=True)
    assert b"Invalid JSON" in r.data


def test_live_aws_without_boto3_or_creds_fails_cleanly(admin):
    r = admin.post("/integrations/new", data={"provider": "aws", "mode": "live"}, follow_redirects=True)
    assert b"access key" in r.data.lower()


def test_failed_live_connection_is_not_saved(admin, monkeypatch):
    from shieldiq.collectors import CollectorError, github_live

    def fail(*a, **k):
        raise CollectorError("Not found on GitHub: /users/nobody")
    monkeypatch.setattr(github_live, "collect", fail)
    before = Integration.query.count()
    r = admin.post("/integrations/new", data={"provider": "github", "mode": "live", "target": "nobody/x"}, follow_redirects=True)
    assert b"Could not connect" in r.data and b"Not found on GitHub" in r.data
    assert Integration.query.count() == before


def test_failed_first_connection_raises_no_alert(admin, monkeypatch):
    """A brand-new connection whose first scan fails is not kept, so it must not leave a "Scan failed" alert behind."""
    from shieldiq.collectors import CollectorError, github_live
    from shieldiq.models import Alert

    def fail(*a, **k):
        raise CollectorError("Not found on GitHub: /users/nobody")
    monkeypatch.setattr(github_live, "collect", fail)
    before = Alert.query.filter_by(kind="scan_failed").count()
    r = admin.post("/integrations/new", data={"provider": "github", "mode": "live", "target": "nobody/x", "name": "Ghost repo"}, follow_redirects=True)
    assert b"Nothing was saved" in r.data
    assert Alert.query.filter_by(kind="scan_failed").count() == before
    assert not Alert.query.filter(Alert.title.like("%Ghost repo%")).count()


def test_upload_scanners(admin):
    tf = b'resource "aws_security_group" "x" {\n  ingress {\n    from_port = 3389\n    to_port = 3389\n    protocol = "tcp"\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n'
    r = admin.post("/scanners", data={"kind": "iac", "file": (io.BytesIO(tf), "rdp.tf")}, content_type="multipart/form-data")
    assert r.status_code == 200 and b"Security group allows SSH/RDP" in r.data
    r = admin.post("/scanners", data={"kind": "secrets", "filename": "c.py",
                                      "content": "GH = 'ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8" + "'"})
    assert b"SaaS / API token committed" in r.data
    r = admin.post("/scanners", data={"kind": "iac", "file": (io.BytesIO(b"x"), "evil.exe")},
                   content_type="multipart/form-data", follow_redirects=True)
    assert b"Unsupported file type" in r.data
    # Terraform pasted into the textarea arrives with CRLF line endings from a real browser
    pasted = tf.decode().replace("\n", "\r\n")
    r = admin.post("/scanners", data={"kind": "iac", "content": pasted})
    assert r.status_code == 200 and b"Security group allows SSH/RDP" in r.data


def test_delete_integration_removes_findings(admin, demo):
    integ = Integration.query.filter_by(org_id=demo.id, provider="slack").first()
    admin.post(f"/integrations/{integ.id}/delete")
    assert Finding.query.filter_by(integration_id=integ.id).count() == 0
    assert db.session.get(Integration, integ.id) is None


# ---------------------------------------------------------------- attack paths & remediation
def test_attack_paths_and_choke_point_fix(admin, demo):
    g = attack_graph.build(demo.id)
    assert g["paths"] and g["choke_points"]
    sg = Finding.query.filter_by(org_id=demo.id, rule_id="AWS-EC2-001", resource_id="sg-0a1b2c3d4e5f60001").first()
    through = [p for p in g["paths"] if any(n["id"] == "sg-0a1b2c3d4e5f60001" for n in p["nodes"])]
    assert through
    r = admin.post(f"/findings/{sg.id}/autofix")
    assert r.status_code == 302
    assert db.session.get(Finding, sg.id).status == "resolved"
    rem = Remediation.query.filter_by(finding_id=sg.id).first()
    assert rem.status == "verified" and any(s["status"] == "verified" for s in rem.steps)
    g2 = attack_graph.build(demo.id)
    assert not any(any(n["id"] == "sg-0a1b2c3d4e5f60001" for n in p["nodes"]) for p in g2["paths"])
    assert len(g2["paths"]) < len(g["paths"])


def test_autofix_refused_for_live_integrations(admin, demo):
    integ = Integration.query.filter_by(org_id=demo.id, provider="aws", mode="demo").first()
    f = Finding.query.filter_by(integration_id=integ.id, status="open").first()
    integ.mode = "live"
    db.session.commit()
    r = admin.post(f"/findings/{f.id}/autofix", follow_redirects=True)
    assert b"Auto-fix only runs on demo" in r.data
    assert db.session.get(Finding, f.id).status == "open"


def test_fix_scripts_download(admin):
    f = Finding.query.filter_by(rule_id="AWS-S3-001").first()
    sh = admin.get(f"/findings/{f.id}/script.sh")
    assert sh.status_code == 200 and b"put-public-access-block" in sh.data and b"acme-customer-exports" in sh.data
    tf = admin.get(f"/findings/{f.id}/script.tf")
    assert b"aws_s3_bucket_public_access_block" in tf.data


class FakeResp:
    def __init__(self, status, data):
        self.status_code, self._data, self.content = status, data, b"1"

    def json(self):
        return self._data


class FakeGitHub:
    def __init__(self):
        self.calls = []

    def request(self, method, url, headers=None, timeout=None, json=None):
        self.calls.append((method, url.split("/repos/acme/infra")[-1], json))
        if url.endswith("/git/ref/heads/main"):
            return FakeResp(200, {"object": {"sha": "abc123"}})
        if url.endswith("/pulls"):
            return FakeResp(201, {"number": 7, "html_url": "https://github.com/acme/infra/pull/7"})
        return FakeResp(201, {})


def test_github_pr_flow(app, demo):
    from shieldiq.services.remediation import open_github_pr
    org = db.session.get(Organization, demo.id)
    org.github_repo = "acme/infra"
    f = Finding.query.filter_by(rule_id="AWS-RDS-001").first()
    fake = FakeGitHub()
    rem = open_github_pr(f, org, "t@x", token="ghp_test", session=fake)
    assert rem.pr_url == "https://github.com/acme/infra/pull/7"
    assert [c[0] for c in fake.calls] == ["GET", "POST", "PUT", "POST"]
    assert fake.calls[1][2]["sha"] == "abc123"
    assert db.session.get(Finding, f.id).status == "in_progress"


def test_github_pr_requires_settings(admin):
    f = Finding.query.first()
    r = admin.post(f"/findings/{f.id}/pr", follow_redirects=True)
    assert b"Set the remediation repository" in r.data


# ---------------------------------------------------------------- reports & exports
def test_pdf_report(admin, app):
    r = admin.post("/reports/generate", data={"framework": "SOC2"})
    assert r.status_code == 302
    pdf = admin.get("/reports/1/download")
    assert pdf.status_code == 200 and pdf.data[:5] == b"%PDF-" and len(pdf.data) > 5000
    assert admin.post("/reports/1/delete").status_code == 302
    assert admin.get("/reports/1/download").status_code == 404


def test_csv_export_guards_formula_injection(admin, demo):
    f = Finding.query.first()
    f.detail = "=HYPERLINK(\"http://evil\")"
    db.session.commit()
    csv = admin.get("/export/findings.csv").data.decode()
    assert "'=HYPERLINK" in csv
    js = admin.get("/export/findings.json").json
    assert js["findings"] and "compliance" in js


# ---------------------------------------------------------------- settings / team
def test_settings_password_and_tokens(admin):
    r = admin.post("/settings", data={"action": "password", "current": "ShieldIQ@2026", "new": "weak", "confirm": "weak"},
                   follow_redirects=True)
    assert b"New password needs" in r.data
    r = admin.post("/settings", data={"action": "token", "token_name": "ci"})
    token = re.search(rb"siq_[A-Za-z0-9_\-]+", r.data).group().decode()
    from shieldiq.models import ApiToken
    assert ApiToken.query.first().token_hash != token  # only the hash is stored


def test_org_settings_encrypt_secrets(admin, demo):
    admin.post("/settings", data={"action": "org", "org_name": "Acme", "alert_min_severity": "high", "alert_score_drop": "3",
                                  "slack_webhook": "https://hooks.slack.com/services/T000/B000/XXXX",
                                  "github_repo": "acme/infra", "github_token": "ghp_secret"})
    org = db.session.get(Organization, demo.id)
    assert org.github_repo == "acme/infra" and "ghp_secret" not in (org.github_token_enc or "")
    from shieldiq.security import decrypt
    assert decrypt(org.github_token_enc) == "ghp_secret"


def test_team_management(admin):
    r = admin.post("/users", data={"action": "create", "full_name": "New Analyst", "email": "na@acme.dev", "role": "analyst",
                                   "password": "Temp0raryPass"})
    assert r.status_code == 302 and User.query.filter_by(email="na@acme.dev").first().role == "analyst"
    u = User.query.filter_by(email="na@acme.dev").first()
    admin.post("/users", data={"action": "toggle", "user_id": u.id})
    assert db.session.get(User, u.id).is_active_user is False


# ---------------------------------------------------------------- REST API
def _token(admin):
    r = admin.post("/settings", data={"action": "token", "token_name": "api"})
    return re.search(rb"siq_[A-Za-z0-9_\-]+", r.data).group().decode()


def test_api_with_token(admin, app):
    tok = _token(admin)
    c = app.test_client()
    h = {"Authorization": f"Bearer {tok}"}
    s = c.get("/api/v1/summary", headers=h).json
    assert 0 <= s["posture_score"] <= 100 and s["open_findings"] > 0
    fs = c.get("/api/v1/findings?severity=critical", headers=h).json["findings"]
    assert fs and all(f["severity"] == "critical" for f in fs)
    fid = fs[0]["id"]
    detail = c.get(f"/api/v1/findings/{fid}", headers=h).json
    assert detail["analysis"]["steps"]
    assert c.patch(f"/api/v1/findings/{fid}", headers=h, json={"status": "bogus"}).status_code == 400
    assert c.patch(f"/api/v1/findings/{fid}", headers=h, json={"status": "accepted"}).status_code == 400
    assert c.patch(f"/api/v1/findings/{fid}", headers=h, json={"status": "resolved"}).json["finding"]["status"] == "resolved"
    assert c.get("/api/v1/attack-paths", headers=h).json["paths"]
    assert "SOC2" in c.get("/api/v1/compliance", headers=h).json
    assert len(c.get("/api/v1/rules", headers=h).json["rules"]) >= 60
    iac = c.post("/api/v1/scan/iac", headers=h, json={"filename": "x.tf", "content": 'resource "aws_db_instance" "d" {\n  publicly_accessible = true\n}\n'}).json
    assert not iac["passed"] and any(f["rule_id"] == "AWS-RDS-001" for f in iac["findings"])
    sec = c.post("/api/v1/scan/secrets", headers=h, json={"content": "k = 'AKIA" + "ZT4M2N8QW5R7Y6PX'"}).json
    assert not sec["passed"]
    integ = c.get("/api/v1/integrations", headers=h).json["integrations"][0]
    assert c.post(f"/api/v1/integrations/{integ['id']}/scan", headers=h).json["status"] == "completed"
    assert c.get("/api/v1/summary", headers={"Authorization": "Bearer siq_nope"}).status_code == 401


def test_api_viewer_token_cannot_write(viewer, app):
    tok = _token(viewer)
    c = app.test_client()
    f = Finding.query.first()
    r = c.patch(f"/api/v1/findings/{f.id}", headers={"Authorization": f"Bearer {tok}"}, json={"status": "resolved"})
    assert r.status_code == 403


def test_api_session_post_requires_csrf_when_enabled(admin, app):
    app.config["WTF_CSRF_ENABLED"] = True
    r = admin.post("/api/v1/copilot/chat", json={"message": "hi"})
    assert r.status_code == 400
    app.config["WTF_CSRF_ENABLED"] = False


def test_command_palette_search(admin):
    res = admin.get("/api/v1/search?q=bucket").json["results"]
    assert res and all("id" in r for r in res)



# ---------------------------------------------------------------- identity + motion story (round 3)
def test_landing_tells_the_story_with_real_data(client, demo):
    html = client.get("/").data.decode()
    # the attack-path bento card is drawn from the demo's real riskiest path, with its real numbers for the score dial
    assert 'id="estate"' in html and "acme-customer-exports" in html
    m = re.search(r'data-ro-score data-from="(\d+)" data-to="(\d+)"', html)
    assert m and int(m.group(2)) >= int(m.group(1))
    # plain-language explanation of what an attack path is, and Connect -> Scan -> Fix
    assert "attack path</b>: a chain of mistakes" in html
    for step in ("[01] CONNECT", "Connect</strong>", "Scan</strong>", "Prioritise</strong>", "Fix</strong>", "Prove</strong>"):
        assert step in html
    # the mark + wordmark identity is used, and motion runs from a vendored file (no CDN)
    assert 'class="mark' in html and "wordmark" in html and "/static/js/motion.js" in html
    assert "cdn." not in html and "googleapis" not in html
    # honest: a portfolio project, provider logos only as "works with"
    assert "student portfolio project" in html and "Works with" in html


def test_score_if_fixed_matches_formula(app, demo):
    from shieldiq.services.scanner import posture_score as ps
    from shieldiq.views import _score_if_fixed
    with app.app_context():
        user = User.query.filter_by(email="demo@shieldiq.local").first()
        g = attack_graph.build(user.org_id)
        path = next(p for p in g["paths"] if p.get("choke_point"))
        out = _score_if_fixed(user.org_id, path)
        assert out["score_before"] == ps(user.org_id)
        assert out["score_after"] >= out["score_before"] and out["path_findings"] >= 1


def test_shell_and_error_use_identity(client, demo):
    login(client)
    html = client.get("/").data.decode()
    assert 'class="mark' in html and "data-gauge" in html and "app-motion.js" in html
    r = client.get("/no-such-page")
    assert r.status_code == 404 and b"err-art" in r.data



def test_setup_guides_page_lists_all_providers(client, demo):
    r = client.get("/guides")
    assert r.status_code == 200
    html = r.data.decode()
    for label in ("Amazon Web Services", "Google Cloud", "Microsoft Azure", "Kubernetes", "GitHub", "Slack"):
        assert label in html
    # honest about which connections are live and which are snapshot imports
    assert html.count("Live · read-only") >= 2 and "Snapshot import" in html
    assert "SecurityAudit" in html and "gcloud" in html and "az storage account list" in html and "kubectl get" in html
    assert "/static/js/guides.js" in html and "<script>" not in html
    # linked from the landing page and the integrations page
    assert "/guides" in client.get("/welcome").data.decode()
    login(client)
    assert "/guides" in client.get("/integrations").data.decode()
