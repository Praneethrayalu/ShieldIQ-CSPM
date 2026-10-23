"""Regression tests for the 2026-10-31 deep-review fixes."""
from shieldiq.models import ApiToken, Finding, Integration
from shieldiq.services import reports

DEMO = {"email": "demo@shieldiq.local", "password": "ShieldIQ@2026"}


def _bearer_token(admin):
    from shieldiq.extensions import db
    from shieldiq.models import User
    user = User.query.filter_by(email=DEMO["email"]).first()
    _, raw = ApiToken.issue(user, "regression-test")
    db.session.commit()
    return raw


def test_bearer_token_last_used_persists(admin):
    """api.py: token.last_used_at must be committed, not dropped on GET."""
    tok = _bearer_token(admin)
    r = admin.get("/api/v1/summary", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 200
    row = ApiToken.query.filter_by(token_hash=ApiToken.hash(tok)).first()
    assert row is not None and row.last_used_at is not None


def test_next_redirect_rejects_external_urls(admin):
    """views.py: form 'next' must not redirect off-site."""
    f = Finding.query.first()
    assert f is not None
    r = admin.post(f"/findings/{f.id}/status",
                    data={"status": "accepted", "note": "ok", "next": "https://evil.example/phish"})
    assert r.status_code in (302, 303)
    assert "evil.example" not in r.headers["Location"]
    assert r.headers["Location"].startswith("/"), r.headers["Location"]


def test_copilot_message_capped(admin):
    """api.py: copilot input capped server-side at 4000 chars."""
    r = admin.post("/api/v1/copilot/chat", json={"message": "x" * 100_000})
    assert r.status_code == 200  # handled, not rejected or blown up


def test_create_user_long_email_rejected(admin):
    """views.py users: over-long email is rejected, never truncated into someone else's identity."""
    from shieldiq.models import User
    long_email = "a" * 64 + "@" + "b" * 190 + ".com"  # valid shape, 259 chars > 255
    before = User.query.count()
    r = admin.post("/users",
                   data={"action": "create", "email": long_email, "full_name": "Long Name",
                         "role": "viewer", "password": "Password@123"})
    assert r.status_code in (302, 303)
    assert User.query.count() == before
    assert not User.query.filter(User.email.like("aaaa%")).first()


def test_register_long_email_rejected(client):
    """auth.py register: same rule - no silent truncation, no identity collision."""
    from shieldiq.models import User
    long_email = "c" * 64 + "@" + "d" * 190 + ".com"  # 259 chars > 255
    r = client.post("/register",
                    data={"full_name": "Long Name", "email": long_email, "org_name": "Corp",
                          "password": "GoodPassw0rd", "confirm": "GoodPassw0rd"})
    assert r.status_code == 400  # re-rendered with errors, not created
    assert not User.query.filter(User.email.like("cccc%")).first()


def test_finding_fingerprint_unique_constraint():
    """models.py: one finding per (integration, fingerprint)."""
    cols = set()
    for c in Finding.__table__.constraints:
        names = {col.name for col in c.columns}
        if "fingerprint" in names:
            cols |= names
    assert {"integration_id", "fingerprint"} <= cols


def test_rescan_does_not_duplicate_findings(admin):
    """scanner.py: rescanning one integration must not duplicate findings."""
    integ = Integration.query.first()
    assert integ is not None
    before = Finding.query.filter_by(integration_id=integ.id).count()
    admin.post(f"/integrations/{integ.id}/scan", data={"next": "/integrations"})
    admin.post(f"/integrations/{integ.id}/scan", data={"next": "/integrations"})
    after = Finding.query.filter_by(integration_id=integ.id).count()
    assert before == after


def test_client_ip_not_spoofable_by_default(app):
    """security.py: X-Forwarded-For ignored unless TRUST_PROXY_HEADERS is set."""
    from shieldiq.security import client_ip
    with app.test_request_context("/", environ_overrides={"REMOTE_ADDR": "10.0.0.9"},
                                  headers={"X-Forwarded-For": "6.6.6.6"}):
        assert not app.config.get("TRUST_PROXY_HEADERS")
        assert client_ip() == "10.0.0.9"
    app.config["TRUST_PROXY_HEADERS"] = True
    try:
        with app.test_request_context("/", environ_overrides={"REMOTE_ADDR": "10.0.0.9"},
                                      headers={"X-Forwarded-For": "6.6.6.6"}):
            assert client_ip() == "6.6.6.6"
    finally:
        app.config["TRUST_PROXY_HEADERS"] = False


def test_pdf_report_on_brand():
    """reports.py: PDF uses the charcoal + signal-orange brand, not the old indigo palette."""
    assert str(reports.ACCENT.hexval()).lower() == "0xff5a1f"
    assert str(reports.INK.hexval()).lower() == "0x151515"


# ------------------------------------------------ v2.1.2 improvements

def test_login_per_ip_throttle(app, client, demo):
    """Repeated failed logins from one network are throttled (brute-force scenario)."""
    app.config["LOGIN_IP_MAX_ATTEMPTS"] = 3
    bad = {"email": "demo@shieldiq.local", "password": "wrong"}
    assert [client.post("/login", data=bad).status_code for _ in range(3)] == [401, 401, 401]
    assert client.post("/login", data=bad).status_code == 429


def test_register_per_ip_throttle(app, client):
    """Registration is rate-limited per network."""
    app.config["REGISTER_IP_MAX_ATTEMPTS"] = 2
    body = {"full_name": "N A", "org_name": "Corp", "password": "GoodPassw0rd", "confirm": "different"}
    for i in range(2):  # invalid (mismatched confirm) so no session is established
        b = dict(body, email=f"user{i}@example.com")
        assert client.post("/register", data=b).status_code == 400
    assert client.post("/register", data=dict(body, email="user9@example.com")).status_code == 429


def test_concurrent_scan_guard(admin):
    """A scan already in flight refuses a second one instead of racing it."""
    from shieldiq.extensions import db
    from shieldiq.models import ScanRun
    integ = Integration.query.first()
    running = ScanRun(org_id=integ.org_id, integration_id=integ.id, source=integ.provider,
                      status="running", triggered_by="other")
    db.session.add(running)
    db.session.commit()
    r = admin.post(f"/integrations/{integ.id}/scan", data={"next": "/integrations"})
    assert r.status_code in (302, 303)
    runs = ScanRun.query.filter_by(integration_id=integ.id).order_by(ScanRun.id.desc()).all()
    assert runs[0].status == "failed" and "already running" in (runs[0].error or "")


def test_concurrent_scan_guard_ignores_stale_runs(admin):
    """A run stuck in 'running' for >15 min does not block new scans."""
    from datetime import timedelta
    from shieldiq.extensions import db
    from shieldiq.models import ScanRun, utcnow
    integ = Integration.query.first()
    stale = ScanRun(org_id=integ.org_id, integration_id=integ.id, source=integ.provider,
                    status="running", triggered_by="old")
    db.session.add(stale)
    db.session.flush()
    stale.started_at = utcnow() - timedelta(minutes=20)
    db.session.commit()
    r = admin.post(f"/integrations/{integ.id}/scan", data={"next": "/integrations"})
    assert r.status_code in (302, 303)
    latest = ScanRun.query.filter_by(integration_id=integ.id).order_by(ScanRun.id.desc()).first()
    assert latest.status == "completed"
    from shieldiq.extensions import db as _db2
    _db2.session.expire_all()
    assert _db2.session.get(ScanRun, stale.id).status == "failed"  # interrupted leftover was closed first


# ------------------------------------------------ migration (backup-first, narrow)

import datetime as _dt
import re as _re
import sqlite3 as _sqlite3

import pytest as _pytest
from sqlalchemy.dialects import sqlite as _sqlite_dialect
from sqlalchemy.schema import CreateIndex as _CreateIndex
from sqlalchemy.schema import CreateTable as _CreateTable

from shieldiq.extensions import db as _db
from shieldiq.services.migrate import MigrationError as _MigrationError
from shieldiq.services.migrate import migrate_sqlite as _migrate


def _build_schema(db_file, finding_constraint=True, running_index=True, finding_nullable_hack=False):
    """Create every model table in db_file, optionally at the v2.1.0 shape."""
    con = _sqlite3.connect(str(db_file))
    for t in _db.metadata.tables.values():
        ddl = str(_CreateTable(t).compile(dialect=_sqlite_dialect.dialect()))
        if t.name == "finding":
            if not finding_constraint:
                ddl = _re.sub(r",\s*CONSTRAINT uq_finding_fingerprint UNIQUE \(integration_id, fingerprint\)",
                              "", ddl, flags=_re.IGNORECASE)
            if finding_nullable_hack:
                ddl = ddl.replace("provider VARCHAR(20) NOT NULL", "provider VARCHAR(20)")
        con.execute(ddl)
    for t in _db.metadata.tables.values():
        for ix in t.indexes:
            if ix.name == "uq_scanrun_running" and not running_index:
                continue
            con.execute(str(_CreateIndex(ix).compile(dialect=_sqlite_dialect.dialect())))
    con.commit()
    return con


def _row(table, **over):
    row = {}
    for c in _db.metadata.tables[table].columns:
        if c.name == "id" or c.nullable or c.default is not None:
            row[c.name] = None
        elif str(c.type).startswith(("VARCHAR", "TEXT")):
            row[c.name] = "x"
        elif str(c.type).startswith(("INTEGER", "BOOLEAN")):
            row[c.name] = 1
        elif str(c.type).startswith("DATETIME"):
            row[c.name] = _dt.datetime(2026, 1, 1)
        else:
            row[c.name] = None
    row.update(over)
    return row


def _finding_row(org=1, integ=7, fp="fp-1"):
    return _row("finding", org_id=org, integration_id=integ, fingerprint=fp, status="open")


def _insert(con, table, row):
    cols = list(row)
    con.execute(f"INSERT INTO {table} ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})",
                [row[c] for c in cols])


def test_migrate_success_children_backup_and_index(tmp_path):
    """v2.1.0-shaped DB: backup written, duplicates collapse to oldest, child rows re-pointed, index added."""
    db_file = tmp_path / "old.db"
    con = _build_schema(db_file, finding_constraint=False, running_index=False)
    _insert(con, "organization", _row("organization", name="Acme"))
    _insert(con, "integration", _row("integration", org_id=1, provider="aws", name="aws prod", mode="demo"))
    integ_id = con.execute("SELECT id FROM integration").fetchone()[0]  # 1 (autoincrement)
    for _ in range(3):  # ids 1,2,3: same integration + fingerprint -> keep 1
        _insert(con, "finding", _finding_row(integ=integ_id))
    _insert(con, "finding", _finding_row(integ=integ_id, fp="fp-2"))  # id 4: distinct, kept
    _insert(con, "finding", _finding_row(integ=None, fp="fp-1"))  # id 5: NULL integration, always kept
    _insert(con, "alert", {"id": 1, "org_id": 1, "kind": "new_finding", "title": "t", "finding_id": 3})
    _insert(con, "remediation", {"id": 1, "org_id": 1, "finding_id": 2, "mode": "demo_apply", "status": "verified"})
    _insert(con, "scan_run", {"id": 1, "org_id": 1, "integration_id": integ_id, "source": "aws",
                              "status": "running", "started_at": _dt.datetime(2026, 1, 1)})
    con.commit()
    con.close()

    res = _migrate(db_file, _db.metadata, echo=lambda *a: None)

    assert res["deduped"] == 2
    con = _sqlite3.connect(str(db_file))
    assert con.execute("SELECT COUNT(*) FROM finding").fetchone()[0] == 3  # ids 1, 4, 5
    assert con.execute("SELECT finding_id FROM alert WHERE id = 1").fetchone()[0] == 1
    assert con.execute("SELECT finding_id FROM remediation WHERE id = 1").fetchone()[0] == 1
    assert con.execute("SELECT status FROM scan_run WHERE id = 1").fetchone()[0] == "failed"  # interrupted run closed
    idx = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='index'")}
    assert "uq_scanrun_running" in idx and "uq_finding_fingerprint" not in idx  # constraint lives in table DDL
    tbl = con.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='finding'").fetchone()[0]
    assert "UNIQUE" in tbl.upper()
    assert con.execute("PRAGMA foreign_key_check").fetchall() == []
    con.close()
    bak = _sqlite3.connect(res["backup"])
    assert bak.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    assert bak.execute("SELECT COUNT(*) FROM finding").fetchone()[0] == 5  # backup kept the pre-migration rows
    bak.close()


def test_migrate_refuses_unknown_columns(tmp_path):
    """A schema this migrator does not know is refused untouched - no backup, no changes."""
    db_file = tmp_path / "weird.db"
    con = _build_schema(db_file, finding_constraint=False, running_index=True)
    con.execute("ALTER TABLE finding ADD COLUMN mystery TEXT")
    _insert(con, "finding", _finding_row())
    con.commit()
    con.close()
    with _pytest.raises(_MigrationError, match="fresh separate folder"):
        _migrate(db_file, _db.metadata, echo=lambda *a: None)
    con = _sqlite3.connect(str(db_file))
    assert con.execute("SELECT COUNT(*) FROM finding").fetchone()[0] == 1
    assert not list(tmp_path.glob("*.bak-*"))
    con.close()


def test_migrate_rolls_back_on_bad_data(tmp_path):
    """If the rebuild fails mid-transaction, the original table is left exactly as it was."""
    db_file = tmp_path / "bad.db"
    con = _build_schema(db_file, finding_constraint=False, running_index=True, finding_nullable_hack=True)
    row = _finding_row()
    row["provider"] = None  # violates NOT NULL in the real model
    _insert(con, "finding", row)
    con.commit()
    con.close()
    with _pytest.raises(Exception):
        _migrate(db_file, _db.metadata, echo=lambda *a: None)
    con = _sqlite3.connect(str(db_file))
    assert con.execute("SELECT COUNT(*) FROM finding").fetchone()[0] == 1  # original row intact
    assert con.execute("SELECT name FROM sqlite_master WHERE name='_migrate_finding'").fetchone() is None
    con.close()


def test_migrate_refuses_locked_database(tmp_path):
    """An open writer makes the migration fail fast and change nothing."""
    db_file = tmp_path / "locked.db"
    con = _build_schema(db_file, finding_constraint=False, running_index=True)
    con.commit()
    writer = _sqlite3.connect(str(db_file), isolation_level=None)
    writer.execute("BEGIN IMMEDIATE")
    try:
        with _pytest.raises(_MigrationError, match="locked"):
            _migrate(db_file, _db.metadata, echo=lambda *a: None)
    finally:
        writer.execute("ROLLBACK")
        writer.close()
    check = _sqlite3.connect(str(db_file))
    assert "UNIQUE" not in check.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='finding'").fetchone()[0].upper()
    check.close()


def test_migrate_idempotent_on_current_schema(tmp_path):
    db_file = tmp_path / "new.db"
    con = _build_schema(db_file)
    con.close()
    res = _migrate(db_file, _db.metadata, echo=lambda *a: None)
    assert res["changed"] == [] and res["backup"] is None


def test_scanrun_running_unique_at_db_level(admin):
    """The concurrent-scan guard is a real database constraint, not just an application check."""
    from sqlalchemy.exc import IntegrityError
    from shieldiq.extensions import db
    from shieldiq.models import ScanRun
    integ = Integration.query.first()
    db.session.add(ScanRun(org_id=integ.org_id, integration_id=integ.id, source="aws", status="running"))
    db.session.commit()
    db.session.add(ScanRun(org_id=integ.org_id, integration_id=integ.id, source="aws", status="running"))
    with _pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()
    # different status or different integration is fine
    db.session.add(ScanRun(org_id=integ.org_id, integration_id=integ.id, source="aws", status="failed"))
    db.session.commit()
