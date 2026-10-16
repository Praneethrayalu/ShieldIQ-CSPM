"""Backup-first SQLite schema migration.

`db.create_all()` only creates missing tables; it never changes an existing one. When a model gains a
constraint or column (v2.1.0 -> v2.1.1 added the findings uniqueness rule; v2.1.2 added the "one running
scan per source" index), an existing database file keeps the old shape.

This module is deliberately narrow. It knows exactly one table rebuild - `finding` gaining its
uniqueness rule - plus adding missing indexes. It REFUSES anything else (unknown columns, other stale
tables) and tells you to run the new version from a fresh folder instead. It never drops data it does
not understand.

Safety properties:
- the backup is made with SQLite's online backup API, so it is consistent even in WAL mode;
- the rebuild runs inside one BEGIN IMMEDIATE transaction: it fails fast (and changes nothing) if
  another process is writing to the database - stop the app before migrating;
- when duplicate findings collapse to their oldest copy, every table with a foreign key to finding.id
  (alerts, remediations) is re-pointed at the kept row, so no child rows are orphaned;
- a full integrity + foreign-key check runs before commit; any failure rolls everything back.

Usage:  flask --app run migrate-db     (stop the app first)
"""
import sqlite3
from datetime import datetime
from pathlib import Path

from sqlalchemy.dialects import sqlite as sqlite_dialect
from sqlalchemy.schema import CreateIndex, CreateTable


class MigrationError(Exception):
    pass


def sqlite_path_from_uri(uri):
    if not uri.startswith("sqlite:///"):
        raise MigrationError(
            "Automatic migration only supports the default local SQLite file. For Postgres/MySQL, "
            "back up the database yourself and apply the schema change with your usual tooling.")
    return Path(uri[len("sqlite:///"):].split("?")[0])


def _ddl(stmt):
    return str(stmt.compile(dialect=sqlite_dialect.dialect())).strip()


def _live_columns(con, table):
    return {r[1] for r in con.execute(f"PRAGMA table_info({table})")}


def _live_index_names(con):
    return {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='index'")}


def _finding_children(metadata):
    """(table, column) pairs with a foreign key to finding.id."""
    refs = []
    for t in metadata.tables.values():
        for c in t.columns:
            for fk in c.foreign_keys:
                if fk.column.table.name == "finding" and fk.column.name == "id":
                    refs.append((t.name, c.name))
    return refs


def _backup(src_path, dst_path):
    """Consistent online backup (safe under WAL / concurrent readers)."""
    src = sqlite3.connect(str(src_path))
    try:
        dst = sqlite3.connect(str(dst_path))
        try:
            src.backup(dst)
        finally:
            dst.close()
    finally:
        src.close()


def migrate_sqlite(db_path, metadata, echo=print):
    """Upgrade a SQLite database file in place, backup first. Returns a summary dict."""
    db_path = Path(db_path)
    if not db_path.exists():
        raise MigrationError(f"No database at {db_path} - nothing to migrate (the app creates a fresh one).")

    finding = metadata.tables["finding"]
    model_cols = {c.name for c in finding.columns}

    probe = sqlite3.connect(str(db_path))
    try:
        live_finding_cols = _live_columns(probe, "finding") if probe.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='finding'").fetchone() else None
        live_indexes = _live_index_names(probe)
        finding_has_unique = any(
            "unique" in (r[0] or "").lower() and "fingerprint" in (r[0] or "").lower()
            for r in probe.execute("SELECT sql FROM sqlite_master WHERE type IN ('table','index') AND sql IS NOT NULL"))
    finally:
        probe.close()

    if live_finding_cols is None:
        raise MigrationError("This database has no findings table at all - run the app once instead; "
                             "it creates a fresh schema.")
    if live_finding_cols != model_cols:
        extra = sorted(live_finding_cols - model_cols)
        missing = sorted(model_cols - live_finding_cols)
        raise MigrationError(
            "The findings table in this database does not match any version this migrator knows "
            f"(unexpected columns: {extra or '-'}; missing columns: {missing or '-'}). It will NOT be "
            "touched. Run this version from a fresh separate folder instead, and keep this database as-is.")

    want_indexes = {ix.name: ix for t in metadata.tables.values() for ix in t.indexes}
    missing_indexes = [ix for name, ix in want_indexes.items() if name not in live_indexes]
    rebuild_finding = not finding_has_unique

    if not rebuild_finding and not missing_indexes:
        echo("Database already matches the current models - nothing to do.")
        return {"changed": [], "backup": None, "deduped": 0}

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup = db_path.with_name(f"{db_path.name}.bak-{stamp}")
    _backup(db_path, backup)
    echo(f"Backup written: {backup} (consistent online copy - restore by renaming it over the database)")

    con = sqlite3.connect(str(db_path), timeout=1.0, isolation_level=None)
    deduped = 0
    try:
        try:
            con.execute("BEGIN IMMEDIATE")  # fails fast if another process holds the write lock
        except sqlite3.OperationalError:
            raise MigrationError(
                "The database is locked by another process. Stop ShieldIQ (and anything else using the "
                "file), then run the migration again. Nothing was changed; the backup above is a spare copy.")
        try:
            con.execute("PRAGMA foreign_keys=OFF")
            if rebuild_finding:
                cols = ", ".join('"%s"' % c.name for c in finding.columns)
                tmp = "_migrate_finding"
                con.execute(f"DROP TABLE IF EXISTS {tmp}")
                con.execute(_ddl(CreateTable(finding)).replace("CREATE TABLE finding", f"CREATE TABLE {tmp}", 1))
                # Rows with NULL integration_id are distinct under the constraint (NULL != NULL in
                # SQLite), so only de-duplicate rows with a real integration id.
                keep = ("SELECT MIN(id) FROM finding WHERE integration_id IS NOT NULL "
                        "GROUP BY integration_id, fingerprint "
                        "UNION SELECT id FROM finding WHERE integration_id IS NULL")
                before = con.execute("SELECT COUNT(*) FROM finding").fetchone()[0]
                dropped_ids = [r[0] for r in con.execute(f"SELECT id FROM finding WHERE id NOT IN ({keep})")]
                # Re-point every FK child of a dropped duplicate at the kept (oldest) copy first.
                for t_name, c_name in _finding_children(metadata):
                    for dup in dropped_ids:
                        kept = con.execute(
                            "SELECT MIN(id) FROM finding WHERE integration_id = (SELECT integration_id FROM finding WHERE id = ?) "
                            "AND fingerprint = (SELECT fingerprint FROM finding WHERE id = ?)", (dup, dup)).fetchone()[0]
                        con.execute(f"UPDATE {t_name} SET {c_name} = ? WHERE {c_name} = ?", (kept, dup))
                con.execute(f"INSERT INTO {tmp} ({cols}) SELECT {cols} FROM finding WHERE id IN ({keep})")
                after = con.execute(f"SELECT COUNT(*) FROM {tmp}").fetchone()[0]
                deduped = before - after
                con.execute("DROP TABLE finding")
                con.execute(f"ALTER TABLE {tmp} RENAME TO finding")
            # Indexes are additive and non-destructive. A brand-new scan cannot be 'running' while the
            # app is stopped, so any existing 'running' rows are interrupted runs: close them before
            # adding the one-running-scan-per-source index.
            if "uq_scanrun_running" in {ix.name for ix in missing_indexes}:
                con.execute("UPDATE scan_run SET status = 'failed', "
                            "error = COALESCE(error, '') || ' [interrupted: marked failed during schema migration]', "
                            "finished_at = COALESCE(finished_at, CURRENT_TIMESTAMP) WHERE status = 'running'")
            for ix in missing_indexes:
                con.execute(_ddl(CreateIndex(ix)))
            ok = con.execute("PRAGMA integrity_check").fetchone()[0]
            if ok != "ok":
                raise MigrationError(f"integrity_check failed after migration ({ok}); rolled back. Restore the backup.")
            fk_bad = con.execute("PRAGMA foreign_key_check").fetchall()
            if fk_bad:
                raise MigrationError(f"foreign_key_check found {len(fk_bad)} problem row(s); rolled back. Restore the backup.")
            con.execute("COMMIT")
        except Exception:
            con.execute("ROLLBACK")
            raise
    finally:
        con.close()

    changed = (["finding"] if rebuild_finding else []) + [ix.name for ix in missing_indexes]
    echo(f"Migrated: {', '.join(changed)}"
         + (f"; collapsed {deduped} duplicate finding(s) (their alerts and remediations now point at the kept copy)" if deduped else ""))
    echo("Original data preserved in the .bak file if anything looks wrong.")
    return {"changed": changed, "backup": str(backup), "deduped": deduped}
