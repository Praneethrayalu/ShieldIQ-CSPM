import click

from .extensions import db


def register_cli(app):
    @app.cli.command("seed-demo")
    def seed_demo_cmd():
        """Create the demo organization (demo@shieldiq.local)."""
        from .seed import seed_demo
        org = seed_demo()
        click.echo("Demo data created." if org else "Demo data already exists.")

    @app.cli.command("reset-db")
    @click.confirmation_option(prompt="This deletes ALL ShieldIQ data. Continue?")
    def reset_db():
        db.drop_all()
        db.create_all()
        click.echo("Database reset.")

    @app.cli.command("migrate-db")
    def migrate_db_cmd():
        """Upgrade an existing local SQLite database to the current schema (backup written first)."""
        from .services.migrate import MigrationError, migrate_sqlite, sqlite_path_from_uri
        try:
            path = sqlite_path_from_uri(app.config["SQLALCHEMY_DATABASE_URI"])
            migrate_sqlite(path, db.metadata, echo=click.echo)
        except MigrationError as exc:
            raise click.ClickException(str(exc))

    @app.cli.command("scan-all")
    def scan_all_cmd():
        """Re-scan every integration of every organization (use from cron / Task Scheduler)."""
        from .models import Organization
        from .services.scanner import scan_all
        for org in Organization.query.all():
            runs = scan_all(org.id, "cli")
            click.echo(f"{org.name}: {len(runs)} scans, score {runs[-1].posture_score if runs else '-'}")
