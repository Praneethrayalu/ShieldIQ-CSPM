import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shieldiq import create_app  # noqa: E402
from shieldiq.config import TestConfig  # noqa: E402
from shieldiq.extensions import db  # noqa: E402


@pytest.fixture()
def app(tmp_path):
    app = create_app(TestConfig, INSTANCE_DIR=str(tmp_path), REPORTS_DIR=str(tmp_path / "reports"))
    with app.app_context():
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def demo(app):
    from shieldiq.seed import seed_demo
    return seed_demo(with_fixes=False)


@pytest.fixture()
def client(app):
    return app.test_client()


def login(client, email="demo@shieldiq.local", password="ShieldIQ@2026"):
    return client.post("/login", data={"email": email, "password": password})


@pytest.fixture()
def admin(client, demo):
    login(client)
    return client


@pytest.fixture()
def analyst(client, demo):
    login(client, "analyst@shieldiq.local")
    return client


@pytest.fixture()
def viewer(client, demo):
    login(client, "viewer@shieldiq.local")
    return client
