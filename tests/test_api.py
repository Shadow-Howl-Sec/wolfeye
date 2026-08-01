"""
tests/test_api.py
------------------
API smoke tests — exercises all major endpoints to ensure correct
status codes, response structure, and auth enforcement.
"""

from __future__ import annotations

import pytest
import json

from app import create_app, db
from app.models.ioc import IOC, IOCType, IOCStatus
from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.models.user import User


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def app():
    application = create_app("testing")
    with application.app_context():
        db.create_all()
        yield application
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def seeded_db(app):
    """Insert a minimal set of records for testing."""
    with app.app_context():
        ioc = IOC(value="1.2.3.4", type=IOCType.IP, source="test", anomaly_score=0.85)
        db.session.add(ioc)
        db.session.flush()

        alert = Alert(
            ioc_id=ioc.id,
            anomaly_score=0.85,
            severity=AlertSeverity.HIGH,
            status=AlertStatus.OPEN,
        )
        db.session.add(alert)
        db.session.commit()
        return {"ioc_id": ioc.id, "alert_id": alert.id}


@pytest.fixture
def admin_session(client, app):
    """Return a test client with an active admin session."""
    with app.app_context():
        admin = User.query.filter_by(username="admin").first()
        if not admin:
            admin = User(username="admin", role="admin")
            admin.set_password("testpass")
            db.session.add(admin)
            db.session.commit()

    resp = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": app.config.get("ADMIN_PASSWORD", "change-me-admin-password")},
    )
    assert resp.status_code == 200
    return client


# ---------------------------------------------------------------------------
# Auth endpoints
# ---------------------------------------------------------------------------

class TestAuth:
    def test_login_success(self, client, app):
        resp = client.post(
            "/api/auth/login",
            json={
                "username": app.config["DEMO_USERNAME"],
                "password": app.config["DEMO_PASSWORD"],
            },
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert "user" in data
        assert data["user"]["role"] == "readonly"

    def test_login_wrong_password(self, client):
        resp = client.post(
            "/api/auth/login",
            json={"username": "demo", "password": "wrongpassword"},
        )
        assert resp.status_code == 401

    def test_login_missing_fields(self, client):
        resp = client.post("/api/auth/login", json={})
        assert resp.status_code == 400

    def test_logout(self, client, app):
        client.post(
            "/api/auth/login",
            json={
                "username": app.config["DEMO_USERNAME"],
                "password": app.config["DEMO_PASSWORD"],
            },
        )
        resp = client.post("/api/auth/logout")
        assert resp.status_code == 200

    def test_me_unauthenticated(self, client):
        resp = client.get("/api/auth/me")
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# IOC endpoints
# ---------------------------------------------------------------------------

class TestIOCs:
    def test_list_iocs_empty(self, client):
        resp = client.get("/api/iocs")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "data" in data
        assert "meta" in data

    def test_list_iocs_with_records(self, client, seeded_db):
        resp = client.get("/api/iocs")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["meta"]["total"] >= 1

    def test_get_ioc_detail(self, client, seeded_db):
        ioc_id = seeded_db["ioc_id"]
        resp = client.get(f"/api/iocs/{ioc_id}")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["value"] == "1.2.3.4"

    def test_get_ioc_not_found(self, client):
        resp = client.get("/api/iocs/99999")
        assert resp.status_code == 404

    def test_filter_by_type(self, client, seeded_db):
        resp = client.get("/api/iocs?type=ip")
        assert resp.status_code == 200

    def test_search_q(self, client, seeded_db):
        resp = client.get("/api/iocs?q=1.2.3")
        assert resp.status_code == 200
        data = resp.get_json()
        assert any("1.2.3.4" in item["value"] for item in data["data"])

    def test_investigate_requires_auth(self, client, seeded_db):
        ioc_id = seeded_db["ioc_id"]
        resp = client.post(f"/api/iocs/{ioc_id}/investigate")
        assert resp.status_code == 401

    def test_investigate_as_admin(self, admin_session, seeded_db):
        ioc_id = seeded_db["ioc_id"]
        resp = admin_session.post(f"/api/iocs/{ioc_id}/investigate")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ioc"]["status"] == "investigated"

    def test_watchlist_add_as_admin(self, admin_session, seeded_db):
        ioc_id = seeded_db["ioc_id"]
        resp = admin_session.post(f"/api/iocs/{ioc_id}/watchlist")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ioc"]["watchlisted"] is True

    def test_export_csv(self, client, seeded_db):
        resp = client.get("/api/iocs/export?fmt=csv")
        assert resp.status_code == 200
        assert "text/csv" in resp.content_type

    def test_export_json(self, client, seeded_db):
        resp = client.get("/api/iocs/export?fmt=json")
        assert resp.status_code == 200
        assert resp.content_type.startswith("application/json")


# ---------------------------------------------------------------------------
# Alert endpoints
# ---------------------------------------------------------------------------

class TestAlerts:
    def test_list_alerts(self, client, seeded_db):
        resp = client.get("/api/alerts")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["meta"]["total"] >= 1

    def test_filter_by_severity(self, client, seeded_db):
        resp = client.get("/api/alerts?severity=high")
        assert resp.status_code == 200

    def test_get_alert_detail(self, client, seeded_db):
        alert_id = seeded_db["alert_id"]
        resp = client.get(f"/api/alerts/{alert_id}")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["severity"] == "high"

    def test_resolve_requires_admin(self, client, seeded_db):
        alert_id = seeded_db["alert_id"]
        resp = client.post(f"/api/alerts/{alert_id}/resolve")
        assert resp.status_code == 401

    def test_resolve_as_admin(self, admin_session, seeded_db):
        alert_id = seeded_db["alert_id"]
        resp = admin_session.post(
            f"/api/alerts/{alert_id}/resolve",
            json={"notes": "Confirmed false positive"},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["alert"]["status"] == "resolved"


# ---------------------------------------------------------------------------
# Stats endpoints
# ---------------------------------------------------------------------------

class TestStats:
    def test_summary(self, client, seeded_db):
        resp = client.get("/api/stats/summary")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "total_iocs" in data

    def test_trends(self, client):
        resp = client.get("/api/stats/trends?days=7")
        assert resp.status_code == 200
        assert isinstance(resp.get_json(), list)

    def test_severity_mix(self, client, seeded_db):
        resp = client.get("/api/stats/severity-mix")
        assert resp.status_code == 200

    def test_ioc_type_mix(self, client, seeded_db):
        resp = client.get("/api/stats/ioc-type-mix")
        assert resp.status_code == 200

    def test_top_sources(self, client):
        resp = client.get("/api/stats/top-sources")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# System endpoints
# ---------------------------------------------------------------------------

class TestSystem:
    def test_ping(self, client):
        resp = client.get("/api/system/ping")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "ok"

    def test_health(self, client):
        resp = client.get("/api/system/health")
        assert resp.status_code in (200, 503)
        data = resp.get_json()
        assert "database" in data
        assert "scheduler" in data
