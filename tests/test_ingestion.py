"""
tests/test_ingestion.py
------------------------
Unit tests for the ingestion service.

Tests use in-memory SQLite and mock external HTTP calls so no
network access is required.
"""

from __future__ import annotations

import pytest
from unittest.mock import patch, MagicMock

from app import create_app, db
from app.models.ioc import IOC
from app.services.ingestion import (
    fetch_urlhaus,
    fetch_threatfox,
    ingest_iocs,
    _normalize_ioc,
)
from app.models.ioc import IOCType


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


# ---------------------------------------------------------------------------
# _normalize_ioc
# ---------------------------------------------------------------------------

class TestNormalizeIOC:
    def test_strips_whitespace(self):
        result = _normalize_ioc("  192.168.1.1  ", IOCType.IP, "test")
        assert result["value"] == "192.168.1.1"

    def test_truncates_long_value(self):
        long_value = "x" * 3000
        result = _normalize_ioc(long_value, IOCType.URL, "test")
        assert len(result["value"]) == 2048

    def test_source_preserved(self):
        result = _normalize_ioc("example.com", IOCType.DOMAIN, "urlhaus")
        assert result["source"] == "urlhaus"

    def test_type_preserved(self):
        result = _normalize_ioc("example.com", IOCType.DOMAIN, "urlhaus")
        assert result["type"] == IOCType.DOMAIN


# ---------------------------------------------------------------------------
# fetch_urlhaus (mocked)
# ---------------------------------------------------------------------------

class TestFetchURLhaus:
    MOCK_RESPONSE = {
        "urls": [
            {"url": "http://malicious.ru/payload.exe", "date_added": "2026-01-01 12:00:00"},
            {"url": "http://evil.xyz/drop.ps1", "date_added": "2026-01-02 08:00:00"},
            {"url": None},  # should be skipped
        ]
    }

    @patch("app.services.ingestion.requests.post")
    def test_returns_list_of_iocs(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.json.return_value = self.MOCK_RESPONSE
        mock_resp.raise_for_status = MagicMock()
        mock_post.return_value = mock_resp

        result = fetch_urlhaus(limit=10)
        assert len(result) == 2
        assert result[0]["type"] == IOCType.URL
        assert result[0]["source"] == "urlhaus"

    @patch("app.services.ingestion.requests.post", side_effect=Exception("timeout"))
    def test_returns_empty_on_error(self, mock_post):
        result = fetch_urlhaus()
        assert result == []


# ---------------------------------------------------------------------------
# fetch_threatfox (mocked)
# ---------------------------------------------------------------------------

class TestFetchThreatFox:
    MOCK_RESPONSE = {
        "query_status": "ok",
        "data": [
            {"ioc": "192.0.2.1:4444", "ioc_type": "ip:port", "first_seen": "2026-01-01 00:00:00"},
            {"ioc": "evil.example.com", "ioc_type": "domain", "first_seen": "2026-01-01 00:00:00"},
        ],
    }

    @patch("app.services.ingestion.requests.post")
    def test_strips_port_from_ip(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.json.return_value = self.MOCK_RESPONSE
        mock_resp.raise_for_status = MagicMock()
        mock_post.return_value = mock_resp

        result = fetch_threatfox(days=1)
        ip_ioc = next(r for r in result if r["type"] == IOCType.IP)
        assert ip_ioc["value"] == "192.0.2.1"

    @patch("app.services.ingestion.requests.post")
    def test_bad_status_returns_empty(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"query_status": "no_results"}
        mock_resp.raise_for_status = MagicMock()
        mock_post.return_value = mock_resp

        result = fetch_threatfox(days=1)
        assert result == []


# ---------------------------------------------------------------------------
# ingest_iocs (uses real in-memory DB)
# ---------------------------------------------------------------------------

class TestIngestIOCs:
    def test_inserts_new_iocs(self, app):
        with app.app_context():
            iocs = [
                _normalize_ioc("10.0.0.1", IOCType.IP, "test"),
                _normalize_ioc("example.com", IOCType.DOMAIN, "test"),
            ]
            inserted, dupes = ingest_iocs(iocs)
            assert inserted == 2
            assert dupes == 0
            assert IOC.query.count() == 2

    def test_deduplicates_same_value_type(self, app):
        with app.app_context():
            ioc = _normalize_ioc("10.0.0.2", IOCType.IP, "test")
            ingest_iocs([ioc])
            inserted, dupes = ingest_iocs([ioc])  # second time
            assert inserted == 0
            assert dupes == 1
            assert IOC.query.count() == 1

    def test_same_value_different_type_both_inserted(self, app):
        with app.app_context():
            ip = _normalize_ioc("10.0.0.3", IOCType.IP, "test")
            domain = _normalize_ioc("10.0.0.3", IOCType.DOMAIN, "test")
            inserted, dupes = ingest_iocs([ip, domain])
            assert inserted == 2
            assert IOC.query.count() == 2
