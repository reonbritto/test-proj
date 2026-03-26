"""Tests for FastAPI application endpoints."""
import pytest
from unittest.mock import patch, AsyncMock
from fastapi.testclient import TestClient
from app.main import app
from app.auth import get_current_user
from app.models import CVEDetail, CVSSScores


# Override auth dependency for all tests — return a fake user
MOCK_USER = {"sub": "test-user", "name": "Test User"}


async def _mock_user():
    return MOCK_USER


app.dependency_overrides[get_current_user] = _mock_user


@pytest.fixture(scope="module")
def client():
    """Create test client that triggers startup events."""
    with TestClient(app) as c:
        yield c


MOCK_CVE = CVEDetail(
    cve_id="CVE-2021-44228",
    description="Apache Log4j2 RCE vulnerability",
    cvss=CVSSScores(
        v3_score=10.0,
        v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        v3_severity="CRITICAL",
        v2_score=9.3,
        v2_vector="AV:N/AC:M/Au:N/C:C/I:C/A:C"
    ),
    cwe_ids=["CWE-917"],
    references=[],
    affected_products=[],
    published="2021-12-10T10:15:09.143",
    modified="2023-04-03T20:15:07.553"
)


class TestCVEEndpoint:
    @patch("app.main.get_cve", new_callable=AsyncMock,
           return_value=MOCK_CVE)
    def test_get_cve_success(self, mock_get, client):
        response = client.get("/api/cve/CVE-2021-44228")
        assert response.status_code == 200
        data = response.json()
        assert data["cve_id"] == "CVE-2021-44228"
        assert data["cvss"]["v3_score"] == 10.0

    @patch("app.main.get_cve", new_callable=AsyncMock,
           return_value=None)
    def test_get_cve_not_found(self, mock_get, client):
        response = client.get("/api/cve/CVE-9999-99999")
        assert response.status_code == 404

    def test_get_cve_invalid_format(self, client):
        response = client.get("/api/cve/invalid-id")
        assert response.status_code == 400


class TestCWEEndpoints:
    def test_search_cwes_no_query(self, client):
        response = client.get("/api/cwe")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) > 0

    def test_search_cwes_by_keyword(self, client):
        response = client.get("/api/cwe?query=injection")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)

    def test_cwe_suggestions(self, client):
        response = client.get("/api/cwe/suggestions?q=injection")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) > 0

    def test_cwe_suggestions_by_id(self, client):
        response = client.get("/api/cwe/suggestions?q=79")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert any("CWE-79" in item.get("text", "")
                   for item in data)

    def test_get_cwe_invalid_id(self, client):
        response = client.get("/api/cwe/abc")
        assert response.status_code == 400


class TestAnalyticsEndpoints:
    def test_top_cwes(self, client):
        response = client.get("/api/analytics/top-cwes")
        assert response.status_code == 200
        assert isinstance(response.json(), list)

    def test_cwe_risk_scores(self, client):
        response = client.get("/api/analytics/cwe-risk")
        assert response.status_code == 200
        assert isinstance(response.json(), list)


class TestPublicEndpoints:
    def test_config_endpoint(self, client):
        response = client.get("/api/config")
        assert response.status_code == 200
        data = response.json()
        assert "client_id" in data
        assert "tenant_id" in data
