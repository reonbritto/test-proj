"""Tests for Microsoft Entra ID authentication — token validation edge cases."""
import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.auth import get_current_user


# Remove the global dependency override for these tests
# so we can test actual auth rejection behaviour.


@pytest.fixture()
def unauth_client():
    """Client WITHOUT the auth override — tests real auth rejection."""
    saved = app.dependency_overrides.copy()
    app.dependency_overrides.pop(get_current_user, None)
    with TestClient(app) as c:
        yield c
    app.dependency_overrides = saved


class TestAuthRejection:
    def test_missing_auth_header_returns_401_or_403(self, unauth_client):
        """Missing auth header returns 403 (HTTPBearer default) or 401."""
        resp = unauth_client.get("/api/cwe")
        assert resp.status_code in (401, 403)

    def test_malformed_bearer_token_returns_401(self, unauth_client):
        resp = unauth_client.get(
            "/api/cwe",
            headers={"Authorization": "Bearer not-a-real-jwt"}
        )
        assert resp.status_code == 401

    def test_empty_bearer_returns_401(self, unauth_client):
        resp = unauth_client.get(
            "/api/cwe",
            headers={"Authorization": "Bearer "}
        )
        # FastAPI's HTTPBearer rejects empty tokens
        assert resp.status_code in (401, 403)


class TestPublicEndpoints:
    def test_health_no_auth_required(self, unauth_client):
        resp = unauth_client.get("/api/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert "cwe_count" in data
        assert "cache" in data

    def test_config_no_auth_required(self, unauth_client):
        resp = unauth_client.get("/api/config")
        assert resp.status_code == 200
        assert "client_id" in resp.json()
