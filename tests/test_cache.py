"""Tests for SQLite cache layer — storage, retrieval, TTL, and SQL safety."""
import os
import tempfile
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from app.cache import (
    _hash_query,
    _is_expired,
    cleanup_expired,
    get_all_cached_cves,
    get_cache_stats,
    get_cached_cve,
    get_cached_search,
    set_cached_cve,
    set_cached_search,
)


# Use a temporary database for all cache tests
@patch("app.cache.DB_PATH", os.path.join(
    tempfile.mkdtemp(), "test_cache.db"
))
class TestCveCache:
    def test_set_and_get_cve(self):
        cve_data = {"cve_id": "CVE-2021-44228", "desc": "Log4j"}
        set_cached_cve("CVE-2021-44228", cve_data)
        result = get_cached_cve("CVE-2021-44228")
        assert result is not None
        assert result["cve_id"] == "CVE-2021-44228"

    def test_get_missing_cve_returns_none(self):
        result = get_cached_cve("CVE-9999-00000")
        assert result is None

    def test_cve_cache_overwrites_on_duplicate(self):
        set_cached_cve("CVE-2021-44228", {"version": 1})
        set_cached_cve("CVE-2021-44228", {"version": 2})
        result = get_cached_cve("CVE-2021-44228")
        assert result["version"] == 2

    def test_get_all_cached_cves(self):
        set_cached_cve("CVE-2024-00001", {"id": "one"})
        set_cached_cve("CVE-2024-00002", {"id": "two"})
        all_cves = get_all_cached_cves()
        assert isinstance(all_cves, list)
        assert len(all_cves) >= 2


@patch("app.cache.DB_PATH", os.path.join(
    tempfile.mkdtemp(), "test_search_cache.db"
))
class TestSearchCache:
    def test_set_and_get_search(self):
        data = {"results": [1, 2, 3]}
        set_cached_search("query=injection", data)
        result = get_cached_search("query=injection")
        assert result is not None
        assert result["results"] == [1, 2, 3]

    def test_get_missing_search_returns_none(self):
        result = get_cached_search("nonexistent-query-params")
        assert result is None

    def test_different_queries_have_different_hashes(self):
        h1 = _hash_query("query=injection")
        h2 = _hash_query("query=overflow")
        assert h1 != h2

    def test_hash_is_deterministic(self):
        h1 = _hash_query("test-query")
        h2 = _hash_query("test-query")
        assert h1 == h2


class TestTTLExpiry:
    def test_not_expired_within_ttl(self):
        recent = datetime.now(timezone.utc).isoformat()
        assert _is_expired(recent) is False

    def test_expired_beyond_ttl(self):
        old = (
            datetime.now(timezone.utc) - timedelta(hours=25)
        ).isoformat()
        assert _is_expired(old) is True

    def test_naive_timestamp_handled(self):
        naive = (
            datetime.now(timezone.utc) - timedelta(hours=1)
        ).strftime("%Y-%m-%dT%H:%M:%S")
        assert _is_expired(naive) is False


@patch("app.cache.DB_PATH", os.path.join(
    tempfile.mkdtemp(), "test_cleanup.db"
))
class TestCleanup:
    def test_cleanup_removes_expired_entries(self):
        set_cached_cve("CVE-2020-00001", {"old": True})
        # Manually age the entry
        from app.cache import _get_connection
        old_time = (
            datetime.now(timezone.utc) - timedelta(hours=48)
        ).isoformat()
        conn = _get_connection()
        conn.execute(
            "UPDATE cve_cache SET fetched_at = ? WHERE cve_id = ?",
            (old_time, "CVE-2020-00001")
        )
        conn.commit()
        conn.close()

        removed = cleanup_expired()
        assert removed >= 1
        assert get_cached_cve("CVE-2020-00001") is None


@patch("app.cache.DB_PATH", os.path.join(
    tempfile.mkdtemp(), "test_stats.db"
))
class TestCacheStats:
    def test_stats_returns_counts(self):
        set_cached_cve("CVE-2024-10001", {"test": True})
        stats = get_cache_stats()
        assert "cve_entries" in stats
        assert "search_entries" in stats
        assert "db_size_bytes" in stats
        assert stats["cve_entries"] >= 1


@patch("app.cache.DB_PATH", os.path.join(
    tempfile.mkdtemp(), "test_sqli.db"
))
class TestSQLInjectionSafety:
    def test_cve_id_with_sql_injection_payload(self):
        """Parameterised queries prevent SQL injection in CVE lookups."""
        malicious_id = "' OR '1'='1'; DROP TABLE cve_cache;--"
        result = get_cached_cve(malicious_id)
        assert result is None  # No crash, no data leak

    def test_search_with_sql_injection_payload(self):
        """Parameterised queries prevent SQL injection in search lookups."""
        malicious_query = "'; DROP TABLE search_cache;--"
        result = get_cached_search(malicious_query)
        assert result is None  # No crash, no data leak

    def test_set_cve_with_special_chars(self):
        """Cache can store and retrieve data with special characters."""
        special_data = {
            "desc": "Test with 'quotes' and \"doubles\" and ;semicolons"
        }
        set_cached_cve("CVE-2024-99999", special_data)
        result = get_cached_cve("CVE-2024-99999")
        assert result is not None
        assert "quotes" in result["desc"]
