"""Tests for input validation and sanitization."""
import pytest
from fastapi import HTTPException
from backend.security import validate_cve_id, validate_cwe_id, sanitize_search_query


class TestValidateCveId:
    def test_valid_cve_id(self):
        assert validate_cve_id("CVE-2021-44228") == "CVE-2021-44228"

    def test_valid_cve_id_lowercase(self):
        assert validate_cve_id("cve-2021-44228") == "CVE-2021-44228"

    def test_valid_cve_id_with_spaces(self):
        assert validate_cve_id("  CVE-2021-44228  ") == "CVE-2021-44228"

    def test_valid_cve_id_five_digits(self):
        assert validate_cve_id("CVE-2023-12345") == "CVE-2023-12345"

    def test_invalid_cve_id_sql_injection(self):
        with pytest.raises(HTTPException) as exc:
            validate_cve_id("'; DROP TABLE cves;--")
        assert exc.value.status_code == 400

    def test_invalid_cve_id_empty(self):
        with pytest.raises(HTTPException):
            validate_cve_id("")

    def test_invalid_cve_id_wrong_format(self):
        with pytest.raises(HTTPException):
            validate_cve_id("CWE-79")

    def test_invalid_cve_id_short_number(self):
        with pytest.raises(HTTPException):
            validate_cve_id("CVE-2021-123")


class TestValidateCweId:
    def test_valid_cwe_id(self):
        assert validate_cwe_id("79") == "79"

    def test_valid_cwe_id_with_spaces(self):
        assert validate_cwe_id("  89  ") == "89"

    def test_invalid_cwe_id_letters(self):
        with pytest.raises(HTTPException):
            validate_cwe_id("abc")

    def test_invalid_cwe_id_injection(self):
        with pytest.raises(HTTPException):
            validate_cwe_id("79; DROP TABLE")

    def test_invalid_cwe_id_with_prefix(self):
        with pytest.raises(HTTPException):
            validate_cwe_id("CWE-79")


class TestSanitizeSearchQuery:
    def test_normal_query(self):
        assert sanitize_search_query("log4j") == "log4j"

    def test_query_with_spaces(self):
        assert sanitize_search_query("  apache log4j  ") == "apache log4j"

    def test_query_length_limit(self):
        long_query = "a" * 300
        result = sanitize_search_query(long_query)
        assert len(result) == 200

    def test_empty_query(self):
        assert sanitize_search_query("") == ""

    def test_strips_special_chars(self):
        result = sanitize_search_query("test<script>alert(1)</script>")
        assert "<" not in result
        assert ">" not in result

    def test_strips_sql_chars(self):
        result = sanitize_search_query("test'; DROP TABLE--")
        assert "'" not in result
        assert ";" not in result

    def test_allows_hyphens_and_dots(self):
        result = sanitize_search_query("log4j-2.17.0")
        assert result == "log4j-2.17.0"

    def test_whitespace_only_returns_empty(self):
        result = sanitize_search_query("   ")
        assert result == ""


class TestValidationEdgeCases:
    def test_cve_id_with_xss_payload(self):
        with pytest.raises(HTTPException) as exc:
            validate_cve_id('<img src=x onerror="alert(1)">')
        assert exc.value.status_code == 400

    def test_cve_id_with_newlines(self):
        with pytest.raises(HTTPException):
            validate_cve_id("CVE-2021-44228\n; DROP TABLE")

    def test_cwe_id_zero(self):
        """CWE ID 0 is not valid in the CWE catalogue."""
        with pytest.raises(HTTPException) as exc:
            validate_cwe_id("0")
        assert exc.value.status_code == 400

    def test_cwe_id_negative(self):
        with pytest.raises(HTTPException):
            validate_cwe_id("-1")

    def test_cve_id_unicode_bypass(self):
        with pytest.raises(HTTPException):
            validate_cve_id("CVE\u200b-2021-44228")  # zero-width space
