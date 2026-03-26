"""Tests for analytics engine — top CWEs, risk scoring, edge cases."""
from app.analytics import top_cwes, cwe_risk_scores
from app.models import CWEEntry


# Mock CWE dictionary (simulates cwe_parser output)
CWE_DICT = {
    "79": CWEEntry(id="79", name="Cross-site Scripting",
                   description="XSS"),
    "89": CWEEntry(id="89", name="SQL Injection",
                   description="SQLi"),
    "787": CWEEntry(id="787", name="Out-of-bounds Write",
                    description="OOB"),
}

# Sample cached CVE data (simulates cache.get_all_cached_cves output)
SAMPLE_CVES = [
    {"cve_id": "CVE-2021-00001", "cwe_ids": ["CWE-79"],
     "cvss": {"v3_score": 6.1}},
    {"cve_id": "CVE-2021-00002", "cwe_ids": ["CWE-79"],
     "cvss": {"v3_score": 7.5}},
    {"cve_id": "CVE-2021-00003", "cwe_ids": ["CWE-89"],
     "cvss": {"v3_score": 9.8}},
    {"cve_id": "CVE-2021-00004", "cwe_ids": ["CWE-787"],
     "cvss": {"v3_score": 8.8}},
    {"cve_id": "CVE-2021-00005", "cwe_ids": ["CWE-79", "CWE-89"],
     "cvss": {"v3_score": 5.4}},
]


class TestTopCwes:
    def test_returns_correct_count(self):
        result = top_cwes(SAMPLE_CVES, CWE_DICT, limit=10)
        assert len(result) == 3  # CWE-79, CWE-89, CWE-787

    def test_most_frequent_first(self):
        result = top_cwes(SAMPLE_CVES, CWE_DICT, limit=10)
        assert result[0].cwe_id == "CWE-79"
        assert result[0].cve_count == 3  # appears in 3 CVEs

    def test_resolves_cwe_names(self):
        result = top_cwes(SAMPLE_CVES, CWE_DICT, limit=10)
        xss = next(r for r in result if r.cwe_id == "CWE-79")
        assert xss.cwe_name == "Cross-site Scripting"

    def test_limit_restricts_output(self):
        result = top_cwes(SAMPLE_CVES, CWE_DICT, limit=2)
        assert len(result) == 2

    def test_empty_cves_returns_empty(self):
        result = top_cwes([], CWE_DICT, limit=10)
        assert result == []

    def test_unknown_cwe_uses_id_as_name(self):
        cves = [{"cve_id": "CVE-2024-00001",
                 "cwe_ids": ["CWE-999"], "cvss": {}}]
        result = top_cwes(cves, CWE_DICT, limit=10)
        assert result[0].cwe_name == "CWE-999"


class TestCweRiskScores:
    def test_returns_risk_scores(self):
        result = cwe_risk_scores(SAMPLE_CVES, CWE_DICT, limit=10)
        assert len(result) > 0
        for r in result:
            assert r.risk_score >= 0
            assert r.risk_score <= 100

    def test_sorted_by_risk_descending(self):
        result = cwe_risk_scores(SAMPLE_CVES, CWE_DICT, limit=10)
        for i in range(len(result) - 1):
            assert result[i].risk_score >= result[i + 1].risk_score

    def test_avg_cvss_calculated(self):
        result = cwe_risk_scores(SAMPLE_CVES, CWE_DICT, limit=10)
        sqli = next(r for r in result if r.cwe_id == "CWE-89")
        # CWE-89 has scores 9.8 and 5.4 → avg 7.6
        assert sqli.avg_cvss == 7.6

    def test_empty_cves_returns_empty(self):
        result = cwe_risk_scores([], CWE_DICT, limit=10)
        assert result == []

    def test_cves_without_scores(self):
        cves = [{"cve_id": "CVE-2024-00001",
                 "cwe_ids": ["CWE-79"], "cvss": {}}]
        result = cwe_risk_scores(cves, CWE_DICT, limit=10)
        assert len(result) == 1
        assert result[0].avg_cvss == 0.0

    def test_limit_restricts_output(self):
        result = cwe_risk_scores(SAMPLE_CVES, CWE_DICT, limit=1)
        assert len(result) == 1
