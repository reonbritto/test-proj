"""Tests for NVD API client — parsing, caching, error handling."""
from urllib.parse import urlparse
from app.nvd_client import parse_nvd_cve


# Realistic NVD API response fragment
SAMPLE_NVD_VULN = {
    "cve": {
        "id": "CVE-2021-44228",
        "descriptions": [
            {"lang": "en", "value": "Apache Log4j2 RCE via JNDI."}
        ],
        "metrics": {
            "cvssMetricV31": [{
                "cvssData": {
                    "baseScore": 10.0,
                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                    "baseSeverity": "CRITICAL"
                }
            }],
            "cvssMetricV2": [{
                "cvssData": {
                    "baseScore": 9.3,
                    "vectorString": "AV:N/AC:M/Au:N/C:C/I:C/A:C"
                }
            }]
        },
        "weaknesses": [
            {"description": [{"value": "CWE-917"}]}
        ],
        "configurations": [
            {"nodes": [{"cpeMatch": [
                {"vulnerable": True,
                 "criteria": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"}
            ]}]}
        ],
        "references": [
            {"url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
             "source": "nvd", "tags": ["Third Party Advisory"]}
        ],
        "published": "2021-12-10T10:15:09.143",
        "lastModified": "2023-04-03T20:15:07.553"
    }
}


class TestParseNvdCve:
    def test_parses_cve_id(self):
        result = parse_nvd_cve(SAMPLE_NVD_VULN)
        assert result.cve_id == "CVE-2021-44228"

    def test_parses_description(self):
        result = parse_nvd_cve(SAMPLE_NVD_VULN)
        assert "Log4j2" in result.description

    def test_parses_cvss_v3(self):
        result = parse_nvd_cve(SAMPLE_NVD_VULN)
        assert result.cvss.v3_score == 10.0
        assert result.cvss.v3_severity == "CRITICAL"
        assert "CVSS:3.1" in result.cvss.v3_vector

    def test_parses_cvss_v2(self):
        result = parse_nvd_cve(SAMPLE_NVD_VULN)
        assert result.cvss.v2_score == 9.3

    def test_parses_cwe_ids(self):
        result = parse_nvd_cve(SAMPLE_NVD_VULN)
        assert "CWE-917" in result.cwe_ids

    def test_parses_affected_products(self):
        result = parse_nvd_cve(SAMPLE_NVD_VULN)
        assert len(result.affected_products) >= 1
        assert result.affected_products[0].vendor == "apache"
        assert result.affected_products[0].product == "log4j"

    def test_parses_references(self):
        result = parse_nvd_cve(SAMPLE_NVD_VULN)
        assert len(result.references) == 1
        parsed = urlparse(result.references[0].url)
        assert parsed.hostname == "nvd.nist.gov"

    def test_parses_dates(self):
        result = parse_nvd_cve(SAMPLE_NVD_VULN)
        assert result.published.startswith("2021-12-10")
        assert result.modified.startswith("2023-04-03")

    def test_handles_missing_metrics(self):
        vuln = {"cve": {
            "id": "CVE-2024-00001",
            "descriptions": [{"lang": "en", "value": "Test"}],
            "metrics": {},
            "weaknesses": [],
            "configurations": [],
            "references": [],
            "published": "2024-01-01T00:00:00",
            "lastModified": "2024-01-01T00:00:00"
        }}
        result = parse_nvd_cve(vuln)
        assert result.cvss.v3_score is None
        assert result.cvss.v2_score is None

    def test_handles_empty_descriptions(self):
        vuln = {"cve": {
            "id": "CVE-2024-00002",
            "descriptions": [],
            "metrics": {},
            "weaknesses": [],
            "configurations": [],
            "references": [],
            "published": "2024-01-01T00:00:00",
            "lastModified": "2024-01-01T00:00:00"
        }}
        result = parse_nvd_cve(vuln)
        assert result.description == ""

    def test_v30_fallback_when_v31_missing(self):
        vuln = {"cve": {
            "id": "CVE-2024-00003",
            "descriptions": [{"lang": "en", "value": "Test"}],
            "metrics": {
                "cvssMetricV30": [{
                    "cvssData": {
                        "baseScore": 7.5,
                        "vectorString": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        "baseSeverity": "HIGH"
                    }
                }]
            },
            "weaknesses": [],
            "configurations": [],
            "references": [],
            "published": "2024-01-01T00:00:00",
            "lastModified": "2024-01-01T00:00:00"
        }}
        result = parse_nvd_cve(vuln)
        assert result.cvss.v3_score == 7.5
        assert result.cvss.v3_severity == "HIGH"
