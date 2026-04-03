"""Tests for CWE data provider."""
import os
import tempfile
from unittest.mock import patch
from backend.cwe_parser import get_cwe_data, COMMON_CWES, _parse_cwe_xml


def test_get_cwe_data_returns_list():
    """get_cwe_data should return a list of CWE entries."""
    result = get_cwe_data()
    assert isinstance(result, list)
    assert len(result) > 0


def test_get_cwe_data_contains_common_cwes():
    """Should include well-known CWEs like XSS and SQLi."""
    result = get_cwe_data()
    ids = [r.id for r in result]
    assert "79" in ids  # XSS
    assert "89" in ids  # SQL Injection
    assert "787" in ids  # Out-of-bounds Write


def test_cwe_entries_have_required_fields():
    """Each CWE entry should have id, name, description."""
    for cwe in COMMON_CWES:
        assert cwe.id
        assert cwe.name
        assert cwe.description


def test_get_cwe_data_returns_copy():
    """Should return a copy, not the original list."""
    data1 = get_cwe_data()
    data2 = get_cwe_data()
    assert data1 is not data2


def test_xss_entry_details():
    """Verify XSS entry has correct name."""
    result = get_cwe_data()
    xss = next(r for r in result if r.id == "79")
    assert "XSS" in xss.name or "Scripting" in xss.name


def test_parse_cwe_xml_extracts_weaknesses():
    """Test that _parse_cwe_xml correctly parses CWE XML format."""
    xml_content = """<?xml version="1.0" encoding="UTF-8"?>
<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-6"
                  Name="Test" Version="4.14">
  <Weaknesses>
    <Weakness ID="79" Name="Cross-site Scripting"
              Abstraction="Base" Status="Stable">
      <Description>The product does not neutralize user input.</Description>
      <Related_Weaknesses>
        <Related_Weakness Nature="ChildOf" CWE_ID="74" View_ID="1000"/>
      </Related_Weaknesses>
    </Weakness>
    <Weakness ID="89" Name="SQL Injection"
              Abstraction="Base" Status="Stable">
      <Description>Improper neutralization of SQL elements.</Description>
    </Weakness>
  </Weaknesses>
</Weakness_Catalog>"""

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".xml", delete=False, encoding="utf-8"
    ) as f:
        f.write(xml_content)
        xml_path = f.name

    try:
        entries = _parse_cwe_xml(xml_path)
        assert len(entries) == 2

        xss = next(e for e in entries if e.id == "79")
        assert xss.name == "Cross-site Scripting"
        assert "neutralize" in xss.description
        assert len(xss.related_weaknesses) == 1
        assert xss.related_weaknesses[0]["nature"] == "ChildOf"
        assert xss.related_weaknesses[0]["cwe_id"] == "74"

        sqli = next(e for e in entries if e.id == "89")
        assert sqli.name == "SQL Injection"
        assert sqli.related_weaknesses == []
    finally:
        os.unlink(xml_path)


def test_load_cwe_data_falls_back_on_failure():
    """When XML download fails, should fall back to COMMON_CWES."""
    import backend.cwe_parser as parser
    original = parser._xml_cwe_data
    parser._xml_cwe_data = None  # Reset cache

    try:
        with patch.object(parser, '_download_cwe_xml', return_value=None):
            # Remove any existing XML files for this test
            with patch('os.path.isdir', return_value=False):
                result = parser.load_cwe_data()
                assert len(result) == len(COMMON_CWES)
                ids = [r.id for r in result]
                assert "79" in ids
                assert "89" in ids
    finally:
        parser._xml_cwe_data = original


def test_cwe_entry_related_weaknesses_default():
    """CWE entries from built-in data should have empty related_weaknesses."""
    for cwe in COMMON_CWES:
        assert cwe.related_weaknesses == []
