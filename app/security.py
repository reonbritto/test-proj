"""Input validation and sanitization utilities."""
import re
from fastapi import HTTPException

# CVE IDs: CVE-YYYY-NNNNN (4-digit year, 4+ digit sequence)
CVE_ID_PATTERN = re.compile(r'^CVE-\d{4}-\d{4,}$')

# CWE IDs: 1–5 numeric digits only (current MITRE catalogue tops out ~1400)
CWE_ID_PATTERN = re.compile(r'^\d{1,5}$')

MAX_QUERY_LENGTH = 200
MAX_CWE_ID_VALUE = 99999  # upper bound; real CWEs are < 2000


def validate_cve_id(cve_id: str) -> str:
    """Validate CVE ID format (e.g., CVE-2021-44228).

    Strips whitespace, uppercases, then enforces the standard
    CVE-YYYY-NNNNN pattern.  Raises HTTP 400 on any mismatch.
    """
    if not cve_id:
        raise HTTPException(
            status_code=400,
            detail="CVE ID must not be empty."
        )
    cve_id = cve_id.strip().upper()
    if not CVE_ID_PATTERN.match(cve_id):
        raise HTTPException(
            status_code=400,
            detail="Invalid CVE ID format. Expected: CVE-YYYY-NNNNN"
        )
    return cve_id


def validate_cwe_id(cwe_id: str) -> str:
    """Validate CWE ID format (numeric only, e.g., '79').

    Accepts 1–5 digit strings representing a positive integer.
    Raises HTTP 400 for non-numeric input, out-of-range values,
    or zero (CWE-0 does not exist).
    """
    if not cwe_id:
        raise HTTPException(
            status_code=400,
            detail="CWE ID must not be empty."
        )
    cwe_id = cwe_id.strip()
    if not CWE_ID_PATTERN.match(cwe_id):
        raise HTTPException(
            status_code=400,
            detail="Invalid CWE ID format. Expected numeric ID (e.g., 79)."
        )
    if int(cwe_id) == 0:
        raise HTTPException(
            status_code=400,
            detail="CWE ID must be a positive integer."
        )
    return cwe_id


def sanitize_search_query(query: str) -> str:
    """Sanitize and truncate a free-text search query.

    - Strips leading/trailing whitespace
    - Truncates to MAX_QUERY_LENGTH characters
    - Removes characters outside alphanumerics (ASCII), spaces,
      hyphens, dots, and commas — prevents shell/SQL meta-character
      injection while still allowing meaningful search terms
    """
    if not query:
        return ""
    query = query.strip()
    if len(query) > MAX_QUERY_LENGTH:
        query = query[:MAX_QUERY_LENGTH]
    # ASCII flag ensures \w matches only [a-zA-Z0-9_], not Unicode
    query = re.sub(r'[^\w\s\-.,]', '', query, flags=re.ASCII)
    return query
