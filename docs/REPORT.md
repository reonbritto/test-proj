# PureSecure CVE Explorer -- Main Report

---

## 1. System Functionality Summary

### What the System Does

PureSecure CVE Explorer is a web-based security intelligence platform that analyses the global vulnerability landscape by querying the **NIST National Vulnerability Database (NVD) API 2.0** in real time. It collects, processes, and presents CVE (Common Vulnerabilities and Exposures) data to help security professionals, developers, and researchers understand emerging threats and prioritise remediation efforts.

### Security Threat Landscape Analysis

The system performs the following analyses to provide actionable security insights:

**Vulnerability Discovery and Search** -- Users can search the entire NVD database by keyword (e.g., "log4j", "remote code execution"), by CWE classification (e.g., CWE-79 for Cross-Site Scripting), or by CVSS severity level (CRITICAL, HIGH, MEDIUM, LOW). The search engine uses a two-step probe approach: it first queries the NVD to determine the total number of matching results, then fetches the most recently published page, ensuring users always see the newest threats first.

**Severity Scoring and Risk Assessment** -- Each vulnerability is displayed with both CVSS v2.0 and CVSS v3.1 scores, vector strings, and severity classifications. Colour-coded badges provide immediate visual risk identification -- a CRITICAL vulnerability (score 9.0-10.0) is instantly distinguishable from a LOW one (score 0.1-3.9). This enables rapid triage of which vulnerabilities demand urgent attention.

**Weakness Classification Mapping** -- The system maps every CVE to its underlying CWE (Common Weakness Enumeration) category. This allows analysts to identify not just individual vulnerabilities but systemic weakness patterns -- for example, discovering that a software vendor has repeated SQL Injection (CWE-89) issues indicates a fundamental input validation gap in their development practices. The system includes 37 built-in CWE definitions for the most commonly referenced weaknesses, with live NVD API fallback for less common ones.

**Trend Analytics** -- Three analytics engines aggregate cached vulnerability data to reveal patterns in the threat landscape:
- **Severity Distribution** counts how many cached CVEs fall into each severity category, showing whether the current threat environment skews towards critical or lower-risk issues.
- **Top CWEs** ranks weakness categories by frequency, revealing which vulnerability types (e.g., Out-of-bounds Write, Cross-Site Scripting) are most prevalent across the industry.
- **Severity Trends** groups vulnerabilities by year and severity level, enabling analysts to observe whether high-severity vulnerabilities are increasing or decreasing over time.

**Affected Product Identification** -- For each CVE, the system parses CPE (Common Platform Enumeration) data to identify exactly which vendors, products, and versions are affected. This enables organisations to cross-reference their software inventory against known vulnerabilities, supporting asset-based vulnerability management.

**Intelligent Caching for Continuous Monitoring** -- An SQLite caching layer with a 24-hour TTL stores previously fetched vulnerability data locally. This serves a dual purpose: it respects NVD API rate limits (~5 requests per 30 seconds without an API key) while also building a local vulnerability database that powers the analytics engine. As users search and browse, the cached dataset grows, providing increasingly comprehensive trend analysis.

---

## 2. Significant Design Decision for Secure Software

### Defence-in-Depth Input Validation Architecture

The most significant design decision for security is the **multi-layered input validation architecture** implemented across `security.py`, `cache.py`, and `common.js`. Rather than relying on a single validation point, the system enforces security at every boundary where untrusted data enters the application -- a textbook application of the defence-in-depth principle.

#### The Design

The system processes three categories of user input: CVE identifiers (e.g., `CVE-2021-44228`), CWE identifiers (e.g., `79`), and free-text search queries. Each category has its own dedicated validation function in the `security.py` module, following the principle of **allowlisting over denylisting** -- rather than attempting to block known malicious patterns (which attackers can bypass), the validators define exactly what constitutes valid input and reject everything else.

```
User Input --> FastAPI Route --> security.py Validation --> Business Logic --> cache.py (Parameterised SQL) --> SQLite
                                      |                                             |
                                 Reject invalid                              No string interpolation
                                 (HTTP 400)                                  (? placeholders only)
```

**CVE ID validation** uses the strict regex `^CVE-\d{4}-\d{4,}$`, which permits only the exact format defined by the MITRE CVE specification: the literal prefix "CVE-", followed by a four-digit year, a hyphen, and four or more digits. Input is normalised (stripped and uppercased) before validation. Any deviation -- including SQL injection attempts like `CVE-2021-44228' OR '1'='1` -- is rejected with HTTP 400 before reaching any business logic.

**CWE ID validation** uses the regex `^\d+$`, permitting only numeric characters. This is deliberately restrictive: while the application could accept the "CWE-" prefix, stripping it to a pure numeric value at the validation boundary eliminates an entire class of injection vectors.

**Search query sanitisation** applies a 200-character length limit and an allowlist regex `[\w\s\-.,]` that permits only word characters, whitespace, hyphens, dots, and commas. This removes control characters, angle brackets, quotes, semicolons, and other characters commonly used in SQL injection, XSS, and command injection attacks.

#### Why This Design is Significant

This design addresses **OWASP Top 10 A03:2021 (Injection)** -- the third most critical web application security risk. The decision to implement validation as a separate `security.py` module rather than inline within route handlers is architecturally important for three reasons:

1. **Centralisation prevents inconsistency.** Every route that accepts a CVE ID calls `validate_cve_id()`. If validation were implemented inline in each route handler, a developer adding a new endpoint might forget to validate, creating an injection vulnerability. The dedicated module makes validation a conscious, importable dependency that appears explicitly in each route's code.

2. **Testability enables confidence.** The `test_security.py` test suite includes specific test cases for SQL injection payloads (e.g., `CVE-2021-44228'; DROP TABLE--`), XSS payloads, and boundary conditions. Because validation is isolated in its own module, these security properties can be tested independently of the web framework, database, and external API.

3. **Layered defence tolerates individual failures.** Even if a validation function were bypassed (e.g., through a future code change), the cache layer provides a second line of defence: all SQL operations in `cache.py` use parameterised queries with `?` placeholders, never string interpolation. The database layer cannot be compromised by injection even if the validation layer fails. Similarly, the frontend provides a third layer: all user-derived data rendered in the browser passes through `escapeHTML()`, which uses the DOM's `textContent` property for safe encoding -- preventing stored XSS even if malicious data somehow reached the database.

This three-layer approach (input validation, parameterised queries, output encoding) means that no single point of failure can result in an injection vulnerability. Each layer independently prevents a different attack vector, and an attacker would need to bypass all three simultaneously to achieve exploitation.

---

## 3. Significant Implementation Decision for Secure Software

### Parameterised SQL Queries in the Cache Layer

The most significant implementation decision for security is the **exclusive use of parameterised queries** throughout `cache.py`, the module responsible for all SQLite database operations. This implementation directly prevents SQL injection -- the most dangerous and prevalent class of web application vulnerability (OWASP A03:2021).

#### The Implementation

Every database operation in `cache.py` passes user-influenced values through parameterised query placeholders (`?`) rather than string concatenation or f-string interpolation. Consider the core retrieval function:

```python
# cache.py, line 44-46 -- SECURE: parameterised query
cursor = conn.execute(
    "SELECT response_json, fetched_at FROM cve_cache WHERE cve_id = ?",
    (cve_id,)
)
```

The `cve_id` value -- which ultimately originates from user input in the URL path `/api/cve/{cve_id}` -- is passed as a parameter tuple `(cve_id,)`, separate from the SQL statement string. The SQLite driver handles escaping and quoting internally, making it structurally impossible for the value to alter the SQL statement's logic, regardless of what characters it contains.

This pattern is applied consistently across all six database operations in the module:

| Function | Line | SQL Operation | Parameterised |
|----------|------|---------------|---------------|
| `get_cached_cve()` | 44 | `SELECT ... WHERE cve_id = ?` | `(cve_id,)` |
| `set_cached_cve()` | 60 | `INSERT OR REPLACE ... VALUES (?, ?, ?)` | `(cve_id, json, timestamp)` |
| `get_cached_search()` | 78 | `SELECT ... WHERE query_hash = ?` | `(query_hash,)` |
| `set_cached_search()` | 95 | `INSERT OR REPLACE ... VALUES (?, ?, ?)` | `(hash, json, timestamp)` |
| `get_all_cached_cves()` | 111 | `SELECT response_json FROM cve_cache` | No user input |
| `_get_connection()` | 16 | `CREATE TABLE IF NOT EXISTS ...` | Schema only, no user input |

The search cache adds an additional defensive layer: the `_hash_query()` function (line 69-70) converts query parameters into a SHA-256 hash before using them as cache keys. This means that even the search cache lookup operates on a fixed-length hexadecimal string rather than raw user input, further reducing the attack surface.

```python
def _hash_query(query: str) -> str:
    return hashlib.sha256(query.encode()).hexdigest()
```

#### Why This Implementation is Significant

**Preventing real attack scenarios.** The application's test suite (`test_main.py`) includes an explicit SQL injection test case:

```python
def test_get_cve_sql_injection(self):
    response = self.client.get("/api/cve/CVE-2021-44228' OR '1'='1")
    assert response.status_code == 400
```

This test verifies that a classic SQL injection payload is rejected. However, the parameterised query implementation ensures that even if this payload somehow bypassed input validation and reached the database layer, the `?` placeholder would treat the entire string `CVE-2021-44228' OR '1'='1` as a literal value to match against the `cve_id` column -- the injected SQL clause `OR '1'='1'` would never be interpreted as SQL syntax.

**Contrast with the insecure alternative.** If the implementation had used string formatting:

```python
# INSECURE -- NOT used in this codebase
cursor = conn.execute(
    f"SELECT response_json FROM cve_cache WHERE cve_id = '{cve_id}'"
)
```

An attacker providing the input `' UNION SELECT sql FROM sqlite_master--` could extract the database schema, and further payloads could read or modify any data in the cache. The parameterised approach makes this structurally impossible at the database driver level, not merely blocked by application-level filtering.

**Defence in depth with connection management.** The implementation also demonstrates secure resource management: every database function follows a `try/finally` pattern that guarantees connection closure regardless of whether an exception occurs. This prevents connection leaks that could lead to denial-of-service conditions under load, and ensures that database locks are released promptly -- a subtle but important aspect of secure, reliable software.

```python
conn = _get_connection()
try:
    # database operation
finally:
    conn.close()
```

**Alignment with secure coding standards.** This implementation follows OWASP's SQL Injection Prevention Cheat Sheet (Defence Option 1: Prepared Statements with Parameterised Queries), CWE-89 (SQL Injection) mitigation guidance, and Python's `sqlite3` module best practices. The consistency of applying this pattern across every single database operation -- with no exceptions -- demonstrates that secure coding is a systematic practice in this codebase, not an afterthought applied selectively.
