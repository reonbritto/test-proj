"""CWE data provider with XML dataset parsing.

Downloads and parses the official CWE XML dataset from MITRE
(https://cwe.mitre.org/data/xml/cwec_latest.xml.zip), extracting
weakness definitions including relationships. Falls back to a
built-in reference dataset if the download or parse fails.

Uses defusedxml to prevent XXE attacks (CWE-611) when processing
the XML document.
"""
import os
import zipfile
import logging
import httpx
from typing import List, Optional

import defusedxml.ElementTree as ET

from .models import CWEEntry
from . import cache

logger = logging.getLogger(__name__)

CWE_XML_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
CWE_XML_ZIP_PATH = os.path.join(
    os.path.dirname(__file__), "..", "data", "cwec_latest.xml.zip"
)
CWE_XML_NS = {"cwe": "http://cwe.mitre.org/cwe-6"}
NVD_CWE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Module-level cache for parsed XML data (populated once)
_xml_cwe_data: Optional[List[CWEEntry]] = None

# Built-in CWE reference data for commonly referenced weaknesses.
# Used as fallback if XML download/parse fails.
COMMON_CWES = [
    CWEEntry(id="16", name="Configuration",
             description="Software configuration weakness."),
    CWEEntry(id="20", name="Improper Input Validation",
             description="The product does not validate or "
             "incorrectly validates input."),
    CWEEntry(id="22", name="Path Traversal",
             description="Improper limitation of a pathname "
             "to a restricted directory."),
    CWEEntry(id="59", name="Improper Link Resolution",
             description="Improper link resolution before "
             "file access."),
    CWEEntry(id="77", name="Command Injection",
             description="Improper neutralization of special "
             "elements used in a command."),
    CWEEntry(id="78", name="OS Command Injection",
             description="Improper neutralization of special "
             "elements used in an OS command."),
    CWEEntry(id="79", name="Cross-site Scripting (XSS)",
             description="Improper neutralization of input "
             "during web page generation."),
    CWEEntry(id="89", name="SQL Injection",
             description="Improper neutralization of special "
             "elements used in an SQL command."),
    CWEEntry(id="94", name="Code Injection",
             description="Improper control of generation of "
             "code."),
    CWEEntry(id="119", name="Buffer Overflow",
             description="Improper restriction of operations "
             "within the bounds of a memory buffer."),
    CWEEntry(id="120", name="Classic Buffer Overflow",
             description="The program copies an input buffer "
             "to an output buffer without verifying that the "
             "size of the input buffer is less than the size "
             "of the output buffer."),
    CWEEntry(id="125", name="Out-of-bounds Read",
             description="The software reads data past the "
             "end of the intended buffer."),
    CWEEntry(id="189", name="Numeric Errors",
             description="Weaknesses in numeric computation."),
    CWEEntry(id="190", name="Integer Overflow",
             description="An integer overflow or wraparound "
             "occurs when the result is used to allocate or "
             "determine buffer sizes."),
    CWEEntry(id="200", name="Information Disclosure",
             description="The product exposes sensitive "
             "information to an actor not explicitly "
             "authorised to have access."),
    CWEEntry(id="264", name="Permissions and Privileges",
             description="Weaknesses related to management "
             "of permissions, privileges, access controls."),
    CWEEntry(id="269", name="Improper Privilege Management",
             description="The software does not properly "
             "assign, modify, track, or check privileges."),
    CWEEntry(id="284", name="Improper Access Control",
             description="The software does not restrict or "
             "incorrectly restricts access to a resource."),
    CWEEntry(id="287", name="Improper Authentication",
             description="The software does not prove or "
             "insufficiently proves an actor's identity."),
    CWEEntry(id="310", name="Cryptographic Issues",
             description="Weaknesses related to design and "
             "implementation of cryptographic features."),
    CWEEntry(id="352", name="Cross-Site Request Forgery",
             description="The web application does not "
             "sufficiently verify that a request was "
             "intentionally submitted."),
    CWEEntry(id="362", name="Race Condition",
             description="The program contains a concurrent "
             "code sequence requiring exclusive access to a "
             "shared resource."),
    CWEEntry(id="399", name="Resource Management Errors",
             description="Weaknesses related to improper "
             "management of system resources."),
    CWEEntry(id="400", name="Uncontrolled Resource Consumption",
             description="The software does not properly "
             "control allocation of a resource enabling "
             "denial of service."),
    CWEEntry(id="416", name="Use After Free",
             description="Referencing memory after it has "
             "been freed can cause crash or arbitrary code "
             "execution."),
    CWEEntry(id="426", name="Untrusted Search Path",
             description="The application searches for "
             "critical resources using a search path under "
             "attacker control."),
    CWEEntry(id="434", name="Unrestricted File Upload",
             description="The software allows upload of "
             "dangerous file types without validation."),
    CWEEntry(id="476", name="NULL Pointer Dereference",
             description="A NULL pointer dereference occurs "
             "when the application dereferences a pointer "
             "that it expects to be valid but is NULL."),
    CWEEntry(id="502", name="Deserialization of Untrusted Data",
             description="The application deserializes "
             "untrusted data without sufficiently verifying "
             "that the resulting data will be valid."),
    CWEEntry(id="601", name="Open Redirect",
             description="A web application accepts "
             "user-controlled input that specifies a link "
             "to an external site and redirects to it."),
    CWEEntry(id="611", name="XML External Entity (XXE)",
             description="The software processes an XML "
             "document that can contain XML entities with "
             "URIs that resolve outside the intended sphere "
             "of control."),
    CWEEntry(id="787", name="Out-of-bounds Write",
             description="The software writes data past the "
             "end or before the beginning of the intended "
             "buffer."),
    CWEEntry(id="798", name="Hard-coded Credentials",
             description="The software contains hard-coded "
             "credentials for authentication."),
    CWEEntry(id="862", name="Missing Authorization",
             description="The software does not perform an "
             "authorization check when an actor attempts to "
             "access a resource."),
    CWEEntry(id="863", name="Incorrect Authorization",
             description="The software performs an "
             "authorization check but does not correctly "
             "perform the check."),
    CWEEntry(id="917", name="Expression Language Injection",
             description="The software constructs expression "
             "language statements using externally-influenced "
             "input."),
    CWEEntry(id="918", name="Server-Side Request Forgery",
             description="The web server receives a URL from "
             "an upstream component and retrieves contents "
             "without verifying the destination."),
]


def _download_cwe_xml() -> Optional[str]:
    """Download the CWE XML zip from MITRE and extract the XML file.

    Returns the path to the extracted XML file, or None on failure.
    """
    data_dir = os.path.dirname(CWE_XML_ZIP_PATH)
    os.makedirs(data_dir, exist_ok=True)

    try:
        logger.info("Downloading CWE XML from %s", CWE_XML_URL)
        with httpx.Client(timeout=60.0) as client:
            response = client.get(CWE_XML_URL, follow_redirects=True)
            response.raise_for_status()

        with open(CWE_XML_ZIP_PATH, "wb") as f:
            f.write(response.content)

        with zipfile.ZipFile(CWE_XML_ZIP_PATH, "r") as zf:
            xml_names = [n for n in zf.namelist()
                         if n.endswith(".xml")]
            if not xml_names:
                logger.error("No XML file found in CWE zip")
                return None
            xml_name = xml_names[0]
            zf.extract(xml_name, data_dir)
            return os.path.join(data_dir, xml_name)

    except (httpx.HTTPError, zipfile.BadZipFile, OSError) as exc:
        logger.warning("CWE XML download failed: %s", exc)
        return None


def _parse_cwe_xml(xml_path: str) -> List[CWEEntry]:
    """Parse the CWE XML file using defusedxml (XXE-safe).

    Extracts Weakness elements with their ID, Name, Description,
    and Related_Weaknesses (parent/child/peer relationships).
    """
    tree = ET.parse(xml_path)
    root = tree.getroot()

    weaknesses = root.findall(".//cwe:Weakness", CWE_XML_NS)
    entries = []

    for weakness in weaknesses:
        cwe_id = weakness.get("ID", "")
        name = weakness.get("Name", "")

        desc_elem = weakness.find("cwe:Description", CWE_XML_NS)
        description = ""
        if desc_elem is not None and desc_elem.text:
            description = desc_elem.text.strip()

        # Extract relationship data (ChildOf, ParentOf, PeerOf, etc.)
        related = []
        rel_weaknesses = weakness.find(
            "cwe:Related_Weaknesses", CWE_XML_NS
        )
        if rel_weaknesses is not None:
            for rel in rel_weaknesses.findall(
                "cwe:Related_Weakness", CWE_XML_NS
            ):
                nature = rel.get("Nature", "")
                target_id = rel.get("CWE_ID", "")
                if nature and target_id:
                    related.append({
                        "nature": nature,
                        "cwe_id": target_id
                    })

        if cwe_id and name:
            entries.append(CWEEntry(
                id=cwe_id,
                name=name,
                description=description[:500] if description else "",
                related_weaknesses=related
            ))

    logger.info("Parsed %d CWE entries from XML", len(entries))
    return entries


def load_cwe_data() -> List[CWEEntry]:
    """Load CWE data from XML dataset, falling back to built-in list.

    Attempts to download and parse the official MITRE CWE XML.
    If the XML is already cached locally, parses it directly.
    Falls back to the built-in COMMON_CWES on any failure.
    """
    global _xml_cwe_data

    if _xml_cwe_data is not None:
        return _xml_cwe_data

    # Check for already-downloaded XML
    data_dir = os.path.dirname(CWE_XML_ZIP_PATH)
    existing_xml = None
    if os.path.isdir(data_dir):
        for fname in os.listdir(data_dir):
            if fname.startswith("cwec_") and fname.endswith(".xml"):
                existing_xml = os.path.join(data_dir, fname)
                break

    xml_path = existing_xml or _download_cwe_xml()

    if xml_path and os.path.isfile(xml_path):
        try:
            _xml_cwe_data = _parse_cwe_xml(xml_path)
            if _xml_cwe_data:
                return _xml_cwe_data
        except Exception as exc:
            logger.warning("CWE XML parse failed: %s", exc)

    # Fallback to built-in data
    logger.info("Using built-in CWE reference data (%d entries)",
                len(COMMON_CWES))
    _xml_cwe_data = list(COMMON_CWES)
    return _xml_cwe_data


def get_cwe_data() -> List[CWEEntry]:
    """Return the CWE dataset (from XML or built-in fallback).

    Returns a copy to prevent mutation of the cached data.
    """
    return list(load_cwe_data())


async def fetch_cwe_from_nvd(cwe_id: str) -> Optional[CWEEntry]:
    """Look up a CWE by ID. Checks loaded data first,
    then falls back to NVD API for unknown CWEs.
    """
    # Check loaded CWE data (XML or built-in)
    data = load_cwe_data()
    for cwe in data:
        if cwe.id == cwe_id:
            return cwe

    # Check cache
    cache_key = f"cwe_lookup_{cwe_id}"
    cached = cache.get_cached_search(cache_key)
    if cached:
        return CWEEntry(**cached)

    # Fallback: query NVD for a CVE using this CWE
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                NVD_CWE_URL,
                params={
                    "cweId": f"CWE-{cwe_id}",
                    "resultsPerPage": 1
                },
                timeout=15.0
            )
            if response.status_code == 200:
                entry = CWEEntry(
                    id=cwe_id,
                    name=f"CWE-{cwe_id}",
                    description=(
                        f"Weakness CWE-{cwe_id}. "
                        f"See MITRE CWE for full details."
                    )
                )
                cache.set_cached_search(
                    cache_key, entry.model_dump()
                )
                return entry
    except (httpx.HTTPError, Exception):
        pass

    return None
