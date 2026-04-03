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

from .models import CWEEntry, Consequence, Mitigation, DetectionMethod
from . import cache

logger = logging.getLogger(__name__)

CWE_XML_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
CWE_XML_ZIP_PATH = os.path.join(
    os.path.dirname(__file__), "..", "data", "cwec_latest.xml.zip"
)
CWE_XML_NS = {"cwe": "http://cwe.mitre.org/cwe-7"}
# Fallback for older XML versions
CWE_XML_NS_V6 = {"cwe": "http://cwe.mitre.org/cwe-6"}
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


def _get_all_text(elem) -> str:
    """Recursively extract all text content from an XML element."""
    parts = []
    if elem.text:
        parts.append(elem.text.strip())
    for child in elem:
        parts.append(_get_all_text(child))
        if child.tail:
            parts.append(child.tail.strip())
    return " ".join(p for p in parts if p)


def _detect_namespace(root) -> dict:
    """Detect the CWE XML namespace from the root element tag."""
    tag = root.tag
    if tag.startswith("{"):
        ns_uri = tag.split("}")[0].lstrip("{")
        return {"cwe": ns_uri}
    return CWE_XML_NS


def _parse_cwe_xml(xml_path: str) -> List[CWEEntry]:
    """Parse the CWE XML file using defusedxml (XXE-safe).

    Extracts Weakness elements with their ID, Name, Description,
    Related_Weaknesses, Common_Consequences, Potential_Mitigations,
    Detection_Methods, Affected_Resources, Taxonomy_Mappings,
    and Applicable_Platforms.
    """
    tree = ET.parse(xml_path)
    root = tree.getroot()
    ns = _detect_namespace(root)

    weaknesses = root.findall(".//cwe:Weakness", ns)
    entries = []

    for weakness in weaknesses:
        cwe_id = weakness.get("ID", "")
        name = weakness.get("Name", "")
        abstraction = weakness.get("Abstraction", "")
        status = weakness.get("Status", "")

        desc_elem = weakness.find("cwe:Description", ns)
        description = ""
        if desc_elem is not None:
            description = _get_all_text(desc_elem)

        # Extended description
        ext_desc_elem = weakness.find(
            "cwe:Extended_Description", ns
        )
        extended_description = ""
        if ext_desc_elem is not None:
            extended_description = _get_all_text(ext_desc_elem)

        # Related weaknesses
        related = []
        rel_weaknesses = weakness.find(
            "cwe:Related_Weaknesses", ns
        )
        if rel_weaknesses is not None:
            for rel in rel_weaknesses.findall(
                "cwe:Related_Weakness", ns
            ):
                nature = rel.get("Nature", "")
                target_id = rel.get("CWE_ID", "")
                if nature and target_id:
                    related.append({
                        "nature": nature,
                        "cwe_id": target_id
                    })

        # Common consequences
        consequences = []
        cons_section = weakness.find(
            "cwe:Common_Consequences", ns
        )
        if cons_section is not None:
            for cons in cons_section.findall(
                "cwe:Consequence", ns
            ):
                scope_elem = cons.find("cwe:Scope", ns)
                impact_elem = cons.find("cwe:Impact", ns)
                likelihood_elem = cons.find("cwe:Likelihood", ns)
                if scope_elem is not None and impact_elem is not None:
                    consequences.append(Consequence(
                        scope=scope_elem.text.strip()
                        if scope_elem.text else "",
                        impact=impact_elem.text.strip()
                        if impact_elem.text else "",
                        likelihood=likelihood_elem.text.strip()
                        if likelihood_elem is not None
                        and likelihood_elem.text else None,
                    ))

        # Potential mitigations
        mitigations = []
        mit_section = weakness.find(
            "cwe:Potential_Mitigations", ns
        )
        if mit_section is not None:
            for mit in mit_section.findall(
                "cwe:Mitigation", ns
            ):
                phase_elem = mit.find("cwe:Phase", ns)
                mit_desc_elem = mit.find("cwe:Description", ns)
                effect_elem = mit.find("cwe:Effectiveness", ns)
                if mit_desc_elem is not None:
                    mitigations.append(Mitigation(
                        phase=phase_elem.text.strip()
                        if phase_elem is not None
                        and phase_elem.text else "General",
                        description=_get_all_text(mit_desc_elem),
                        effectiveness=effect_elem.text.strip()
                        if effect_elem is not None
                        and effect_elem.text else None,
                    ))

        # Detection methods
        detections = []
        det_section = weakness.find(
            "cwe:Detection_Methods", ns
        )
        if det_section is not None:
            for det in det_section.findall(
                "cwe:Detection_Method", ns
            ):
                method_elem = det.find("cwe:Method", ns)
                det_desc_elem = det.find("cwe:Description", ns)
                effect_elem = det.find("cwe:Effectiveness", ns)
                if method_elem is not None and det_desc_elem is not None:
                    detections.append(DetectionMethod(
                        method=method_elem.text.strip()
                        if method_elem.text else "",
                        description=_get_all_text(det_desc_elem),
                        effectiveness=effect_elem.text.strip()
                        if effect_elem is not None
                        and effect_elem.text else None,
                    ))

        # Affected resources
        affected_resources = []
        res_section = weakness.find(
            "cwe:Affected_Resources", ns
        )
        if res_section is not None:
            for res in res_section.findall(
                "cwe:Affected_Resource", ns
            ):
                if res.text:
                    affected_resources.append(res.text.strip())

        # Taxonomy mappings (OWASP, CERT, etc.)
        taxonomy_mappings = []
        tax_section = weakness.find(
            "cwe:Taxonomy_Mappings", ns
        )
        if tax_section is not None:
            for mapping in tax_section.findall(
                "cwe:Taxonomy_Mapping", ns
            ):
                tax_name = mapping.get("Taxonomy_Name", "")
                entry_name_elem = mapping.find(
                    "cwe:Entry_Name", ns
                )
                entry_id_elem = mapping.find(
                    "cwe:Entry_ID", ns
                )
                if tax_name:
                    taxonomy_mappings.append({
                        "taxonomy": tax_name,
                        "entry_id": entry_id_elem.text.strip()
                        if entry_id_elem is not None
                        and entry_id_elem.text else "",
                        "entry_name": entry_name_elem.text.strip()
                        if entry_name_elem is not None
                        and entry_name_elem.text else "",
                    })

        # Applicable platforms (languages, technologies)
        applicable_platforms = []
        plat_section = weakness.find(
            "cwe:Applicable_Platforms", ns
        )
        if plat_section is not None:
            for lang in plat_section.findall(
                "cwe:Language", ns
            ):
                lang_name = lang.get("Name", lang.get("Class", ""))
                if lang_name:
                    applicable_platforms.append({
                        "type": "Language",
                        "name": lang_name,
                        "prevalence": lang.get("Prevalence", ""),
                    })
            for tech in plat_section.findall(
                "cwe:Technology", ns
            ):
                tech_name = tech.get("Name", tech.get("Class", ""))
                if tech_name:
                    applicable_platforms.append({
                        "type": "Technology",
                        "name": tech_name,
                        "prevalence": tech.get("Prevalence", ""),
                    })

        # Related attack patterns (CAPEC IDs)
        related_attack_patterns = []
        rap_section = weakness.find(
            "cwe:Related_Attack_Patterns", ns
        )
        if rap_section is not None:
            for rap in rap_section.findall(
                "cwe:Related_Attack_Pattern", ns
            ):
                capec_id = rap.get("CAPEC_ID", "")
                if capec_id:
                    related_attack_patterns.append(capec_id)

        if cwe_id and name:
            entries.append(CWEEntry(
                id=cwe_id,
                name=name,
                description=description[:500] if description else "",
                abstraction=abstraction or None,
                status=status or None,
                extended_description=(
                    extended_description[:2000]
                    if extended_description else None
                ),
                common_consequences=consequences,
                potential_mitigations=mitigations,
                detection_methods=detections,
                affected_resources=affected_resources,
                taxonomy_mappings=taxonomy_mappings,
                related_weaknesses=related,
                applicable_platforms=applicable_platforms,
                related_attack_patterns=related_attack_patterns,
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
