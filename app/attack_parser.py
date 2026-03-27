"""MITRE ATT&CK data provider with STIX JSON parsing.

Downloads and parses the ATT&CK Enterprise STIX 2.1 bundle and
the CAPEC STIX bundle from MITRE's GitHub repository. The CAPEC
bundle provides the authoritative CAPEC→ATT&CK technique mappings
(the ATT&CK bundle only has these on revoked techniques).
"""
import os
import json
import logging
import re
import httpx
from typing import Dict, List, Optional

from .models import AttackTactic, AttackTechnique

logger = logging.getLogger(__name__)

ATTACK_STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)
CAPEC_STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "capec/2.1/stix-capec.json"
)
DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
ATTACK_JSON_PATH = os.path.join(DATA_DIR, "enterprise-attack.json")
CAPEC_JSON_PATH = os.path.join(DATA_DIR, "stix-capec.json")

# Module-level cache (populated once at startup)
_tactic_dict: Optional[Dict[str, AttackTactic]] = None
_technique_dict: Optional[Dict[str, AttackTechnique]] = None
_capec_to_techniques: Optional[Dict[str, List[AttackTechnique]]] = None


def _download_json(url: str, path: str) -> Optional[str]:
    """Download a JSON file from a URL and save it locally."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    try:
        logger.info("Downloading %s", url)
        with httpx.Client(timeout=120.0) as client:
            response = client.get(url, follow_redirects=True)
            response.raise_for_status()
        with open(path, "wb") as f:
            f.write(response.content)
        logger.info("Saved to %s (%d bytes)", path, len(response.content))
        return path
    except (httpx.HTTPError, OSError) as exc:
        logger.warning("Download failed for %s: %s", url, exc)
        return None


def _parse_attack_stix(json_path: str) -> tuple:
    """Parse the ATT&CK Enterprise STIX bundle.

    Returns (tactic_dict, technique_dict, shortname_to_tactic).
    """
    with open(json_path, "r", encoding="utf-8") as f:
        bundle = json.load(f)

    objects = bundle.get("objects", [])

    # Phase 1: Extract tactics
    tactics: Dict[str, AttackTactic] = {}
    shortname_to_tactic: Dict[str, str] = {}

    for obj in objects:
        if obj.get("type") != "x-mitre-tactic":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        ext_refs = obj.get("external_references", [])
        attack_id = ""
        url = ""
        for ref in ext_refs:
            if ref.get("source_name") == "mitre-attack":
                attack_id = ref.get("external_id", "")
                url = ref.get("url", "")
                break

        if not attack_id:
            continue

        shortname = obj.get("x_mitre_shortname", "")
        tactic = AttackTactic(
            id=attack_id,
            name=obj.get("name", ""),
            shortname=shortname,
            description=obj.get("description", "")[:500],
            url=url,
        )
        tactics[attack_id] = tactic
        if shortname:
            shortname_to_tactic[shortname] = attack_id

    # Phase 2: Extract techniques
    techniques: Dict[str, AttackTechnique] = {}

    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        ext_refs = obj.get("external_references", [])
        attack_id = ""
        url = ""
        for ref in ext_refs:
            if ref.get("source_name") == "mitre-attack":
                attack_id = ref.get("external_id", "")
                url = ref.get("url", "")
                break

        if not attack_id:
            continue

        tactic_ids = []
        for phase in obj.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") == "mitre-attack":
                phase_name = phase.get("phase_name", "")
                tactic_id = shortname_to_tactic.get(phase_name)
                if tactic_id:
                    tactic_ids.append(tactic_id)

        is_sub = obj.get("x_mitre_is_subtechnique", False)
        parent_id = None
        if is_sub and "." in attack_id:
            parent_id = attack_id.rsplit(".", 1)[0]

        technique = AttackTechnique(
            id=attack_id,
            name=obj.get("name", ""),
            description=obj.get("description", "")[:500],
            tactics=tactic_ids,
            is_subtechnique=is_sub,
            parent_id=parent_id,
            url=url,
        )
        techniques[attack_id] = technique

    logger.info(
        "Parsed ATT&CK: %d tactics, %d techniques",
        len(tactics), len(techniques),
    )
    return tactics, techniques


def _parse_capec_stix(
    json_path: str,
    techniques: Dict[str, AttackTechnique],
) -> Dict[str, List[AttackTechnique]]:
    """Parse the CAPEC STIX bundle to build CAPEC→ATT&CK mappings.

    CAPEC attack-pattern objects have external_references with
    source_name="ATTACK" pointing to ATT&CK technique IDs.
    """
    with open(json_path, "r", encoding="utf-8") as f:
        bundle = json.load(f)

    capec_map: Dict[str, List[AttackTechnique]] = {}

    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue

        refs = obj.get("external_references", [])
        capec_id = ""
        attack_ids = []

        for ref in refs:
            source = ref.get("source_name", "")
            if source == "capec":
                ext_id = ref.get("external_id", "")
                match = re.match(r"CAPEC-(\d+)", ext_id)
                if match:
                    capec_id = match.group(1)
            elif source == "ATTACK":
                attack_ids.append(ref.get("external_id", ""))

        if not capec_id or not attack_ids:
            continue

        mapped = []
        for aid in attack_ids:
            tech = techniques.get(aid)
            if tech:
                mapped.append(tech)
                # Also add CAPEC ID to technique's capec_ids
                if capec_id not in tech.capec_ids:
                    tech.capec_ids.append(capec_id)

        if mapped:
            capec_map[capec_id] = mapped

    logger.info("Parsed CAPEC STIX: %d CAPEC→ATT&CK mappings", len(capec_map))
    return capec_map


def load_attack_data() -> bool:
    """Load ATT&CK + CAPEC data from STIX JSON, downloading if needed."""
    global _tactic_dict, _technique_dict, _capec_to_techniques

    if _tactic_dict is not None:
        return True

    # Download/load ATT&CK STIX
    attack_path = ATTACK_JSON_PATH
    if not os.path.isfile(attack_path):
        attack_path = _download_json(ATTACK_STIX_URL, ATTACK_JSON_PATH)
    else:
        logger.info("Using cached ATT&CK JSON: %s", attack_path)

    if attack_path is None:
        logger.warning("ATT&CK data unavailable — feature disabled")
        _tactic_dict = {}
        _technique_dict = {}
        _capec_to_techniques = {}
        return False

    # Download/load CAPEC STIX
    capec_path = CAPEC_JSON_PATH
    if not os.path.isfile(capec_path):
        capec_path = _download_json(CAPEC_STIX_URL, CAPEC_JSON_PATH)
    else:
        logger.info("Using cached CAPEC JSON: %s", capec_path)

    try:
        _tactic_dict, _technique_dict = _parse_attack_stix(attack_path)

        if capec_path:
            _capec_to_techniques = _parse_capec_stix(
                capec_path, _technique_dict
            )
        else:
            logger.warning("CAPEC data unavailable — no CAPEC→ATT&CK mapping")
            _capec_to_techniques = {}

        return True
    except (json.JSONDecodeError, KeyError, OSError) as exc:
        logger.error("Failed to parse STIX data: %s", exc)
        _tactic_dict = {}
        _technique_dict = {}
        _capec_to_techniques = {}
        return False


def get_tactics() -> Dict[str, AttackTactic]:
    """Return all ATT&CK tactics."""
    if _tactic_dict is None:
        load_attack_data()
    return _tactic_dict or {}


def get_techniques() -> Dict[str, AttackTechnique]:
    """Return all ATT&CK techniques."""
    if _technique_dict is None:
        load_attack_data()
    return _technique_dict or {}


def get_techniques_for_capec(capec_id: str) -> List[AttackTechnique]:
    """Return ATT&CK techniques mapped to a given CAPEC ID."""
    if _capec_to_techniques is None:
        load_attack_data()
    return (_capec_to_techniques or {}).get(capec_id, [])


def get_techniques_for_capec_list(
    capec_ids: List[str],
) -> List[AttackTechnique]:
    """Return deduplicated ATT&CK techniques for a list of CAPEC IDs."""
    seen = set()
    result = []
    for cid in capec_ids:
        for tech in get_techniques_for_capec(cid):
            if tech.id not in seen:
                seen.add(tech.id)
                result.append(tech)
    return result


def get_tactics_for_techniques(
    techniques: List[AttackTechnique],
) -> List[AttackTactic]:
    """Return deduplicated tactics referenced by the given techniques."""
    all_tactics = get_tactics()
    seen = set()
    result = []
    for tech in techniques:
        for tid in tech.tactics:
            if tid not in seen and tid in all_tactics:
                seen.add(tid)
                result.append(all_tactics[tid])
    return result
