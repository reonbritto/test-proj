"""Analytics engine for CWE data aggregation and risk scoring."""
from collections import Counter, defaultdict
from typing import List
from .models import CWEStats, CWERiskScore


def top_cwes(cves: List[dict],
             cwe_dict: dict,
             limit: int = 10) -> List[CWEStats]:
    """Find the CWEs with the most associated CVEs."""
    cwe_counter = Counter()
    for cve in cves:
        for cwe_id in cve.get("cwe_ids", []):
            cwe_counter[cwe_id] += 1

    results = []
    for cwe_id, count in cwe_counter.most_common(limit):
        # Strip 'CWE-' prefix to look up in dict
        numeric_id = cwe_id.replace("CWE-", "")
        cwe_entry = cwe_dict.get(numeric_id)
        cwe_name = cwe_entry.name if cwe_entry else cwe_id
        results.append(CWEStats(
            cwe_id=cwe_id,
            cwe_name=cwe_name,
            cve_count=count
        ))
    return results


def cwe_risk_scores(cves: List[dict],
                    cwe_dict: dict,
                    limit: int = 15) -> List[CWERiskScore]:
    """Compute CWE risk scores by cross-referencing frequency and severity.

    Combines how often a CWE appears in real CVEs with the average
    CVSS v3 severity of those CVEs. This analysis is not available
    on the CWE website, which lists weaknesses statically without
    real-world exploit frequency or severity data.
    """
    cwe_counts: Counter = Counter()
    cwe_scores: dict = defaultdict(list)

    for cve in cves:
        cvss = cve.get("cvss", {})
        v3_score = cvss.get("v3_score")
        for cwe_id in cve.get("cwe_ids", []):
            cwe_counts[cwe_id] += 1
            if v3_score is not None:
                cwe_scores[cwe_id].append(float(v3_score))

    if not cwe_counts:
        return []

    max_count = max(cwe_counts.values())

    results = []
    for cwe_id, count in cwe_counts.most_common(limit):
        scores = cwe_scores.get(cwe_id, [])
        avg_cvss = round(sum(scores) / len(scores), 1) if scores else 0.0

        # Composite risk: 60% frequency, 40% severity (both normalised)
        norm_freq = count / max_count if max_count else 0
        norm_severity = avg_cvss / 10.0
        risk = round((norm_freq * 0.6 + norm_severity * 0.4) * 100, 1)

        numeric_id = cwe_id.replace("CWE-", "")
        cwe_entry = cwe_dict.get(numeric_id)
        cwe_name = cwe_entry.name if cwe_entry else cwe_id

        results.append(CWERiskScore(
            cwe_id=cwe_id,
            cwe_name=cwe_name,
            cve_count=count,
            avg_cvss=avg_cvss,
            risk_score=risk
        ))

    results.sort(key=lambda r: r.risk_score, reverse=True)
    return results
