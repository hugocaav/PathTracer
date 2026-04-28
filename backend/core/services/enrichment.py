"""MITRE ATT&CK mapping and CVSS enrichment for incidents.

Single source of truth — replaces the duplicated maps in
ingestion/live_ingest.py and ingestion/enrichment.py.
"""

from core.models import Incident


SIGNATURE_TO_TECHNIQUE: dict[str, tuple[str, str]] = {
    "ssh brute force":     ("T1110.001", "Brute Force: Password Guessing"),
    "ftp brute force":     ("T1110.001", "Brute Force: Password Guessing"),
    "telnet brute force":  ("T1110.001", "Brute Force: Password Guessing"),
    "nmap syn scan":       ("T1046",     "Network Service Discovery"),
    "nmap null scan":      ("T1046",     "Network Service Discovery"),
    "nmap fin scan":       ("T1046",     "Network Service Discovery"),
    "nmap xmas scan":      ("T1046",     "Network Service Discovery"),
    "port scan":           ("T1046",     "Network Service Discovery"),
    "icmp ping sweep":     ("T1018",     "Remote System Discovery"),
    "ping":                ("T1018",     "Remote System Discovery"),
    "smb scan":            ("T1021.002", "Remote Services: SMB/Windows Admin Shares"),
    "rdp scan":            ("T1021.001", "Remote Services: Remote Desktop Protocol"),
    "http directory scan": ("T1083",     "File and Directory Discovery"),
    "kali":                ("T1592",     "Gather Victim Host Information"),
}

TECHNIQUE_CVSS: dict[str, float] = {
    "T1110.001": 7.5,
    "T1046":     5.3,
    "T1018":     4.3,
    "T1592":     4.3,
    "T1021.002": 7.8,
    "T1021.001": 7.8,
    "T1083":     5.3,
    "T1071":     5.3,
}

UNKNOWN_TECHNIQUE: tuple[str, str] = ("T0000", "Unknown Technique")
DEFAULT_CVSS: float = 5.0


def map_technique(signature: str) -> tuple[str, str]:
    """Match the lowercased signature against keyword fragments."""
    sig = signature.lower()
    for keyword, technique in SIGNATURE_TO_TECHNIQUE.items():
        if keyword in sig:
            return technique
    return UNKNOWN_TECHNIQUE


def lookup_cvss(technique_id: str) -> float:
    return TECHNIQUE_CVSS.get(technique_id, DEFAULT_CVSS)


def enrich_incident(incident: Incident) -> bool:
    """Populate technique_id, technique_name, cvss_score on a single incident.

    Idempotent — only writes when something changed. Returns True if saved.
    """
    alerts = list(incident.alerts.all())
    if not alerts:
        return False

    signatures = [a.signature for a in alerts]
    top_signature = max(set(signatures), key=signatures.count)
    technique_id, technique_name = map_technique(top_signature)
    cvss = lookup_cvss(technique_id)

    changed = False
    update_fields = []
    if incident.technique_id != technique_id:
        incident.technique_id = technique_id
        update_fields.append("technique_id")
        changed = True
    if incident.technique_name != technique_name:
        incident.technique_name = technique_name
        update_fields.append("technique_name")
        changed = True
    if incident.cvss_score != cvss:
        incident.cvss_score = cvss
        update_fields.append("cvss_score")
        changed = True

    if changed:
        incident.save(update_fields=update_fields)
    return changed
