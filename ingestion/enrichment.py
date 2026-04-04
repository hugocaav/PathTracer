import os
import sys
import django
import requests
from pathlib import Path

# Setup Django environment
sys.path.append(str(Path(__file__).parent.parent / 'backend'))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'pathtracer.settings')
django.setup()

from core.models import Incident, Alert


# MITRE ATT&CK mapping based on alert signatures
SIGNATURE_TO_TECHNIQUE = {
    'ssh brute force':      ('T1110.001', 'Brute Force: Password Guessing'),
    'ftp brute force':      ('T1110.001', 'Brute Force: Password Guessing'),
    'telnet brute force':   ('T1110.001', 'Brute Force: Password Guessing'),
    'nmap syn scan':        ('T1046', 'Network Service Discovery'),
    'nmap null scan':       ('T1046', 'Network Service Discovery'),
    'nmap fin scan':        ('T1046', 'Network Service Discovery'),
    'nmap xmas scan':       ('T1046', 'Network Service Discovery'),
    'port scan':            ('T1046', 'Network Service Discovery'),
    'icmp ping sweep':      ('T1018', 'Remote System Discovery'),
    'smb scan':             ('T1021.002', 'Remote Services: SMB/Windows Admin Shares'),
    'rdp scan':             ('T1021.001', 'Remote Services: Remote Desktop Protocol'),
    'http directory scan':  ('T1083', 'File and Directory Discovery'),
    'ping':                 ('T1018', 'Remote System Discovery'),
    'kali':                 ('T1592', 'Gather Victim Host Information'),
}

# CVSS scores by MITRE technique (static fallback)
TECHNIQUE_CVSS = {
    'T1110.001': 7.5,
    'T1046':     5.3,
    'T1018':     4.3,
    'T1592':     4.3,
    'T1021.002': 7.8,
    'T1021.001': 7.8,
    'T1083':     5.3,
    'T1071':     5.3,
}


def map_technique(signature: str) -> tuple[str, str]:
    """Map alert signature to MITRE ATT&CK technique."""
    signature_lower = signature.lower()
    for keyword, technique in SIGNATURE_TO_TECHNIQUE.items():
        if keyword in signature_lower:
            return technique
    return ('T0000', 'Unknown Technique')


def get_cvss_from_nvd(keyword: str) -> float | None:
    """Query NIST NVD API for CVSS score related to keyword."""
    try:
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {
            'keywordSearch': keyword,
            'resultsPerPage': 1,
        }
        headers = {'User-Agent': 'PathTracer/1.0'}
        response = requests.get(url, params=params, headers=headers, timeout=10)

        if response.status_code == 200:
            data = response.json()
            vulnerabilities = data.get('vulnerabilities', [])
            if vulnerabilities:
                cve = vulnerabilities[0]['cve']
                metrics = cve.get('metrics', {})

                # Try CVSS v3.1 first
                cvss31 = metrics.get('cvssMetricV31', [])
                if cvss31:
                    return cvss31[0]['cvssData']['baseScore']

                # Fallback to CVSS v2
                cvss2 = metrics.get('cvssMetricV2', [])
                if cvss2:
                    return cvss2[0]['cvssData']['baseScore']
    except Exception as e:
        print(f"[WARN] NVD API error: {e}")
    return None


def enrich_incidents() -> None:
    """Enrich all incidents without CVSS score."""
    incidents = Incident.objects.filter(cvss_score__isnull=True)
    print(f"[INFO] Enriching {incidents.count()} incidents...")

    for incident in incidents:
        # Get most common signature in this incident
        alerts = incident.alerts.all()
        if not alerts:
            continue

        # Get most frequent signature
        signatures = [a.signature for a in alerts]
        top_signature = max(set(signatures), key=signatures.count)

        # Map to MITRE ATT&CK
        technique_id, technique_name = map_technique(top_signature)
        incident.technique_id = technique_id
        incident.technique_name = technique_name

        # Try NVD API first
        cvss = get_cvss_from_nvd(technique_name)

        # Fallback to static mapping
        if not cvss:
            cvss = TECHNIQUE_CVSS.get(technique_id, 5.0)

        incident.cvss_score = cvss
        incident.save()

        print(f"[+] Incident {incident.id} | {incident.src_ip} | "
              f"{technique_id} | CVSS: {cvss}")

    print("\n[DONE] Enrichment complete.")


if __name__ == '__main__':
    enrich_incidents()