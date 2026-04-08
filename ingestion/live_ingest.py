import os
import sys
import json
import time
import django
import paramiko
from pathlib import Path
from datetime import datetime

# Setup Django environment
sys.path.append(str(Path(__file__).parent.parent / 'backend'))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'pathtracer.settings')
django.setup()

from core.models import Alert, Host, Incident

# SSH Configuration
UBUNTU_HOST = '192.168.12.128'
UBUNTU_USER = 'victim'
UBUNTU_PASS = 'victim123'
EVE_PATH = '/var/log/suricata/eve.json'

# How often to poll (seconds)
POLL_INTERVAL = 10


def get_ssh_client():
    """Create SSH connection to Ubuntu victim."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(UBUNTU_HOST, username=UBUNTU_USER, password=UBUNTU_PASS)
    return client


def parse_alert(event: dict) -> Alert | None:
    """Parse a Suricata eve.json alert event into an Alert object."""
    try:
        timestamp = datetime.fromisoformat(
            event['timestamp'].replace('+0000', '+00:00')
        )
        Host.objects.get_or_create(ip_address=event['src_ip'])
        Host.objects.get_or_create(ip_address=event['dest_ip'])

        if Alert.objects.filter(
            timestamp=timestamp,
            src_ip=event['src_ip'],
            signature=event['alert']['signature']
        ).exists():
            return None

        alert = Alert.objects.create(
            timestamp=timestamp,
            src_ip=event['src_ip'],
            dest_ip=event['dest_ip'],
            src_port=event.get('src_port'),
            dest_port=event.get('dest_port'),
            protocol=event.get('proto', ''),
            signature=event['alert']['signature'],
            severity=event['alert'].get('severity', 3),
            category=event['alert'].get('category', ''),
            raw_json=event,
        )
        return alert

    except Exception as e:
        print(f"[ERROR] {e}")
        return None


def correlate_incident(alert: Alert) -> None:
    """Group alert into incident by src_ip + attack family."""
    from datetime import timedelta

    sig_lower = alert.signature.lower()
    if 'brute force' in sig_lower:
        family = 'brute_force'
    elif any(x in sig_lower for x in ['syn scan', 'null scan', 'fin scan', 'xmas scan', 'port scan']):
        family = 'port_scan'
    elif 'ping sweep' in sig_lower or 'icmp' in sig_lower:
        family = 'recon'
    elif 'smb' in sig_lower:
        family = 'smb_scan'
    elif 'rdp' in sig_lower:
        family = 'rdp_scan'
    elif 'http' in sig_lower:
        family = 'web_scan'
    else:
        family = 'other'

    recent = Incident.objects.filter(
        src_ip=alert.src_ip,
        status='open',
        technique_name__icontains=family,
        start_time__gte=alert.timestamp - timedelta(minutes=30)
    ).first()

    if recent:
        recent.alerts.add(alert)
        recent.alert_count += 1
        recent.end_time = alert.timestamp
        recent.save()
    else:
        incident = Incident.objects.create(
            src_ip=alert.src_ip,
            start_time=alert.timestamp,
            alert_count=1,
            technique_name=family,
        )
        incident.alerts.add(alert)


def enrich_new_incidents():
    """Enrich incidents that don't have CVSS score yet."""
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
        'smb scan':             ('T1021.002', 'SMB/Windows Admin Shares'),
        'rdp scan':             ('T1021.001', 'Remote Desktop Protocol'),
        'http directory scan':  ('T1083', 'File and Directory Discovery'),
        'kali':                 ('T1592', 'Gather Victim Host Information'),
    }
    TECHNIQUE_CVSS = {
        'T1110.001': 7.5,
        'T1046':     5.3,
        'T1018':     4.3,
        'T1592':     4.3,
        'T1021.002': 7.8,
        'T1021.001': 7.8,
        'T1083':     5.3,
    }

    incidents = Incident.objects.filter(cvss_score__isnull=True)
    for incident in incidents:
        alerts = incident.alerts.all()
        if not alerts:
            continue
        signatures = [a.signature for a in alerts]
        top_signature = max(set(signatures), key=signatures.count)
        sig_lower = top_signature.lower()

        technique_id, technique_name = 'T0000', 'Unknown'
        for keyword, technique in SIGNATURE_TO_TECHNIQUE.items():
            if keyword in sig_lower:
                technique_id, technique_name = technique
                break

        incident.technique_id = technique_id
        incident.technique_name = technique_name
        incident.cvss_score = TECHNIQUE_CVSS.get(technique_id, 5.0)
        incident.save()


def watch_eve_json():
    """Continuously watch eve.json on Ubuntu via SSH."""
    print(f"[INFO] Connecting to {UBUNTU_HOST}...")

    ssh = get_ssh_client()
    print(f"[INFO] Connected. Watching {EVE_PATH}")
    print(f"[INFO] Polling every {POLL_INTERVAL} seconds...")
    print(f"[INFO] Press Ctrl+C to stop\n")

    # Get current file size to start from end
    stdin, stdout, stderr = ssh.exec_command(f'wc -c < {EVE_PATH}')
    last_size = int(stdout.read().strip())

    ingested_total = 0

    try:
        while True:
            # Check new file size
            stdin, stdout, stderr = ssh.exec_command(f'wc -c < {EVE_PATH}')
            current_size = int(stdout.read().strip())

            if current_size > last_size:
                # Read only new bytes
                bytes_to_read = current_size - last_size
                cmd = f'tail -c {bytes_to_read} {EVE_PATH}'
                stdin, stdout, stderr = ssh.exec_command(cmd)
                new_data = stdout.read().decode('utf-8', errors='ignore')

                ingested = 0
                for line in new_data.strip().split('\n'):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    if event.get('event_type') != 'alert':
                        continue

                    alert = parse_alert(event)
                    if alert:
                        correlate_incident(alert)
                        ingested += 1
                        print(f"[+] {alert.signature} | {alert.src_ip} → {alert.dest_ip}")

                if ingested > 0:
                    enrich_new_incidents()
                    ingested_total += ingested
                    print(f"[INFO] Total ingested this session: {ingested_total}\n")

                last_size = current_size

            time.sleep(POLL_INTERVAL)

    except KeyboardInterrupt:
        print(f"\n[INFO] Stopped. Total ingested: {ingested_total}")
        ssh.close()
    except Exception as e:
        print(f"[ERROR] {e}")
        ssh.close()


if __name__ == '__main__':
    watch_eve_json()