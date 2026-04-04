import os
import sys
import json
import django
from pathlib import Path
from datetime import datetime

# Setup Django environment
sys.path.append(str(Path(__file__).parent.parent / 'backend'))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'pathtracer.settings')
django.setup()

from core.models import Alert, Host, Incident


EVE_LOG_PATH = r"\\192.168.12.128\suricata\eve.json"  # placeholder, adjust later


def parse_alert(event: dict) -> Alert | None:
    """Parse a Suricata eve.json alert event into an Alert object."""
    try:
        # Parse timestamp
        timestamp = datetime.fromisoformat(
            event['timestamp'].replace('+0000', '+00:00')
        )

        # Get or create source host
        Host.objects.get_or_create(ip_address=event['src_ip'])

        # Get or create destination host
        Host.objects.get_or_create(ip_address=event['dest_ip'])

        # Check if alert already exists (avoid duplicates)
        if Alert.objects.filter(
            timestamp=timestamp,
            src_ip=event['src_ip'],
            signature=event['alert']['signature']
        ).exists():
            return None

        # Create alert
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
        print(f"[ERROR] Failed to parse alert: {e}")
        return None


def correlate_incident(alert: Alert) -> None:
    """Group alert into existing incident by src_ip + technique family."""
    from django.utils import timezone
    from datetime import timedelta

    # Map signature to attack family for grouping
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

    # Look for open incident from same IP + same attack family in last 30 min
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


def ingest_file(filepath: str) -> None:
    """Read eve.json and ingest all alert events."""
    print(f"[INFO] Reading: {filepath}")
    ingested = 0
    skipped = 0

    with open(filepath, 'r') as f:
        for line in f:
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
            else:
                skipped += 1

    print(f"\n[DONE] Ingested: {ingested} | Skipped (duplicates): {skipped}")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python ingest.py <path_to_eve.json>")
        sys.exit(1)
    ingest_file(sys.argv[1])