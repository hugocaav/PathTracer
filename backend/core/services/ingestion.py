"""Suricata alert ingestion service.

Single source of truth — replaces the duplicated parse_alert / correlate_incident
in ingestion/live_ingest.py and ingestion/ingest.py.

Behavior preserved exactly from live_ingest.py: family classification rules,
30-minute incident window, dedup key (timestamp, src_ip, signature), and
enrichment runs against newly-touched incidents in the same transaction.
"""

import logging
from datetime import datetime, timedelta
from typing import Iterable

from django.db import transaction

from core.models import Alert, Host, Incident
from core.services import enrichment


logger = logging.getLogger(__name__)

MAX_BATCH = 1000
INCIDENT_WINDOW = timedelta(minutes=30)


def classify_family(signature: str) -> str:
    """Map signature to attack family for incident grouping.
    Preserved verbatim from ingestion/live_ingest.py:74-88."""
    sig = signature.lower()
    if "brute force" in sig:
        return "brute_force"
    if any(x in sig for x in ("syn scan", "null scan", "fin scan", "xmas scan", "port scan")):
        return "port_scan"
    if "ping sweep" in sig or "icmp" in sig:
        return "recon"
    if "smb" in sig:
        return "smb_scan"
    if "rdp" in sig:
        return "rdp_scan"
    if "http" in sig:
        return "web_scan"
    return "other"


def _parse_timestamp(raw: str) -> datetime:
    return datetime.fromisoformat(raw.replace("+0000", "+00:00"))


def _is_valid(event: dict) -> bool:
    if event.get("event_type") != "alert":
        return False
    if not event.get("timestamp") or not event.get("src_ip") or not event.get("dest_ip"):
        return False
    alert = event.get("alert") or {}
    if not alert.get("signature"):
        return False
    return True


def _correlate(alert: Alert) -> tuple[Incident, bool]:
    """Find or create the incident this alert belongs to.
    Preserved verbatim from ingestion/live_ingest.py:70-109 — including the
    technique_name__icontains=family lookup. Returns (incident, created)."""
    family = classify_family(alert.signature)

    recent = Incident.objects.filter(
        src_ip=alert.src_ip,
        status="open",
        technique_name__icontains=family,
        start_time__gte=alert.timestamp - INCIDENT_WINDOW,
    ).first()

    if recent:
        recent.alerts.add(alert)
        recent.alert_count += 1
        recent.end_time = alert.timestamp
        recent.save(update_fields=["alert_count", "end_time"])
        return recent, False

    incident = Incident.objects.create(
        src_ip=alert.src_ip,
        start_time=alert.timestamp,
        alert_count=1,
        technique_name=family,
    )
    incident.alerts.add(alert)
    return incident, True


@transaction.atomic
def parse_and_persist(events: Iterable[dict]) -> dict:
    """Process a batch of Suricata alert events.

    - Validates each event independently (invalid ones are skipped, not aborted).
    - Deduplicates against (timestamp, src_ip, signature) with one pre-fetch query.
    - Bulk-creates Alerts, then runs correlation per alert (read-modify-write).
    - Enriches every touched incident in the same transaction.
    """
    events = list(events)
    counts = {
        "received": len(events),
        "stored": 0,
        "skipped_duplicate": 0,
        "skipped_invalid": 0,
        "incidents_created": 0,
        "incidents_updated": 0,
    }
    if not events:
        return counts

    # 1. Validate up front. Build (timestamp_str, src_ip, signature) tuples for dedup.
    valid: list[tuple[datetime, dict]] = []
    src_ips: set[str] = set()
    dest_ips: set[str] = set()
    for event in events:
        if not _is_valid(event):
            counts["skipped_invalid"] += 1
            continue
        try:
            ts = _parse_timestamp(event["timestamp"])
        except (ValueError, TypeError):
            counts["skipped_invalid"] += 1
            continue
        valid.append((ts, event))
        src_ips.add(event["src_ip"])
        dest_ips.add(event["dest_ip"])

    print(f"[INGEST.svc] validate  valid={len(valid)} invalid={counts['skipped_invalid']} src_ips={sorted(src_ips)}", flush=True)
    if not valid:
        return counts

    # 2. Pre-fetch hosts in one query, bulk-create the missing ones.
    all_ips = src_ips | dest_ips
    existing_hosts = set(
        Host.objects.filter(ip_address__in=all_ips).values_list("ip_address", flat=True)
    )
    new_hosts = [Host(ip_address=ip) for ip in all_ips - existing_hosts]
    if new_hosts:
        Host.objects.bulk_create(new_hosts, ignore_conflicts=True)
    print(f"[INGEST.svc] hosts  total_ips={len(all_ips)} existing={len(existing_hosts)} new={len(new_hosts)}", flush=True)

    # 3. Pre-fetch existing dedup keys for the batch's src_ip set.
    existing_keys: set[tuple[datetime, str, str]] = set(
        Alert.objects.filter(src_ip__in=src_ips).values_list(
            "timestamp", "src_ip", "signature"
        )
    )
    print(f"[INGEST.svc] dedup  existing_keys_loaded={len(existing_keys)}", flush=True)

    # 4. Build Alert instances, skip duplicates against pre-fetched + intra-batch sets.
    seen_in_batch: set[tuple[datetime, str, str]] = set()
    new_alerts: list[Alert] = []
    for ts, event in valid:
        alert_obj = event["alert"] or {}
        key = (ts, event["src_ip"], alert_obj["signature"])
        if key in existing_keys or key in seen_in_batch:
            counts["skipped_duplicate"] += 1
            continue
        seen_in_batch.add(key)
        new_alerts.append(
            Alert(
                timestamp=ts,
                src_ip=event["src_ip"],
                dest_ip=event["dest_ip"],
                src_port=event.get("src_port"),
                dest_port=event.get("dest_port"),
                protocol=event.get("proto", ""),
                signature=alert_obj["signature"],
                severity=alert_obj.get("severity", 3),
                category=alert_obj.get("category", ""),
                raw_json=event,
            )
        )

    if not new_alerts:
        print(f"[INGEST.svc] all duplicates  skipped={counts['skipped_duplicate']}", flush=True)
        return counts

    # 5. Bulk-create alerts. We need PKs for the M2M attach in correlation,
    # so bulk_create's returned objects must carry IDs (Django supports this on
    # backends that report rowcount; SQLite does for non-conflicting inserts).
    Alert.objects.bulk_create(new_alerts, batch_size=500)
    counts["stored"] = len(new_alerts)
    print(f"[INGEST.svc] bulk_create  alerts={len(new_alerts)} skipped_dup={counts['skipped_duplicate']}", flush=True)

    # 6. Correlation: per-alert read-modify-write of Incident.
    touched_incident_ids: set[int] = set()
    for alert in new_alerts:
        incident, created = _correlate(alert)
        touched_incident_ids.add(incident.id)
        family = classify_family(alert.signature)
        print(f"[INGEST.svc]   correlate {'NEW' if created else 'APPEND'}  incident_id={incident.id} src_ip={alert.src_ip} family={family} signature={alert.signature!r}", flush=True)
        if created:
            counts["incidents_created"] += 1
        else:
            counts["incidents_updated"] += 1

    # 7. Enrich every touched incident inside the same transaction so consumers
    # never see null technique_id / cvss_score for newly-ingested data.
    for incident in Incident.objects.filter(id__in=touched_incident_ids):
        before = (incident.technique_id, incident.technique_name, incident.cvss_score)
        enrichment.enrich_incident(incident)
        after = (incident.technique_id, incident.technique_name, incident.cvss_score)
        if before != after:
            print(f"[INGEST.svc]   enrich  incident_id={incident.id}  {before} -> {after}", flush=True)

    return counts
