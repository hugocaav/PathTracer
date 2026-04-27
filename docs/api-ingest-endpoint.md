# API Reference: `POST /api/ingest/alerts/`

## Request

| Field | Value |
|---|---|
| Method | `POST` |
| URL | `http://<server>:8000/api/ingest/alerts/` |
| Headers | `Content-Type: application/json` |
| Auth | None — sender IP must appear in `INGEST_ALLOWED_IPS` env var on the server |
| Limits | ≤ 1000 events per request · ≤ 10 MB body |

## Body

```json
{
  "events": [ <suricata eve.json alert dict>, ... ]
}
```

Required fields per event: `timestamp`, `src_ip`, `dest_ip`, `event_type == "alert"`, `alert.signature`.
Optional: `src_port`, `dest_port`, `proto`, `alert.severity`, `alert.category`. The full event is stored in `Alert.raw_json`.

Events that don't have the required fields are counted in `skipped_invalid`; the rest of the batch still commits. Anything where `event_type != "alert"` is skipped silently as well.

## curl

```bash
curl -X POST http://localhost:8000/api/ingest/alerts/ \
  -H "Content-Type: application/json" \
  -d '{
    "events": [
      {
        "timestamp": "2026-04-26T12:00:00.000000+0000",
        "event_type": "alert",
        "src_ip": "10.0.0.5",
        "dest_ip": "192.168.1.10",
        "src_port": 44321,
        "dest_port": 22,
        "proto": "TCP",
        "alert": {
          "signature": "SSH Brute Force Attempt",
          "severity": 2,
          "category": "Attempted Admin"
        }
      }
    ]
  }'
```

## Python (the shape the on-host agent should use)

```python
import json, requests, time
from pathlib import Path

INGEST_URL = "http://pathtracer.lab:8000/api/ingest/alerts/"
EVE_PATH   = Path("/var/log/suricata/eve.json")
STATE      = Path("/var/lib/suricata-agent/offset")
BATCH      = 500

def read_new_events():
    offset = int(STATE.read_text()) if STATE.exists() else 0
    size = EVE_PATH.stat().st_size
    if size < offset:           # log rotated
        offset = 0
    with EVE_PATH.open("rb") as f:
        f.seek(offset)
        chunk = f.read()
        new_offset = f.tell()
    events = []
    for line in chunk.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        if ev.get("event_type") == "alert":
            events.append(ev)
    return events, new_offset

def post(events):
    r = requests.post(INGEST_URL, json={"events": events}, timeout=10)
    r.raise_for_status()
    return r.json()

while True:
    events, new_offset = read_new_events()
    for i in range(0, len(events), BATCH):
        result = post(events[i:i+BATCH])
        print(result)
    STATE.write_text(str(new_offset))
    time.sleep(5)
```

The endpoint is idempotent on `(timestamp, src_ip, signature)`, so the agent can safely retry a failed POST without producing duplicates.

## Response (200)

```json
{
  "received": 42,
  "stored": 40,
  "skipped_duplicate": 2,
  "skipped_invalid": 0,
  "incidents_created": 3,
  "incidents_updated": 5
}
```

## Errors

| Status | When | Body |
|---|---|---|
| 400 | malformed JSON, missing `events`, `events` not a list | `{"error":"invalid body"}` |
| 403 | sender IP not in `INGEST_ALLOWED_IPS` (empty list rejects everything) | `{"error":"ip not allowed"}` |
| 405 | not a POST | (Django default) |
| 413 | body > 10 MB or `len(events) > 1000` | `{"error":"payload too large"}` or `{"error":"batch too large (max 1000)"}` |
| 500 | unexpected exception during persist | `{"error":"<message>"}` |

## Server config

Set on the PathTracer server before starting `runserver` / gunicorn:

```bash
export INGEST_ALLOWED_IPS="192.168.12.128,192.168.12.129"   # or "*" for any
```

Empty / unset → endpoint rejects every request with 403.
