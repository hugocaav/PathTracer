import json
from collections import defaultdict

from django.db.models import Max, Min, Sum
from django.utils import timezone

from ..models import Alert, Incident
from .ai import extract_json_object, get_groq_client


TECHNIQUE_TO_STAGE = {
    "T1046": 1,
    "T1018": 1,
    "T1592": 1,
    "T1110": 3,
    "T1110.001": 3,
    "T1071": 3,
    "T1083": 3,
    "T1021": 3,
    "T1021.001": 3,
    "T1021.002": 3,
    "T1078": 4,
    "T1059": 4,
    "T1547": 5,
    "T1053": 5,
    "T1095": 6,
    "T1571": 6,
}

STAGE_NAMES = {
    1: "Reconnaissance",
    2: "Weaponization",
    3: "Delivery",
    4: "Exploitation",
    5: "Installation",
    6: "Command & Control",
    7: "Actions on Objectives",
}


def get_kill_chain_stage(technique_id):
    if not technique_id:
        return None
    normalized = technique_id.strip().upper()
    if normalized in TECHNIQUE_TO_STAGE:
        return TECHNIQUE_TO_STAGE[normalized]
    return TECHNIQUE_TO_STAGE.get(normalized.split(".")[0])


def calculate_kill_chain_confidence(stage_sequence, total_alert_count):
    if not stage_sequence:
        return 0

    distinct_stages = len(set(stage_sequence))
    distinct_score = min(distinct_stages / 4, 1) * 40

    if len(stage_sequence) == 1:
        order_ratio = 1
    else:
        ordered_pairs = sum(
            1
            for previous, current in zip(stage_sequence, stage_sequence[1:])
            if current >= previous
        )
        order_ratio = ordered_pairs / (len(stage_sequence) - 1)

    order_score = order_ratio * 30
    alert_score = min(total_alert_count / 100, 1) * 30
    return int(round(distinct_score + order_score + alert_score))


def build_hourly_activity_for_ip(ip):
    hourly_buckets = {f"{hour:02d}": 0 for hour in range(24)}
    for timestamp in Alert.objects.filter(src_ip=ip).values_list("timestamp", flat=True):
        local_timestamp = timezone.localtime(timestamp)
        hourly_buckets[f"{local_timestamp.hour:02d}"] += 1
    return [{"hour": hour, "count": count} for hour, count in hourly_buckets.items()]


def get_peak_alert_velocity(ip):
    per_minute_counts = defaultdict(int)
    for timestamp in Alert.objects.filter(src_ip=ip).values_list("timestamp", flat=True):
        local_timestamp = timezone.localtime(timestamp).replace(second=0, microsecond=0)
        per_minute_counts[local_timestamp] += 1
    return max(per_minute_counts.values(), default=0)


def calculate_threat_score(ip):
    incidents_qs = Incident.objects.filter(src_ip=ip)
    alerts_qs = Alert.objects.filter(src_ip=ip)

    max_cvss = incidents_qs.aggregate(value=Max("cvss_score"))["value"] or 0
    current_stage = max(
        (get_kill_chain_stage(technique_id) or 0 for technique_id in incidents_qs.values_list("technique_id", flat=True)),
        default=0,
    )
    total_alerts = alerts_qs.count()
    peak_velocity = get_peak_alert_velocity(ip)
    unique_techniques = (
        incidents_qs.exclude(technique_id="")
        .exclude(technique_id__isnull=True)
        .values("technique_id")
        .distinct()
        .count()
    )

    factor_cvss = min(max_cvss / 10, 1) * 25
    factor_kill_chain = min(current_stage / 7, 1) * 25
    factor_volume = min(total_alerts / 1000, 1) * 20
    factor_velocity = min(peak_velocity / 20, 1) * 15
    factor_diversity = min(unique_techniques / 6, 1) * 15

    score = min(
        int(round(factor_cvss + factor_kill_chain + factor_volume + factor_velocity + factor_diversity)),
        100,
    )

    if score >= 80:
        label, color_class = "CRITICAL", "high"
    elif score >= 60:
        label, color_class = "HIGH", "medium"
    elif score >= 40:
        label, color_class = "MEDIUM", "warning"
    elif score >= 20:
        label, color_class = "LOW", "low"
    else:
        label, color_class = "MINIMAL", "info"

    return {
        "score": score,
        "label": label,
        "color_class": color_class,
        "factors": {
            "cvss": {"label": "Max CVSS", "points": int(round(factor_cvss)), "max_points": 25, "value": round(max_cvss, 1)},
            "kill_chain": {"label": "Kill Chain", "points": int(round(factor_kill_chain)), "max_points": 25, "value": current_stage},
            "volume": {"label": "Alert Volume", "points": int(round(factor_volume)), "max_points": 20, "value": total_alerts},
            "velocity": {"label": "Attack Velocity", "points": int(round(factor_velocity)), "max_points": 15, "value": peak_velocity},
            "diversity": {"label": "Technique Diversity", "points": int(round(factor_diversity)), "max_points": 15, "value": unique_techniques},
        },
    }


def get_attacker_profile_data(ip):
    alerts_qs = Alert.objects.filter(src_ip=ip)
    incidents_qs = Incident.objects.filter(src_ip=ip).order_by("-start_time")

    alert_bounds = alerts_qs.aggregate(first_seen=Min("timestamp"), last_seen=Max("timestamp"))
    total_alerts = alerts_qs.count()
    total_incidents = incidents_qs.count()
    threat_score = calculate_threat_score(ip)
    peak_velocity = get_peak_alert_velocity(ip)
    kill_chain_stage = max(
        (get_kill_chain_stage(technique_id) or 0 for technique_id in incidents_qs.values_list("technique_id", flat=True)),
        default=0,
    )

    techniques = list(
        incidents_qs.exclude(technique_id="")
        .exclude(technique_id__isnull=True)
        .values("technique_id", "technique_name")
        .annotate(count=Sum("alert_count"))
        .order_by("-count", "technique_id")
    )

    hourly_activity = build_hourly_activity_for_ip(ip)
    active_hours = [entry["hour"] for entry in hourly_activity if entry["count"] > 0]
    incidents = list(
        incidents_qs.values(
            "id",
            "src_ip",
            "start_time",
            "end_time",
            "alert_count",
            "cvss_score",
            "technique_id",
            "technique_name",
            "status",
        )
    )

    ai_analysis = {}
    try:
        client = get_groq_client()
        prompt = (
            f"IP address: {ip}\n"
            f"Total alerts: {total_alerts}\n"
            f"Total incidents: {total_incidents}\n"
            f"Techniques used: {json.dumps(techniques, default=str)}\n"
            f"Kill Chain stage reached: {kill_chain_stage} ({STAGE_NAMES.get(kill_chain_stage, 'Unknown')})\n"
            f"Attack velocity: {peak_velocity} alerts per minute at peak\n"
            f"Active hours: {', '.join(active_hours) if active_hours else 'Unknown'}\n"
        )
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {
                    "role": "system",
                    "content": (
                        "Return ONLY valid JSON with keys: attack_pattern, automation_likelihood, "
                        "sophistication, threat_assessment."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            temperature=0.2,
            response_format={"type": "json_object"},
        )
        ai_analysis = extract_json_object(response.choices[0].message.content or "")
    except Exception:
        ai_analysis = {}

    return {
        "ip": ip,
        "threat_score": threat_score,
        "total_alerts": total_alerts,
        "total_incidents": total_incidents,
        "first_seen": alert_bounds["first_seen"],
        "last_seen": alert_bounds["last_seen"],
        "incidents": incidents,
        "techniques": techniques,
        "hourly_activity": hourly_activity,
        "kill_chain_stage": kill_chain_stage,
        "ai_analysis": ai_analysis,
        "peak_velocity": peak_velocity,
    }


def build_kill_chain_payload(ip):
    incidents = list(
        Incident.objects.filter(src_ip=ip).order_by("start_time").values(
            "id",
            "src_ip",
            "start_time",
            "end_time",
            "alert_count",
            "cvss_score",
            "technique_id",
            "technique_name",
            "status",
        )
    )

    if not incidents:
        return {
            "ip": ip,
            "current_stage": 0,
            "current_stage_name": "No confirmed stage",
            "next_stage": 1,
            "next_stage_name": STAGE_NAMES[1],
            "confidence": 0,
            "evidence": [],
            "incidents": [],
            "narrative": "",
            "predicted_techniques": [],
            "recommended_actions": [],
            "time_estimate": "Unknown",
        }

    evidence = []
    stage_sequence = []
    total_alert_count = 0
    analyzed_incidents = []

    for incident in incidents:
        technique_id = incident.get("technique_id") or ""
        stage = get_kill_chain_stage(technique_id)
        if stage is not None:
            stage_sequence.append(stage)
        alert_count = incident.get("alert_count") or 0
        total_alert_count += alert_count
        stage_name = STAGE_NAMES.get(stage, "Unknown")
        evidence.append(
            f"{incident['start_time']}: {technique_id or 'Unknown technique'} ({incident.get('technique_name') or 'Unknown'}) "
            f"mapped to {stage_name} with {alert_count} alerts."
        )
        analyzed_incidents.append({**incident, "stage": stage, "stage_name": stage_name})

    current_stage = max(stage_sequence) if stage_sequence else 0
    confidence = calculate_kill_chain_confidence(stage_sequence, total_alert_count)
    next_stage = min(current_stage + 1, 7) if current_stage else 1
    next_stage_name = STAGE_NAMES.get(next_stage, "Unknown")

    narrative = ""
    predicted_techniques = []
    recommended_actions = []
    time_estimate = "Unknown"

    try:
        client = get_groq_client()
        prompt = (
            "You are a senior threat intelligence analyst. Analyze this attack sequence and provide:\n\n"
            "A 2-sentence narrative of what the attacker is doing\n"
            "predicted_techniques: array of 2-3 MITRE technique IDs likely next\n"
            "recommended_actions: array of 3-5 specific actionable steps\n"
            "time_estimate: string estimate of time to next stage\n\n"
            "Base your analysis on the Kill Chain stage progression and attack velocity.\n"
            "Return ONLY valid JSON with keys: narrative, predicted_techniques, recommended_actions, time_estimate.\n"
            "Be specific to the actual IPs and techniques provided.\n\n"
            f"Attacker IP: {ip}\n"
            f"Current stage: {current_stage} ({STAGE_NAMES.get(current_stage, 'Unknown')})\n"
            f"Confidence: {confidence}\n"
            f"Evidence:\n- " + "\n- ".join(evidence) + "\n\n"
            f"Incidents: {json.dumps(analyzed_incidents, default=str)}"
        )

        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "system", "content": "Return only JSON."}, {"role": "user", "content": prompt}],
            temperature=0.2,
            response_format={"type": "json_object"},
        )
        payload = extract_json_object(response.choices[0].message.content or "")
        narrative = (payload.get("narrative") or "").strip()
        predicted_techniques = [item for item in (payload.get("predicted_techniques") or []) if isinstance(item, str)][:3]
        recommended_actions = [item for item in (payload.get("recommended_actions") or []) if isinstance(item, str)][:5]
        time_estimate = (payload.get("time_estimate") or "Unknown").strip()

        if predicted_techniques:
            predicted_stage = get_kill_chain_stage(predicted_techniques[0])
            if predicted_stage:
                next_stage = predicted_stage
                next_stage_name = STAGE_NAMES.get(next_stage, next_stage_name)
    except Exception:
        pass

    return {
        "ip": ip,
        "current_stage": current_stage,
        "current_stage_name": STAGE_NAMES.get(current_stage, "Unknown"),
        "next_stage": next_stage,
        "next_stage_name": next_stage_name,
        "confidence": confidence,
        "evidence": evidence,
        "incidents": analyzed_incidents,
        "narrative": narrative,
        "predicted_techniques": predicted_techniques,
        "recommended_actions": recommended_actions,
        "time_estimate": time_estimate,
    }

