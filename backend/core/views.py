from django.db.models import Count
from django.db.models.functions import TruncHour
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, render
from django.utils import timezone

from .models import Alert, Host, Incident
from .services.ai import get_groq_client
from .services.chat import process_chat_request
from .services.threats import (
    STAGE_NAMES,
    build_kill_chain_payload,
    calculate_threat_score,
    get_attacker_profile_data,
)


def dashboard(request):
    """Render the main PathTracer dashboard."""
    incidents = Incident.objects.all().order_by("-cvss_score", "-created_at")
    alerts = Alert.objects.all().order_by("-timestamp")[:50]
    hosts = Host.objects.all()

    threat_scores = {}
    for incident in incidents:
        if incident.src_ip not in threat_scores:
            threat_scores[incident.src_ip] = calculate_threat_score(incident.src_ip)
        incident.threat_score = threat_scores[incident.src_ip]

    context = {
        "incidents": incidents,
        "alerts": alerts,
        "hosts": hosts,
        "total_alerts": Alert.objects.count(),
        "total_incidents": Incident.objects.count(),
        "open_incidents": Incident.objects.filter(status="open").count(),
        "high_risk": Incident.objects.filter(cvss_score__gte=7.0).count(),
        "threat_scores": threat_scores,
    }
    return render(request, "core/dashboard.html", context)


def incident_detail(request, pk):
    """Render a single incident detail page."""
    incident = get_object_or_404(Incident, pk=pk)
    alerts = incident.alerts.all().order_by("-timestamp")
    end_time = incident.end_time or timezone.now()
    duration_minutes = max(int((end_time - incident.start_time).total_seconds() // 60), 0)

    return render(
        request,
        "core/incident_detail.html",
        {
            "incident": incident,
            "alerts": alerts,
            "duration_minutes": duration_minutes,
            "threat_score": calculate_threat_score(incident.src_ip),
        },
    )


def api_incidents(request):
    """Return incidents and known hosts for dashboard visualizations."""
    incidents = Incident.objects.all().values(
        "id",
        "src_ip",
        "alert_count",
        "cvss_score",
        "technique_id",
        "technique_name",
        "status",
    )
    hosts = Host.objects.all().values("ip_address", "hostname")
    return JsonResponse({"incidents": list(incidents), "hosts": list(hosts)})


def api_alerts(request):
    """Return recent alerts for the dashboard table."""
    alerts = Alert.objects.all().order_by("-timestamp")[:100].values(
        "id",
        "timestamp",
        "src_ip",
        "dest_ip",
        "signature",
        "severity",
        "category",
    )
    return JsonResponse({"alerts": list(alerts)})


def generate_ai_summary(request, pk):
    """Generate and persist an AI summary for an incident."""
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)

    try:
        client = get_groq_client()
    except ImportError as exc:
        return JsonResponse({"error": str(exc)}, status=500)

    incident = get_object_or_404(Incident, pk=pk)
    alerts = incident.alerts.all()
    alert_list = "\n".join(
        f"- {alert.signature} from {alert.src_ip}:{alert.src_port} to {alert.dest_ip}:{alert.dest_port} at {alert.timestamp}"
        for alert in alerts[:20]
    )

    prompt = f"""You are a cybersecurity analyst. Analyze this security incident and provide a brief, clear summary.

Incident Details:
- Source IP: {incident.src_ip}
- Total Alerts: {incident.alert_count}
- MITRE Technique: {incident.technique_id} - {incident.technique_name}
- CVSS Score: {incident.cvss_score}
- Status: {incident.status}

Sample Alerts:
{alert_list}

Provide a 3-4 sentence summary covering:
1. What attack occurred
2. Severity level
3. The attacker's objective
4. One key mitigation recommendation

Be concise and technical but clear."""

    try:
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.5,
        )
        summary = response.choices[0].message.content
        incident.ai_summary = summary
        incident.save()
        return JsonResponse({"summary": summary})
    except Exception as exc:
        return JsonResponse({"error": str(exc)}, status=500)


def api_timeline(request):
    """Return hourly alert buckets for the dashboard timeline chart."""
    end_time = timezone.now().replace(minute=0, second=0, microsecond=0)
    start_time = end_time - timezone.timedelta(hours=23)

    alerts = (
        Alert.objects.filter(timestamp__gte=start_time, timestamp__lt=end_time + timezone.timedelta(hours=1))
        .annotate(hour_bucket=TruncHour("timestamp"))
        .values("hour_bucket")
        .annotate(count=Count("id"))
        .order_by("hour_bucket")
    )

    timeline_dict = {
        (start_time + timezone.timedelta(hours=offset)).strftime("%H:00"): 0
        for offset in range(24)
    }

    for entry in alerts:
        bucket = entry["hour_bucket"]
        if bucket is None:
            continue
        label = timezone.localtime(bucket).strftime("%H:00")
        if label in timeline_dict:
            timeline_dict[label] = entry["count"]

    return JsonResponse({"timeline": [{"hour": hour, "count": count} for hour, count in timeline_dict.items()]})


def api_chat(request):
    """Handle analyst natural-language chat requests."""
    return process_chat_request(request)


def analyze_kill_chain(request, ip):
    """Return kill-chain analysis data for an attacker IP."""
    if request.method != "GET":
        return JsonResponse({"error": "GET required"}, status=405)
    return JsonResponse(build_kill_chain_payload(ip))


def attacker_profile(request, ip):
    """Render the attacker profile page for a source IP."""
    return render(request, "core/attacker_profile.html", get_attacker_profile_data(ip))


def api_attacker_profile(request, ip):
    """Return attacker profile data as JSON."""
    if request.method != "GET":
        return JsonResponse({"error": "GET required"}, status=405)
    return JsonResponse(get_attacker_profile_data(ip), json_dumps_params={"default": str})
