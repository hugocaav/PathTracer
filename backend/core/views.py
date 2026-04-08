from django.db.models import Count
from django.db.models.functions import TruncHour
from django.conf import settings
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, render
from django.utils import timezone

from .models import Alert, Host, Incident


def dashboard(request):
    """Main dashboard view."""
    incidents = Incident.objects.all().order_by("-cvss_score", "-created_at")
    alerts = Alert.objects.all().order_by("-timestamp")[:50]
    hosts = Host.objects.all()

    context = {
        "incidents": incidents,
        "alerts": alerts,
        "hosts": hosts,
        "total_alerts": Alert.objects.count(),
        "total_incidents": Incident.objects.count(),
        "open_incidents": Incident.objects.filter(status="open").count(),
        "high_risk": Incident.objects.filter(cvss_score__gte=7.0).count(),
    }
    return render(request, "core/dashboard.html", context)


def incident_detail(request, pk):
    """Single incident detail view."""
    incident = get_object_or_404(Incident, pk=pk)
    alerts = incident.alerts.all().order_by("-timestamp")
    end_time = incident.end_time or timezone.now()
    duration_minutes = max(int((end_time - incident.start_time).total_seconds() // 60), 0)
    context = {
        "incident": incident,
        "alerts": alerts,
        "duration_minutes": duration_minutes,
    }
    return render(request, "core/incident_detail.html", context)


def api_incidents(request):
    """API endpoint returns incidents as JSON for the attack map."""
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
    return JsonResponse(
        {
            "incidents": list(incidents),
            "hosts": list(hosts),
        }
    )


def api_alerts(request):
    """API endpoint returns the latest alerts as JSON."""
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
    """Generate an AI incident summary using the Groq API."""
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)

    try:
        from groq import Groq
    except ImportError:
        return JsonResponse({"error": "Groq package not installed"}, status=500)

    incident = get_object_or_404(Incident, pk=pk)
    alerts = incident.alerts.all()

    alert_list = "\n".join(
        [
            f"- {a.signature} from {a.src_ip}:{a.src_port} to {a.dest_ip}:{a.dest_port} at {a.timestamp}"
            for a in alerts[:20]
        ]
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
        client = Groq(api_key=settings.GROQ_API_KEY)
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.5,
        )
        summary = response.choices[0].message.content
        incident.ai_summary = summary
        incident.save()
        return JsonResponse({"summary": summary})

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)


def api_timeline(request):
    """API endpoint returns the last 24 hourly alert counts for the chart."""
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

    timeline = [{"hour": hour, "count": count} for hour, count in timeline_dict.items()]
    return JsonResponse({"timeline": timeline})
