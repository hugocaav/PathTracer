from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse
from .models import Alert, Incident, Host
import ollama as ollama_client

def dashboard(request):
    """Main dashboard view."""
    incidents = Incident.objects.all().order_by('-created_at')
    alerts = Alert.objects.all().order_by('-timestamp')[:50]
    hosts = Host.objects.all()

    context = {
        'incidents': incidents,
        'alerts': alerts,
        'hosts': hosts,
        'total_alerts': Alert.objects.count(),
        'total_incidents': Incident.objects.count(),
        'open_incidents': Incident.objects.filter(status='open').count(),
        'high_risk': Incident.objects.filter(cvss_score__gte=7.0).count(),
    }
    return render(request, 'core/dashboard.html', context)


def incident_detail(request, pk):
    """Single incident detail view."""
    incident = get_object_or_404(Incident, pk=pk)
    alerts = incident.alerts.all().order_by('-timestamp')
    context = {
        'incident': incident,
        'alerts': alerts,
    }
    return render(request, 'core/incident_detail.html', context)


def api_incidents(request):
    """API endpoint — returns incidents as JSON for attack map."""
    incidents = Incident.objects.all().values(
        'id', 'src_ip', 'alert_count', 'cvss_score',
        'technique_id', 'technique_name', 'status'
    )
    hosts = Host.objects.all().values('ip_address', 'hostname')
    return JsonResponse({
        'incidents': list(incidents),
        'hosts': list(hosts),
    })


def api_alerts(request):
    """API endpoint — returns latest alerts as JSON."""
    alerts = Alert.objects.all().order_by('-timestamp')[:100].values(
        'id', 'timestamp', 'src_ip', 'dest_ip',
        'signature', 'severity', 'category'
    )
    return JsonResponse({'alerts': list(alerts)})

def generate_ai_summary(request, pk):
    """Generate AI incident summary using local Ollama model."""
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)

    incident = get_object_or_404(Incident, pk=pk)
    alerts = incident.alerts.all()

    # Build context for the AI
    alert_list = "\n".join([
        f"- {a.signature} from {a.src_ip}:{a.src_port} to {a.dest_ip}:{a.dest_port} at {a.timestamp}"
        for a in alerts[:20]  # limit to 20 alerts
    ])

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
2. How severe it is
3. What the attacker was trying to do
4. One key mitigation recommendation

Be concise and technical but clear."""

    try:
        response = ollama_client.chat(
            model='gemma4:e2b',
            messages=[{'role': 'user', 'content': prompt}],
            options={
                'temperature': 1.0,
                'top_p': 0.95,
                'top_k': 64,
            }
        )
        summary = response['message']['content']
        incident.ai_summary = summary
        incident.save()
        return JsonResponse({'summary': summary})

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)