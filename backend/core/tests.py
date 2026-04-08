from django.test import Client, TestCase
from django.urls import reverse
from django.utils import timezone

from .models import Alert, Host, Incident


class CoreViewTests(TestCase):
    def setUp(self):
        self.client = Client()
        Host.objects.create(ip_address="192.168.12.10", hostname="attacker")
        Host.objects.create(ip_address="192.168.12.20", hostname="target")

        self.alert = Alert.objects.create(
            timestamp=timezone.now() - timezone.timedelta(minutes=30),
            src_ip="192.168.12.10",
            dest_ip="192.168.12.20",
            src_port=4444,
            dest_port=22,
            protocol="TCP",
            signature="SSH Brute Force Attempt",
            severity=1,
            category="Attempted Administrator Privilege Gain",
            raw_json={"event_type": "alert"},
        )
        self.incident = Incident.objects.create(
            src_ip="192.168.12.10",
            start_time=self.alert.timestamp,
            alert_count=1,
            cvss_score=7.5,
            technique_id="T1110.001",
            technique_name="Brute Force: Password Guessing",
            status="open",
        )
        self.incident.alerts.add(self.alert)

    def test_dashboard_loads(self):
        response = self.client.get(reverse("dashboard"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "192.168.12.10")

    def test_api_incidents_returns_incidents_and_hosts(self):
        response = self.client.get(reverse("api_incidents"))

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(len(payload["incidents"]), 1)
        self.assertEqual(len(payload["hosts"]), 2)

    def test_api_alerts_returns_latest_alerts(self):
        response = self.client.get(reverse("api_alerts"))

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(len(payload["alerts"]), 1)
        self.assertEqual(payload["alerts"][0]["signature"], "SSH Brute Force Attempt")

    def test_api_timeline_returns_24_buckets(self):
        response = self.client.get(reverse("api_timeline"))

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(len(payload["timeline"]), 24)
        self.assertEqual(sum(item["count"] for item in payload["timeline"]), 1)

    def test_generate_ai_summary_requires_post(self):
        response = self.client.get(reverse("generate_ai_summary", args=[self.incident.pk]))

        self.assertEqual(response.status_code, 405)
