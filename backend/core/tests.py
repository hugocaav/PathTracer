import sys
from types import SimpleNamespace
from unittest.mock import patch

from django.test import Client, TestCase
from django.urls import reverse
from django.utils import timezone

from .models import Alert, Host, Incident
from .views import calculate_threat_score


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

    def test_api_chat_rejects_unsafe_sql(self):
        sql_response = SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content='{"sql": "DELETE FROM core_alert"}'))]
        )

        fake_client = SimpleNamespace(
            chat=SimpleNamespace(
                completions=SimpleNamespace(create=lambda **kwargs: sql_response)
            )
        )
        fake_groq_module = SimpleNamespace(Groq=lambda api_key: fake_client)

        with patch.dict(sys.modules, {"groq": fake_groq_module}):
            response = self.client.post(
                reverse("api_chat"),
                data='{"question": "delete alerts", "history": []}',
                content_type="application/json",
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json()["answer"],
            "I can only answer questions about security alerts, incidents, and hosts in PathTracer.",
        )

    def test_api_chat_returns_answer_sql_and_results(self):
        responses = iter(
            [
                SimpleNamespace(
                    choices=[
                        SimpleNamespace(
                            message=SimpleNamespace(
                                content='{"sql": "SELECT src_ip, COUNT(*) AS total_alerts FROM core_alert GROUP BY src_ip ORDER BY total_alerts DESC LIMIT 1"}'
                            )
                        )
                    ]
                ),
                SimpleNamespace(
                    choices=[
                        SimpleNamespace(
                            message=SimpleNamespace(
                                content="192.168.12.10 currently has the highest alert volume in the available data."
                            )
                        )
                    ]
                ),
            ]
        )

        fake_client = SimpleNamespace(
            chat=SimpleNamespace(
                completions=SimpleNamespace(create=lambda **kwargs: next(responses))
            )
        )
        fake_groq_module = SimpleNamespace(Groq=lambda api_key: fake_client)

        with patch.dict(sys.modules, {"groq": fake_groq_module}):
            response = self.client.post(
                reverse("api_chat"),
                data='{"question": "Which IP has the most alerts?", "history": []}',
                content_type="application/json",
            )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertIn("SELECT src_ip", payload["sql"])
        self.assertEqual(payload["results"][0]["src_ip"], "192.168.12.10")
        self.assertIn("highest alert volume", payload["answer"])

    def test_kill_chain_endpoint_returns_stage_data(self):
        response = self.client.get(reverse("kill_chain", args=[self.incident.src_ip]))

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["ip"], self.incident.src_ip)
        self.assertEqual(payload["current_stage"], 3)
        self.assertEqual(payload["current_stage_name"], "Delivery")
        self.assertIn("confidence", payload)

    def test_calculate_threat_score_returns_expected_shape(self):
        score = calculate_threat_score(self.incident.src_ip)

        self.assertIn("score", score)
        self.assertIn("label", score)
        self.assertIn("color_class", score)
        self.assertIn("factors", score)
        self.assertIn("cvss", score["factors"])

    def test_attacker_profile_endpoints_render(self):
        page_response = self.client.get(reverse("attacker_profile", args=[self.incident.src_ip]))
        api_response = self.client.get(reverse("api_attacker_profile", args=[self.incident.src_ip]))

        self.assertEqual(page_response.status_code, 200)
        self.assertEqual(api_response.status_code, 200)
        payload = api_response.json()
        self.assertEqual(payload["ip"], self.incident.src_ip)
        self.assertEqual(payload["total_incidents"], 1)
