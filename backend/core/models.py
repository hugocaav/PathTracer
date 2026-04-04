from django.db import models


class Host(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)
    hostname = models.CharField(max_length=255, blank=True)
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.ip_address


class Alert(models.Model):
    SEVERITY_CHOICES = [
        (1, 'High'),
        (2, 'Medium'),
        (3, 'Low'),
        (4, 'Info'),
    ]

    timestamp = models.DateTimeField()
    src_ip = models.GenericIPAddressField()
    dest_ip = models.GenericIPAddressField()
    src_port = models.IntegerField(null=True, blank=True)
    dest_port = models.IntegerField(null=True, blank=True)
    protocol = models.CharField(max_length=10, blank=True)
    signature = models.CharField(max_length=500)
    severity = models.IntegerField(choices=SEVERITY_CHOICES, default=3)
    category = models.CharField(max_length=255, blank=True)
    raw_json = models.JSONField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.timestamp} | {self.signature} | {self.src_ip}"


class Incident(models.Model):
    STATUS_CHOICES = [
        ('open', 'Open'),
        ('reviewing', 'Reviewing'),
        ('closed', 'Closed'),
    ]

    src_ip = models.GenericIPAddressField()
    start_time = models.DateTimeField()
    end_time = models.DateTimeField(null=True, blank=True)
    alert_count = models.IntegerField(default=0)
    alerts = models.ManyToManyField(Alert, blank=True)
    cvss_score = models.FloatField(null=True, blank=True)
    technique_id = models.CharField(max_length=20, blank=True)
    technique_name = models.CharField(max_length=255, blank=True)
    ai_summary = models.TextField(blank=True)
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='open'
    )
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Incident {self.id} | {self.src_ip} | {self.alert_count} alerts"