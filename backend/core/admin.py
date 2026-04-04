from django.contrib import admin
from .models import Alert, Incident, Host


@admin.register(Host)
class HostAdmin(admin.ModelAdmin):
    list_display = ['ip_address', 'hostname', 'first_seen', 'last_seen']
    search_fields = ['ip_address', 'hostname']


@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = ['timestamp', 'signature', 'src_ip', 'dest_ip', 'severity']
    list_filter = ['severity', 'category']
    search_fields = ['signature', 'src_ip', 'dest_ip']


@admin.register(Incident)
class IncidentAdmin(admin.ModelAdmin):
    list_display = ['id', 'src_ip', 'alert_count', 'cvss_score', 'status', 'created_at']
    list_filter = ['status']
    search_fields = ['src_ip', 'technique_id']