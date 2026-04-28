from django.urls import path
from . import views

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('attacker/<str:ip>/', views.attacker_profile, name='attacker_profile'),
    path('incidents/<int:pk>/', views.incident_detail, name='incident_detail'),
    path('api/attacker/<str:ip>/', views.api_attacker_profile, name='api_attacker_profile'),
    path('api/incidents/', views.api_incidents, name='api_incidents'),
    path('api/alerts/', views.api_alerts, name='api_alerts'),
    path('api/chat/', views.api_chat, name='api_chat'),
    path('api/killchain/<str:ip>/', views.analyze_kill_chain, name='kill_chain'),
    path('api/incidents/<int:pk>/summary/', views.generate_ai_summary, name='generate_ai_summary'),
    path('api/timeline/', views.api_timeline, name='api_timeline'),
    path('api/ingest/alerts/', views.api_ingest, name='api_ingest'),
]
