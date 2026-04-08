from django.urls import path
from . import views

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('incidents/<int:pk>/', views.incident_detail, name='incident_detail'),
    path('api/incidents/', views.api_incidents, name='api_incidents'),
    path('api/alerts/', views.api_alerts, name='api_alerts'),
    path('api/incidents/<int:pk>/summary/', views.generate_ai_summary, name='generate_ai_summary'),
    path('api/timeline/', views.api_timeline, name='api_timeline'),
]