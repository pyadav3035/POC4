"""
URL Configuration for auth_service project.
"""

from django.contrib import admin
from django.urls import path, include
from apps.users.health import HealthCheckView, ReadinessView, LivenessView, MetricsView

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/v1/auth/', include('apps.users.urls')),
    
    # Health check endpoints for microservice deployment
    path('health/', HealthCheckView.as_view(), name='health'),
    path('ready/', ReadinessView.as_view(), name='readiness'),
    path('live/', LivenessView.as_view(), name='liveness'),
    path('metrics/', MetricsView.as_view(), name='metrics'),
]
