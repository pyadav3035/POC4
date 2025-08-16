"""
Health check and monitoring endpoints for microservice deployment.
"""

import time
import psutil
from django.conf import settings
from django.db import connection
from django.http import JsonResponse
from django.views import View
from rest_framework.permissions import AllowAny
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
import logging

logger = logging.getLogger(__name__)


class HealthCheckView(APIView):
    """
    Basic health check endpoint for load balancers and orchestrators.
    """
    permission_classes = [AllowAny]
    
    def get(self, request):
        """Return basic health status."""
        return Response({
            'status': 'healthy',
            'timestamp': time.time(),
            'service': 'auth_service'
        }, status=status.HTTP_200_OK)


class ReadinessView(APIView):
    """
    Readiness probe for Kubernetes deployments.
    Checks database connectivity and critical dependencies.
    """
    permission_classes = [AllowAny]
    
    def get(self, request):
        """Check if service is ready to handle requests."""
        checks = {
            'database': self._check_database(),
            'migrations': self._check_migrations()
        }
        
        all_healthy = all(checks.values())
        
        return Response({
            'status': 'ready' if all_healthy else 'not_ready',
            'checks': checks,
            'timestamp': time.time()
        }, status=status.HTTP_200_OK if all_healthy else status.HTTP_503_SERVICE_UNAVAILABLE)
    
    def _check_database(self):
        """Check database connectivity."""
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
            return True
        except Exception:
            return False
    
    def _check_migrations(self):
        """Check if migrations are applied."""
        try:
            from django.db.migrations.executor import MigrationExecutor
            executor = MigrationExecutor(connection)
            plan = executor.migration_plan(executor.loader.graph.leaf_nodes())
            return len(plan) == 0
        except Exception:
            return False


class LivenessView(APIView):
    """
    Liveness probe for Kubernetes deployments.
    Basic check that the application is running.
    """
    permission_classes = [AllowAny]
    
    def get(self, request):
        """Check if service is alive."""
        return Response({
            'status': 'alive',
            'timestamp': time.time()
        }, status=status.HTTP_200_OK)


class MetricsView(APIView):
    """
    Basic metrics endpoint for monitoring.
    """
    permission_classes = [AllowAny]
    
    def get(self, request):
        """Return basic system metrics."""
        try:
            # System metrics
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            # Database connection info
            db_connections = self._get_db_connections()
            
            metrics = {
                'system': {
                    'cpu_percent': cpu_percent,
                    'memory_percent': memory.percent,
                    'memory_available_mb': memory.available // (1024 * 1024),
                    'disk_percent': disk.percent,
                    'disk_free_gb': disk.free // (1024 * 1024 * 1024)
                },
                'database': {
                    'connections': db_connections
                },
                'timestamp': time.time()
            }
            
            return Response(metrics, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Error collecting metrics: {str(e)}")
            return Response({
                'error': 'Failed to collect metrics',
                'timestamp': time.time()
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def _get_db_connections(self):
        """Get database connection count."""
        try:
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT count(*) 
                    FROM pg_stat_activity 
                    WHERE datname = current_database()
                """)
                return cursor.fetchone()[0]
        except Exception:
            return 0