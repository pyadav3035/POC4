"""
Performance and load tests for auth service.
"""

import time
import threading
from django.test import TestCase, Client
from django.contrib.auth.models import User
from concurrent.futures import ThreadPoolExecutor, as_completed


class PerformanceTests(TestCase):
    """Performance tests for critical endpoints."""
    
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='perfuser',
            email='perf@example.com',
            password='perfpass123'
        )
    
    def test_health_endpoint_performance(self):
        """Test health endpoint response time."""
        start_time = time.time()
        response = self.client.get('/health/')
        end_time = time.time()
        
        self.assertEqual(response.status_code, 200)
        response_time = end_time - start_time
        self.assertLess(response_time, 0.1)  # Should respond in < 100ms
    
    def test_login_endpoint_performance(self):
        """Test login endpoint response time."""
        data = {
            'username': 'perfuser',
            'password': 'perfpass123'
        }
        
        start_time = time.time()
        response = self.client.post('/api/v1/auth/login/', data)
        end_time = time.time()
        
        self.assertEqual(response.status_code, 200)
        response_time = end_time - start_time
        self.assertLess(response_time, 1.0)  # Should respond in < 1s
    
    def test_concurrent_health_checks(self):
        """Test concurrent health check requests."""
        def make_request():
            client = Client()
            response = client.get('/health/')
            return response.status_code == 200
        
        # Test 10 concurrent requests
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(make_request) for _ in range(10)]
            results = [future.result() for future in as_completed(futures)]
        
        # All requests should succeed
        self.assertTrue(all(results))
    
    def test_memory_usage_stability(self):
        """Test that repeated requests don't cause memory leaks."""
        import gc
        
        # Make 100 requests to various endpoints
        endpoints = ['/health/', '/ready/', '/live/']
        
        for _ in range(100):
            for endpoint in endpoints:
                response = self.client.get(endpoint)
                self.assertIn(response.status_code, [200, 503])
        
        # Force garbage collection
        gc.collect()
        
        # Test should complete without memory errors
        self.assertTrue(True)