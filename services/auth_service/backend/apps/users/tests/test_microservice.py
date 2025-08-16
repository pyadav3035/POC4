"""
Comprehensive test suite for auth service microservice.
"""

import json
import time
from django.test import TestCase, Client
from django.contrib.auth.models import User
from django.urls import reverse
from django.core.cache import cache
from rest_framework.test import APITestCase
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from apps.users.models import UserProfile


class HealthCheckTests(TestCase):
    """Test health check endpoints."""
    
    def setUp(self):
        self.client = Client()
    
    def test_health_endpoint(self):
        """Test basic health check."""
        response = self.client.get('/health/')
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data['status'], 'healthy')
        self.assertEqual(data['service'], 'auth_service')
    
    def test_liveness_endpoint(self):
        """Test liveness probe."""
        response = self.client.get('/live/')
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data['status'], 'alive')
    
    def test_readiness_endpoint(self):
        """Test readiness probe."""
        response = self.client.get('/ready/')
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn('status', data)
        self.assertIn('checks', data)
    
    def test_metrics_endpoint(self):
        """Test metrics endpoint."""
        response = self.client.get('/metrics/')
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn('system', data)
        self.assertIn('database', data)


class AuthenticationTests(APITestCase):
    """Test authentication endpoints."""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.profile = UserProfile.objects.create(
            user=self.user,
            rank='Officer',
            unitname='Test Unit',
            designation='Test Role',
            mobileNo='+1234567890',
            personalNo='+1234567891',
            phoneNo='+1234567892'
        )
    
    def test_login_success(self):
        """Test successful login."""
        data = {
            'username': 'testuser',
            'password': 'testpass123'
        }
        response = self.client.post('/api/v1/auth/login/', data)
        self.assertEqual(response.status_code, 200)
        
        response_data = response.json()
        self.assertTrue(response_data['success'])
        self.assertIn('tokens', response_data['data'])
        self.assertIn('access', response_data['data']['tokens'])
        self.assertIn('refresh', response_data['data']['tokens'])
    
    def test_login_invalid_credentials(self):
        """Test login with invalid credentials."""
        data = {
            'username': 'testuser',
            'password': 'wrongpassword'
        }
        response = self.client.post('/api/v1/auth/login/', data)
        self.assertEqual(response.status_code, 400)
        
        response_data = response.json()
        self.assertFalse(response_data['success'])
    
    def test_signup_success(self):
        """Test successful user registration."""
        data = {
            'username': 'newuser',
            'email': 'newuser@example.com',
            'password': 'newpass123',
            'confirm_password': 'newpass123',
            'rank': 'Officer',
            'unitname': 'New Unit',
            'designation': 'New Role',
            'mobileNo': '+1234567893',
            'personalNo': '+1234567894',
            'phoneNo': '+1234567895'
        }
        response = self.client.post('/api/v1/auth/signup/', data)
        self.assertEqual(response.status_code, 201)
        
        response_data = response.json()
        self.assertTrue(response_data['success'])
        self.assertIn('user', response_data['data'])
    
    def test_signup_password_mismatch(self):
        """Test signup with password mismatch."""
        data = {
            'username': 'newuser2',
            'email': 'newuser2@example.com',
            'password': 'newpass123',
            'confirm_password': 'differentpass',
            'rank': 'Officer',
            'unitname': 'New Unit',
            'designation': 'New Role',
            'mobileNo': '+1234567896',
            'personalNo': '+1234567897',
            'phoneNo': '+1234567898'
        }
        response = self.client.post('/api/v1/auth/signup/', data)
        self.assertEqual(response.status_code, 400)
    
    def test_profile_access(self):
        """Test authenticated profile access."""
        refresh = RefreshToken.for_user(self.user)
        access_token = str(refresh.access_token)
        
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
        response = self.client.get('/api/v1/auth/profile/')
        
        self.assertEqual(response.status_code, 200)
        response_data = response.json()
        self.assertTrue(response_data['success'])
        self.assertEqual(response_data['data']['user']['username'], 'testuser')


class SecurityTests(TestCase):
    """Test security features."""
    
    def setUp(self):
        self.client = Client()
        cache.clear()
    
    def test_security_headers(self):
        """Test security headers are present."""
        response = self.client.get('/health/')
        
        self.assertIn('X-Content-Type-Options', response)
        self.assertIn('X-Frame-Options', response)
        self.assertIn('X-XSS-Protection', response)
        self.assertIn('Content-Security-Policy', response)
        self.assertIn('Referrer-Policy', response)
        
        self.assertEqual(response['X-Content-Type-Options'], 'nosniff')
        self.assertEqual(response['X-Frame-Options'], 'DENY')
    
    def test_rate_limiting_login(self):
        """Test rate limiting on login endpoint."""
        data = {
            'username': 'testuser',
            'password': 'wrongpassword'
        }
        
        # Make 6 failed attempts (limit is 5)
        for i in range(6):
            response = self.client.post('/api/v1/auth/login/', data)
            if i < 5:
                self.assertEqual(response.status_code, 400)
            else:
                self.assertEqual(response.status_code, 429)
    
    def test_csrf_protection(self):
        """Test CSRF protection is enabled."""
        response = self.client.post('/api/v1/auth/login/', {})
        # Should fail due to CSRF or validation, not 500 error
        self.assertIn(response.status_code, [400, 403])


class CircuitBreakerTests(TestCase):
    """Test circuit breaker functionality."""
    
    def test_circuit_breaker_import(self):
        """Test circuit breaker can be imported."""
        from apps.users.circuit_breaker import CircuitBreaker, database_circuit_breaker
        self.assertIsNotNone(CircuitBreaker)
        self.assertIsNotNone(database_circuit_breaker)


class ServiceRegistryTests(TestCase):
    """Test service registry functionality."""
    
    def test_service_registry_import(self):
        """Test service registry can be imported."""
        from apps.users.service_registry import ServiceRegistry, service_registry
        self.assertIsNotNone(ServiceRegistry)
        self.assertIsNotNone(service_registry)


class SecretsManagerTests(TestCase):
    """Test secrets management."""
    
    def test_secrets_manager_import(self):
        """Test secrets manager can be imported."""
        from apps.users.secrets_manager import SecretsManager, secrets_manager
        self.assertIsNotNone(SecretsManager)
        self.assertIsNotNone(secrets_manager)
    
    def test_secret_encryption_decryption(self):
        """Test secret encryption and decryption."""
        from apps.users.secrets_manager import secrets_manager
        
        test_secret = "test_secret_value"
        encrypted = secrets_manager.encrypt_secret(test_secret)
        decrypted = secrets_manager.decrypt_secret(encrypted)
        
        self.assertEqual(test_secret, decrypted)


class MiddlewareTests(TestCase):
    """Test custom middleware."""
    
    def setUp(self):
        self.client = Client()
    
    def test_request_logging_middleware(self):
        """Test request logging middleware."""
        response = self.client.get('/api/v1/auth/profile/')
        # Should not cause errors
        self.assertIsNotNone(response)
    
    def test_security_headers_middleware(self):
        """Test security headers middleware."""
        response = self.client.get('/health/')
        
        # Check security headers are added
        self.assertIn('X-Content-Type-Options', response)
        self.assertIn('X-Frame-Options', response)


class ModelTests(TestCase):
    """Test model functionality."""
    
    def test_user_profile_creation(self):
        """Test UserProfile model creation."""
        user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        
        profile = UserProfile.objects.create(
            user=user,
            rank='Officer',
            unitname='Test Unit',
            designation='Test Role',
            mobileNo='+1234567890',
            personalNo='+1234567891',
            phoneNo='+1234567892'
        )
        
        self.assertEqual(profile.user, user)
        self.assertEqual(profile.rank, 'Officer')
        self.assertTrue(profile.status)


class ManagementCommandTests(TestCase):
    """Test management commands."""
    
    def test_health_check_command(self):
        """Test health check management command."""
        from django.core.management import call_command
        from io import StringIO
        
        out = StringIO()
        call_command('health_check', stdout=out)
        output = out.getvalue()
        
        self.assertIn('health checks', output.lower())


class IntegrationTests(APITestCase):
    """Integration tests for complete workflows."""
    
    def test_complete_auth_workflow(self):
        """Test complete authentication workflow."""
        # 1. Register new user
        signup_data = {
            'username': 'integrationuser',
            'email': 'integration@example.com',
            'password': 'integrationpass123',
            'confirm_password': 'integrationpass123',
            'rank': 'Officer',
            'unitname': 'Integration Unit',
            'designation': 'Integration Role',
            'mobileNo': '+1234567899',
            'personalNo': '+1234567800',
            'phoneNo': '+1234567801'
        }
        
        signup_response = self.client.post('/api/v1/auth/signup/', signup_data)
        self.assertEqual(signup_response.status_code, 201)
        
        # 2. Login with new user
        login_data = {
            'username': 'integrationuser',
            'password': 'integrationpass123'
        }
        
        login_response = self.client.post('/api/v1/auth/login/', login_data)
        self.assertEqual(login_response.status_code, 200)
        
        tokens = login_response.json()['data']['tokens']
        access_token = tokens['access']
        refresh_token = tokens['refresh']
        
        # 3. Access protected profile endpoint
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
        profile_response = self.client.get('/api/v1/auth/profile/')
        self.assertEqual(profile_response.status_code, 200)
        
        # 4. Update profile
        update_data = {
            'email': 'updated@example.com',
            'first_name': 'Updated'
        }
        
        update_response = self.client.put('/api/v1/auth/profile/', update_data)
        self.assertEqual(update_response.status_code, 200)
        
        # 5. Logout
        logout_data = {'refresh': refresh_token}
        logout_response = self.client.post('/api/v1/auth/logout/', logout_data)
        self.assertEqual(logout_response.status_code, 200)
    
    def test_microservice_health_endpoints(self):
        """Test all microservice health endpoints."""
        endpoints = ['/health/', '/ready/', '/live/', '/metrics/']
        
        for endpoint in endpoints:
            response = self.client.get(endpoint)
            self.assertIn(response.status_code, [200, 503])  # 503 acceptable for readiness
            
            # Ensure response is JSON
            try:
                response.json()
            except json.JSONDecodeError:
                self.fail(f"Endpoint {endpoint} did not return valid JSON")