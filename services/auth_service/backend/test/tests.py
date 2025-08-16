"""
Tests for the users app authentication functionality.

This module contains comprehensive tests for username-based authentication
using Django's User model with PostgreSQL backend.
"""

from django.test import TestCase
from django.contrib.auth.models import User
from django.urls import reverse
from rest_framework.test import APITestCase
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
import json
import os
import uuid

# Generate dynamic test data to avoid hardcoded credentials
def get_test_credentials():
    """Generate unique test credentials for each test run."""
    unique_id = str(uuid.uuid4())[:8]
    return {
        'username': f'testuser_{unique_id}',
        'email': f'test_{unique_id}@example.com',
        'password': os.environ.get('TEST_PASSWORD', f'testpass_{unique_id}'),
        'first_name': 'Test',
        'last_name': 'User'
    }


class LoginAPITestCase(APITestCase):
    """Test cases for the username-based Login API."""
    
    def setUp(self):
        """Set up test data for username-based authentication."""
        self.login_url = reverse('users:login')
        self.test_creds = get_test_credentials()
        self.user = User.objects.create_user(
            username=self.test_creds['username'],
            email=self.test_creds['email'],
            password=self.test_creds['password'],
            first_name=self.test_creds['first_name'],
            last_name=self.test_creds['last_name']
        )
    
    def test_login_success_with_username(self):
        """Test successful login with valid username and password."""
        data = {
            'username': self.test_creds['username'],
            'password': self.test_creds['password']
        }
        response = self.client.post(self.login_url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['success'])
        self.assertIn('tokens', response.data['data'])
        self.assertIn('access', response.data['data']['tokens'])
        self.assertIn('refresh', response.data['data']['tokens'])
        self.assertEqual(response.data['data']['user']['username'], self.test_creds['username'])
        self.assertEqual(response.data['data']['user']['email'], self.test_creds['email'])
    
    def test_login_invalid_username(self):
        """Test login with non-existent username."""
        data = {
            'username': 'nonexistent',
            'password': self.test_creds['password']
        }
        response = self.client.post(self.login_url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data['success'])
        self.assertIn('errors', response.data)
    
    def test_login_invalid_password(self):
        """Test login with correct username but wrong password."""
        data = {
            'username': self.test_creds['username'],
            'password': 'wrongpassword'
        }
        response = self.client.post(self.login_url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data['success'])
        self.assertIn('errors', response.data)
    
    def test_login_missing_username(self):
        """Test login with missing username field."""
        data = {'password': self.test_creds['password']}
        response = self.client.post(self.login_url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data['success'])
        self.assertIn('username', response.data['errors'])
    
    def test_login_missing_password(self):
        """Test login with missing password field."""
        data = {'username': self.test_creds['username']}
        response = self.client.post(self.login_url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data['success'])
        self.assertIn('password', response.data['errors'])
    
    def test_login_empty_credentials(self):
        """Test login with empty username and password."""
        data = {'username': '', 'password': ''}
        response = self.client.post(self.login_url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data['success'])
    
    def test_login_inactive_user(self):
        """Test login with inactive user account."""
        self.user.is_active = False
        self.user.save()
        
        data = {
            'username': self.test_creds['username'],
            'password': self.test_creds['password']
        }
        response = self.client.post(self.login_url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data['success'])
    
    def test_login_updates_last_login(self):
        """Test that successful login updates the last_login timestamp."""
        original_last_login = self.user.last_login
        
        data = {
            'username': self.test_creds['username'],
            'password': self.test_creds['password']
        }
        response = self.client.post(self.login_url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Refresh user from database
        self.user.refresh_from_db()
        self.assertNotEqual(self.user.last_login, original_last_login)
        self.assertIsNotNone(self.user.last_login)


class LogoutAPITestCase(APITestCase):
    """Test cases for the Logout API with JWT token blacklisting."""
    
    def setUp(self):
        """Set up test data for logout functionality."""
        self.logout_url = reverse('users:logout')
        self.test_creds = get_test_credentials()
        self.user = User.objects.create_user(
            username=self.test_creds['username'],
            email=self.test_creds['email'],
            password=self.test_creds['password']
        )
        self.refresh = RefreshToken.for_user(self.user)
    
    def test_logout_success(self):
        """Test successful logout with valid refresh token."""
        data = {'refresh': str(self.refresh)}
        response = self.client.post(self.logout_url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['success'])
        self.assertEqual(response.data['message'], 'Logout successful')
    
    def test_logout_missing_token(self):
        """Test logout without providing refresh token."""
        response = self.client.post(self.logout_url, {}, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data['success'])
        self.assertIn('errors', response.data)
    
    def test_logout_invalid_token(self):
        """Test logout with malformed refresh token."""
        data = {'refresh': 'invalid_token_string'}
        response = self.client.post(self.logout_url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data['success'])
    
    def test_logout_already_blacklisted_token(self):
        """Test logout with already blacklisted token."""
        # First logout (blacklist the token)
        data = {'refresh': str(self.refresh)}
        response1 = self.client.post(self.logout_url, data, format='json')
        self.assertEqual(response1.status_code, status.HTTP_200_OK)
        
        # Try to logout again with the same token
        response2 = self.client.post(self.logout_url, data, format='json')
        self.assertEqual(response2.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response2.data['success'])


class UserProfileAPITestCase(APITestCase):
    """Test cases for the User Profile API with JWT authentication."""
    
    def setUp(self):
        """Set up test data for profile functionality."""
        self.profile_url = reverse('users:profile')
        self.test_creds = get_test_credentials()
        self.user = User.objects.create_user(
            username=self.test_creds['username'],
            email=self.test_creds['email'],
            password=self.test_creds['password'],
            first_name=self.test_creds['first_name'],
            last_name=self.test_creds['last_name']
        )
        self.refresh = RefreshToken.for_user(self.user)
        self.access_token = str(self.refresh.access_token)
    
    def test_profile_success_with_jwt(self):
        """Test successful profile retrieval with valid JWT token."""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.access_token}')
        response = self.client.get(self.profile_url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['success'])
        self.assertEqual(response.data['data']['user']['username'], self.test_creds['username'])
        self.assertEqual(response.data['data']['user']['email'], self.test_creds['email'])
        self.assertEqual(response.data['data']['user']['first_name'], self.test_creds['first_name'])
        self.assertEqual(response.data['data']['user']['last_name'], self.test_creds['last_name'])
    
    def test_profile_unauthorized_no_token(self):
        """Test profile retrieval without authentication token."""
        response = self.client.get(self.profile_url)
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
    
    def test_profile_unauthorized_invalid_token(self):
        """Test profile retrieval with invalid JWT token."""
        self.client.credentials(HTTP_AUTHORIZATION='Bearer invalid_token')
        response = self.client.get(self.profile_url)
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
    
    def test_profile_unauthorized_malformed_header(self):
        """Test profile retrieval with malformed authorization header."""
        self.client.credentials(HTTP_AUTHORIZATION='InvalidHeader token')
        response = self.client.get(self.profile_url)
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class TokenRefreshTestCase(APITestCase):
    """Test cases for JWT token refresh functionality."""
    
    def setUp(self):
        """Set up test data for token refresh."""
        self.refresh_url = reverse('users:token_refresh')
        self.test_creds = get_test_credentials()
        self.user = User.objects.create_user(
            username=self.test_creds['username'],
            email=self.test_creds['email'],
            password=self.test_creds['password']
        )
        self.refresh = RefreshToken.for_user(self.user)
    
    def test_token_refresh_success(self):
        """Test successful token refresh with valid refresh token."""
        data = {'refresh': str(self.refresh)}
        response = self.client.post(self.refresh_url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)
        self.assertIsInstance(response.data['access'], str)
    
    def test_token_refresh_invalid_token(self):
        """Test token refresh with invalid refresh token."""
        data = {'refresh': 'invalid_refresh_token'}
        response = self.client.post(self.refresh_url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
    
    def test_token_refresh_missing_token(self):
        """Test token refresh without providing refresh token."""
        response = self.client.post(self.refresh_url, {}, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)