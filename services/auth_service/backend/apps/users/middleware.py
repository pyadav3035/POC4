"""
Security middleware for auth service.
"""

import time
import logging
from django.core.cache import cache
from django.http import JsonResponse
from django.utils.deprecation import MiddlewareMixin

logger = logging.getLogger(__name__)


class SecurityHeadersMiddleware(MiddlewareMixin):
    """
    Add security headers to all responses.
    """
    
    def process_response(self, request, response):
        """Add security headers."""
        # Prevent XSS attacks
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-Frame-Options'] = 'DENY'
        response['X-XSS-Protection'] = '1; mode=block'
        
        # HTTPS enforcement
        if not request.is_secure() and hasattr(request, 'META'):
            forwarded_proto = request.META.get('HTTP_X_FORWARDED_PROTO')
            if forwarded_proto != 'https':
                response['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        
        # Content Security Policy
        response['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"
        
        # Referrer Policy
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        return response


class RateLimitMiddleware(MiddlewareMixin):
    """
    Rate limiting middleware for API endpoints.
    """
    
    def process_request(self, request):
        """Check rate limits for sensitive endpoints."""
        if request.path.startswith('/api/auth/login/'):
            return self._check_login_rate_limit(request)
        elif request.path.startswith('/api/auth/signup/'):
            return self._check_signup_rate_limit(request)
        return None
    
    def _check_login_rate_limit(self, request):
        """Rate limit login attempts."""
        client_ip = self._get_client_ip(request)
        cache_key = f"login_attempts:{client_ip}"
        
        attempts = cache.get(cache_key, 0)
        if attempts >= 5:  # Max 5 attempts per 15 minutes
            logger.warning(f"Rate limit exceeded for login from IP: {client_ip}")
            return JsonResponse({
                'success': False,
                'message': 'Too many login attempts. Please try again later.',
                'errors': {
                    'detail': 'Rate limit exceeded',
                    'code': 'rate_limit_exceeded'
                }
            }, status=429)
        
        # Increment counter
        cache.set(cache_key, attempts + 1, 900)  # 15 minutes
        return None
    
    def _check_signup_rate_limit(self, request):
        """Rate limit signup attempts."""
        client_ip = self._get_client_ip(request)
        cache_key = f"signup_attempts:{client_ip}"
        
        attempts = cache.get(cache_key, 0)
        if attempts >= 3:  # Max 3 signups per hour
            logger.warning(f"Rate limit exceeded for signup from IP: {client_ip}")
            return JsonResponse({
                'success': False,
                'message': 'Too many signup attempts. Please try again later.',
                'errors': {
                    'detail': 'Rate limit exceeded',
                    'code': 'rate_limit_exceeded'
                }
            }, status=429)
        
        # Increment counter
        cache.set(cache_key, attempts + 1, 3600)  # 1 hour
        return None
    
    def _get_client_ip(self, request):
        """Get client IP address."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', 'unknown')
        return ip


class RequestLoggingMiddleware(MiddlewareMixin):
    """
    Log API requests for monitoring and security.
    """
    
    def process_request(self, request):
        """Log incoming requests."""
        request._start_time = time.time()
        
        # Log sensitive endpoint access
        if request.path.startswith('/api/auth/'):
            client_ip = self._get_client_ip(request)
            logger.info(f"API request: {request.method} {request.path} from IP: {client_ip}")
    
    def process_response(self, request, response):
        """Log response details."""
        if hasattr(request, '_start_time'):
            duration = time.time() - request._start_time
            
            # Log slow requests
            if duration > 1.0:  # Requests taking more than 1 second
                logger.warning(f"Slow request: {request.method} {request.path} took {duration:.2f}s")
        
        return response
    
    def _get_client_ip(self, request):
        """Get client IP address."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', 'unknown')
        return ip