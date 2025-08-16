"""
Circuit breaker pattern implementation for microservice resilience.
"""

import time
import logging
from functools import wraps
from django.core.cache import cache
from django.conf import settings

logger = logging.getLogger(__name__)


class CircuitBreakerError(Exception):
    """Exception raised when circuit breaker is open."""
    pass


class CircuitBreaker:
    """
    Circuit breaker implementation for database and external service calls.
    """
    
    def __init__(self, name, failure_threshold=5, recovery_timeout=30):
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.failure_count_key = f"circuit_breaker:{name}:failures"
        self.last_failure_key = f"circuit_breaker:{name}:last_failure"
        self.state_key = f"circuit_breaker:{name}:state"
    
    def __call__(self, func):
        """Decorator to wrap functions with circuit breaker."""
        @wraps(func)
        def wrapper(*args, **kwargs):
            return self._call_with_circuit_breaker(func, *args, **kwargs)
        return wrapper
    
    def _call_with_circuit_breaker(self, func, *args, **kwargs):
        """Execute function with circuit breaker protection."""
        state = self._get_state()
        
        if state == 'open':
            if self._should_attempt_reset():
                self._set_state('half_open')
            else:
                logger.warning(f"Circuit breaker {self.name} is OPEN - rejecting call")
                raise CircuitBreakerError(f"Circuit breaker {self.name} is open")
        
        try:
            result = func(*args, **kwargs)
            self._on_success()
            return result
        except Exception as e:
            self._on_failure()
            raise e
    
    def _get_state(self):
        """Get current circuit breaker state."""
        return cache.get(self.state_key, 'closed')
    
    def _set_state(self, state):
        """Set circuit breaker state."""
        cache.set(self.state_key, state, timeout=3600)
        logger.info(f"Circuit breaker {self.name} state changed to: {state}")
    
    def _get_failure_count(self):
        """Get current failure count."""
        return cache.get(self.failure_count_key, 0)
    
    def _increment_failure_count(self):
        """Increment failure count."""
        count = self._get_failure_count() + 1
        cache.set(self.failure_count_key, count, timeout=3600)
        cache.set(self.last_failure_key, time.time(), timeout=3600)
        return count
    
    def _reset_failure_count(self):
        """Reset failure count."""
        cache.delete(self.failure_count_key)
        cache.delete(self.last_failure_key)
    
    def _should_attempt_reset(self):
        """Check if enough time has passed to attempt reset."""
        last_failure = cache.get(self.last_failure_key, 0)
        return time.time() - last_failure >= self.recovery_timeout
    
    def _on_success(self):
        """Handle successful call."""
        state = self._get_state()
        if state == 'half_open':
            self._set_state('closed')
            self._reset_failure_count()
            logger.info(f"Circuit breaker {self.name} reset to CLOSED")
    
    def _on_failure(self):
        """Handle failed call."""
        failure_count = self._increment_failure_count()
        logger.warning(f"Circuit breaker {self.name} failure count: {failure_count}")
        
        if failure_count >= self.failure_threshold:
            self._set_state('open')
            logger.error(f"Circuit breaker {self.name} opened due to {failure_count} failures")


# Pre-configured circuit breakers
database_circuit_breaker = CircuitBreaker(
    name='database',
    failure_threshold=getattr(settings, 'CIRCUIT_BREAKER_SETTINGS', {}).get('failure_threshold', 5),
    recovery_timeout=getattr(settings, 'CIRCUIT_BREAKER_SETTINGS', {}).get('recovery_timeout', 30)
)


def retry_on_failure(max_retries=3, delay=1, backoff=2):
    """
    Retry decorator with exponential backoff.
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            retries = 0
            current_delay = delay
            
            while retries < max_retries:
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    retries += 1
                    if retries >= max_retries:
                        logger.error(f"Function {func.__name__} failed after {max_retries} retries: {str(e)}")
                        raise e
                    
                    logger.warning(f"Function {func.__name__} failed (attempt {retries}/{max_retries}), retrying in {current_delay}s: {str(e)}")
                    time.sleep(current_delay)
                    current_delay *= backoff
            
            return None
        return wrapper
    return decorator