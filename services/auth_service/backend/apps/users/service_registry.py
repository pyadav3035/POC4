"""
Service discovery and registration for microservice architecture.
"""

import json
import time
import logging
from django.conf import settings
from django.core.cache import cache

logger = logging.getLogger(__name__)


class ServiceRegistry:
    """
    Simple service registry for microservice discovery.
    """
    
    def __init__(self):
        self.service_key_prefix = "service_registry"
        self.heartbeat_interval = 30  # seconds
        self.service_timeout = 90  # seconds
    
    def register_service(self, service_name, host, port, health_check_url=None):
        """
        Register a service in the registry.
        """
        service_info = {
            'name': service_name,
            'host': host,
            'port': port,
            'health_check_url': health_check_url or f"http://{host}:{port}/health/",
            'registered_at': time.time(),
            'last_heartbeat': time.time(),
            'status': 'healthy'
        }
        
        service_key = f"{self.service_key_prefix}:{service_name}"
        cache.set(service_key, json.dumps(service_info), timeout=self.service_timeout)
        
        logger.info(f"Service registered: {service_name} at {host}:{port}")
        return service_info
    
    def update_heartbeat(self, service_name):
        """
        Update service heartbeat to indicate it's still alive.
        """
        service_key = f"{self.service_key_prefix}:{service_name}"
        service_data = cache.get(service_key)
        
        if service_data:
            service_info = json.loads(service_data)
            service_info['last_heartbeat'] = time.time()
            service_info['status'] = 'healthy'
            
            cache.set(service_key, json.dumps(service_info), timeout=self.service_timeout)
            logger.debug(f"Heartbeat updated for service: {service_name}")
            return True
        
        logger.warning(f"Service not found for heartbeat update: {service_name}")
        return False
    
    def get_service(self, service_name):
        """
        Get service information by name.
        """
        service_key = f"{self.service_key_prefix}:{service_name}"
        service_data = cache.get(service_key)
        
        if service_data:
            service_info = json.loads(service_data)
            
            # Check if service is still alive
            if time.time() - service_info['last_heartbeat'] > self.service_timeout:
                service_info['status'] = 'unhealthy'
                cache.set(service_key, json.dumps(service_info), timeout=self.service_timeout)
            
            return service_info
        
        return None
    
    def get_all_services(self):
        """
        Get all registered services.
        """
        # This is a simplified implementation
        # In production, you'd use a proper service discovery tool like Consul or etcd
        services = {}
        
        # For demonstration, return current service info
        current_service = self.get_service(settings.SERVICE_NAME)
        if current_service:
            services[settings.SERVICE_NAME] = current_service
        
        return services
    
    def deregister_service(self, service_name):
        """
        Remove service from registry.
        """
        service_key = f"{self.service_key_prefix}:{service_name}"
        cache.delete(service_key)
        logger.info(f"Service deregistered: {service_name}")


# Global service registry instance
service_registry = ServiceRegistry()


def register_current_service():
    """
    Register the current auth service.
    """
    try:
        host = settings.config('SERVICE_HOST', default='localhost')
        port = settings.config('SERVICE_PORT', default=8000, cast=int)
        
        service_registry.register_service(
            service_name=settings.SERVICE_NAME,
            host=host,
            port=port,
            health_check_url=f"http://{host}:{port}/health/"
        )
        
        logger.info(f"Auth service registered successfully at {host}:{port}")
        
    except Exception as e:
        logger.error(f"Failed to register auth service: {str(e)}")


def send_heartbeat():
    """
    Send heartbeat for current service.
    """
    try:
        service_registry.update_heartbeat(settings.SERVICE_NAME)
    except Exception as e:
        logger.error(f"Failed to send heartbeat: {str(e)}")


class ServiceDiscovery:
    """
    Service discovery client for finding other microservices.
    """
    
    def __init__(self):
        self.registry = service_registry
    
    def find_service(self, service_name):
        """
        Find a service by name.
        """
        service_info = self.registry.get_service(service_name)
        
        if service_info and service_info['status'] == 'healthy':
            return {
                'url': f"http://{service_info['host']}:{service_info['port']}",
                'health_check_url': service_info['health_check_url']
            }
        
        return None
    
    def get_service_url(self, service_name, path=''):
        """
        Get full URL for a service endpoint.
        """
        service = self.find_service(service_name)
        if service:
            return f"{service['url']}{path}"
        
        raise ServiceNotFoundError(f"Service {service_name} not found or unhealthy")


class ServiceNotFoundError(Exception):
    """Exception raised when a required service is not found."""
    pass


# Global service discovery instance
service_discovery = ServiceDiscovery()