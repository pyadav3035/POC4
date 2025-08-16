"""
Management command to register the auth service in service discovery.
"""

from django.core.management.base import BaseCommand
from django.conf import settings
from apps.users.service_registry import register_current_service


class Command(BaseCommand):
    help = 'Register the auth service in service discovery'
    
    def handle(self, *args, **options):
        """Register the service."""
        try:
            register_current_service()
            self.stdout.write(
                self.style.SUCCESS(
                    f'Successfully registered {settings.SERVICE_NAME} service'
                )
            )
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(
                    f'Failed to register service: {str(e)}'
                )
            )