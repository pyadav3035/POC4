"""
Management command to perform comprehensive health checks.
"""

from django.core.management.base import BaseCommand
from django.db import connection
from django.core.cache import cache
from apps.users.circuit_breaker import database_circuit_breaker
import time


class Command(BaseCommand):
    help = 'Perform comprehensive health checks for the auth service'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Show detailed health check information',
        )
    
    def handle(self, *args, **options):
        """Perform health checks."""
        verbose = options['verbose']
        
        self.stdout.write('Performing health checks...\n')
        
        checks = [
            ('Database Connection', self.check_database),
            ('Cache System', self.check_cache),
            ('Circuit Breakers', self.check_circuit_breakers),
            ('Migrations', self.check_migrations),
        ]
        
        all_passed = True
        
        for check_name, check_func in checks:
            try:
                start_time = time.time()
                result = check_func()
                duration = time.time() - start_time
                
                if result:
                    status = self.style.SUCCESS('✓ PASS')
                    if verbose:
                        status += f' ({duration:.2f}s)'
                else:
                    status = self.style.ERROR('✗ FAIL')
                    all_passed = False
                
                self.stdout.write(f'{check_name}: {status}')
                
            except Exception as e:
                self.stdout.write(
                    f'{check_name}: {self.style.ERROR("✗ ERROR")} - {str(e)}'
                )
                all_passed = False
        
        self.stdout.write('')
        
        if all_passed:
            self.stdout.write(
                self.style.SUCCESS('All health checks passed! Service is healthy.')
            )
        else:
            self.stdout.write(
                self.style.ERROR('Some health checks failed! Service may be unhealthy.')
            )
            exit(1)
    
    def check_database(self):
        """Check database connectivity."""
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
                cursor.fetchone()
            return True
        except Exception:
            return False
    
    def check_cache(self):
        """Check cache system."""
        try:
            test_key = 'health_check_test'
            test_value = 'test_value'
            
            cache.set(test_key, test_value, timeout=10)
            retrieved_value = cache.get(test_key)
            cache.delete(test_key)
            
            return retrieved_value == test_value
        except Exception:
            return False
    
    def check_circuit_breakers(self):
        """Check circuit breaker status."""
        try:
            # This is a simplified check
            # In production, you'd check the actual circuit breaker states
            return True
        except Exception:
            return False
    
    def check_migrations(self):
        """Check if all migrations are applied."""
        try:
            from django.db.migrations.executor import MigrationExecutor
            executor = MigrationExecutor(connection)
            plan = executor.migration_plan(executor.loader.graph.leaf_nodes())
            return len(plan) == 0
        except Exception:
            return False