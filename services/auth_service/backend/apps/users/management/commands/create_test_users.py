"""
Management command to create test users for development and testing.
"""

from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from django.db import IntegrityError


class Command(BaseCommand):
    help = 'Create test users for development and testing'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--users',
            type=int,
            default=5,
            help='Number of test users to create (default: 5)',
        )
        parser.add_argument(
            '--password',
            type=str,
            default=None,
            help='Password for test users (required for security)',
        )
    
    def handle(self, *args, **options):
        num_users = options['users']
        password = options['password']
        
        if not password:
            self.stdout.write(
                self.style.ERROR('Password is required. Use --password argument.')
            )
            return
        
        self.stdout.write(
            self.style.SUCCESS(f'Creating {num_users} test users...')
        )
        
        created_count = 0
        
        for i in range(1, num_users + 1):
            username = f'testuser{i}'
            email = f'testuser{i}@example.com'
            first_name = f'Test{i}'
            last_name = 'User'
            
            try:
                user = User.objects.create_user(
                    username=username,
                    email=email,
                    password=password,
                    first_name=first_name,
                    last_name=last_name
                )
                
                self.stdout.write(
                    self.style.SUCCESS(f'✓ Created user: {username} ({email})')
                )
                created_count += 1
                
            except IntegrityError:
                self.stdout.write(
                    self.style.WARNING(f'✗ User {username} already exists')
                )
        
        # Create an admin user
        try:
            admin_user = User.objects.create_superuser(
                username='admin',
                email='admin@example.com',
                password=password,
                first_name='Admin',
                last_name='User'
            )
            self.stdout.write(
                self.style.SUCCESS('✓ Created admin user: admin (admin@example.com)')
            )
            created_count += 1
            
        except IntegrityError:
            self.stdout.write(
                self.style.WARNING('✗ Admin user already exists')
            )
        
        self.stdout.write(
            self.style.SUCCESS(
                f'\nCompleted! Created {created_count} new users.\n'
                f'You can now test the login API with usernames like "testuser1", "testuser2", etc.\n'
                f'Example: POST /api/v1/auth/login/ with {{"username": "testuser1", "password": "[your_password]"}}'
            )
        )
