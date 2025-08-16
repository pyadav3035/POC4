#!/usr/bin/env python
"""
Test runner script for auth service microservice.
"""

import os
import sys
import django
from django.conf import settings
from django.test.utils import get_runner

if __name__ == "__main__":
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
    django.setup()
    
    # Override settings for testing
    settings.USE_MEMORY_CACHE = True
    settings.DATABASES['default'] = {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:',
    }
    
    TestRunner = get_runner(settings)
    test_runner = TestRunner()
    
    # Run specific test modules
    test_modules = [
        'apps.users.tests.test_microservice',
        'apps.users.tests.test_performance'
    ]
    
    failures = test_runner.run_tests(test_modules)
    
    if failures:
        sys.exit(1)
    else:
        print("\n✅ All tests passed! Microservice is working correctly.")
        sys.exit(0)