"""
Admin configuration for users app.

Since we're using Django's built-in User model, the admin interface
is already available. This file can be used for custom admin configurations.
"""

from django.contrib import admin
from django.contrib.auth.models import User
from django.contrib.auth.admin import UserAdmin

# The default UserAdmin is already registered, but we can customize it if needed
# admin.site.unregister(User)
# admin.site.register(User, CustomUserAdmin)
