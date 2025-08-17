"""
User Profile Models for Django Authentication Service.

This module extends Django's built-in User model with custom profile fields
for production-ready user management with PostgreSQL 18 backend.
"""

from django.contrib.auth.models import User
from django.db import models
from django.core.validators import RegexValidator
import uuid
from django.utils import timezone


class UserProfile(models.Model):
    """
    Extended user profile model for additional user information.
    
    This model stores additional profile fields beyond Django's built-in User model,
    optimized for PostgreSQL 18 storage and Angular 18+ frontend consumption.
    """
    
    # Primary key using UUID for better security
    id = models.UUIDField(
        primary_key=True, 
        default=uuid.uuid4, 
        editable=False,
        help_text="Unique identifier for the user profile"
    )
    
    # One-to-one relationship with Django User model
    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name='profile',
        help_text="Reference to Django's built-in User model"
    )
    
    # Professional information fields
    rank = models.CharField(
        max_length=100,
        help_text="User's rank or position in organization"
    )
    
    unitname = models.CharField(
        max_length=200,
        help_text="Name of the unit or department"
    )
    
    designation = models.CharField(
        max_length=200,
        help_text="User's job designation or title"
    )
    
    # Phone number validators for Indian phone numbers
    phone_regex = RegexValidator(
        regex=r'^\+?1?\d{9,15}$',
        message="Phone number must be entered in the format: '+999999999'. Up to 15 digits allowed."
    )
    
    mobileNo = models.CharField(
        validators=[phone_regex],
        max_length=17,
        help_text="Mobile phone number with country code"
    )
    
    personalNo = models.CharField(
        validators=[phone_regex],
        max_length=17,
        help_text="Personal phone number with country code"
    )
    
    phoneNo = models.CharField(
        validators=[phone_regex],
        max_length=17,
        help_text="Office or landline phone number"
    )
    
    # Status and tracking fields
    status = models.BooleanField(
        default=True,
        help_text="Active status of the user profile"
    )
    
    # Timestamps for audit trail
    created_at = models.DateTimeField(
        auto_now_add=True,
        help_text="Timestamp when profile was created"
    )
    
    updated_at = models.DateTimeField(
        auto_now=True,
        help_text="Timestamp when profile was last updated"
    )
    
    class Meta:
        db_table = 'user_profiles'
        verbose_name = 'User Profile'
        verbose_name_plural = 'User Profiles'
        indexes = [
            models.Index(fields=['rank']),
            models.Index(fields=['unitname']),
            models.Index(fields=['status']),
            models.Index(fields=['created_at']),
        ]
        ordering = ['-created_at']
    
    def __str__(self):
        """String representation of UserProfile."""
        return f"{self.user.username} - {self.rank} ({self.unitname})"
    
    def get_full_name(self):
        """
        Return user's full name from related User model.
        
        Returns:
            str: Full name or username if names not available
        """
        if self.user.first_name and self.user.last_name:
            return f"{self.user.first_name} {self.user.last_name}"
        return self.user.username
    
    def is_active_profile(self):
        """
        Check if both user and profile are active.
        
        Returns:
            bool: True if both user.is_active and profile.status are True
        """
        return self.user.is_active and self.status
    
    @property
    def user_id(self):
        """
        Get the UUID string representation for API responses.
        
        Returns:
            str: UUID as string
        """
        return str(self.id)


# Signal to create/update profile when User is created/updated
from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver


@receiver(post_save, sender=User)
def create_or_update_user_profile(sender, instance, created, **kwargs):
    """
    Signal handler to automatically create UserProfile when User is created.
    
    Args:
        sender: The User model class
        instance: The User instance being saved
        created: Boolean indicating if this is a new instance
        **kwargs: Additional keyword arguments
    """
    if created:
        # Profile will be created separately in the signup view
        # to handle all profile fields together
        pass
    else:
        # Update profile if it exists
        if hasattr(instance, 'profile'):
            instance.profile.save()


@receiver(post_delete, sender=UserProfile)
def delete_user_when_profile_deleted(sender, instance, **kwargs):
    """
    Signal handler to delete User when UserProfile is deleted.
    
    Args:
        sender: The UserProfile model class
        instance: The UserProfile instance being deleted
        **kwargs: Additional keyword arguments
    """
    try:
        instance.user.delete()
    except User.DoesNotExist:
        pass  # User already deleted


class HomePageInformation(models.Model):
    TAB_CHOICES = [
        ('instructions', 'Instructions'),
        ('offline', 'Offline'),
        ('downloads', 'Downloads'),
        ('publications', 'Publications'),
    ]

    tab_type = models.CharField(max_length=20, choices=TAB_CHOICES)
    title = models.CharField(max_length=255, blank=True, null=True)
    content = models.TextField(blank=True, null=True)

    class Meta:
        db_table = 'information_home_page'

    def __str__(self):
        return f"{self.tab_type}: {self.title }"

class Feedback(models.Model):
    module = models.CharField(max_length=90)
    userlogin = models.IntegerField()
    remarks = models.CharField(max_length=900, blank=True, null=True)
    insert_datetime = models.DateTimeField(default=timezone.now)
    modified_datetime = models.DateTimeField(blank=True)
    is_active = models.IntegerField()
    username = models.CharField(max_length=50)
    personal_no = models.CharField(max_length=50, blank=True, null=True)
    phone_no = models.CharField(max_length=20, blank=True, null=True)
    nudid = models.CharField(max_length=20, blank=True, null=True)
    question1 = models.CharField(max_length=10, blank=True, null=True)
    question2 = models.CharField(max_length=10, blank=True, null=True)
    question3 = models.CharField(max_length=10, blank=True, null=True)
    question4 = models.CharField(max_length=10, blank=True, null=True)
    avg_feedback = models.CharField(max_length=500, blank=True, null=True)

    class Meta:
        db_table = 'tbl_usermgmt_feedback'

    def __str__(self):
        return f"{self.username} - Avg: {self.avg_feedback}"
    