"""
Serializers for user authentication and management.

This module contains serializers for handling user login and signup using Django's built-in User model.
Optimized for Angular 18+ frontend consumption with clean JSON responses.
"""

from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import transaction
from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken
import logging

from .models import UserProfile
from .models import HomePageInformation

logger = logging.getLogger(__name__)


class LoginSerializer(serializers.Serializer):
    """
    Serializer for user login with username and password.
    
    This serializer validates user credentials against Django's User model using PostgreSQL
    and returns JWT tokens upon successful authentication.
    
    Frontend Usage (Angular 18+):
    ```typescript
    // POST to /api/v1/auth/login/
    const loginData = {
      username: '[username]',
      password: '[password]'
    };
    
    this.http.post<LoginResponse>('/api/v1/auth/login/', loginData)
      .subscribe(response => {
        if (response.success) {
          // Store tokens in localStorage or sessionStorage
          localStorage.setItem('access_token', response.data.tokens.access);
          localStorage.setItem('refresh_token', response.data.tokens.refresh);
        }
      });
    ```
    """
    
    username = serializers.CharField(
        required=True,
        max_length=150,  # Django User model username max_length
        error_messages={
            'required': 'Username is required.',
            'blank': 'Username cannot be blank.',
            'max_length': 'Username must be 150 characters or fewer.'
        }
    )
    
    password = serializers.CharField(
        required=True,
        write_only=True,
        style={'input_type': 'password'},
        error_messages={
            'required': 'Password is required.',
            'blank': 'Password cannot be blank.'
        }
    )
    
    def validate(self, attrs):
        """
        Validate user credentials against Django User model using PostgreSQL.
        
        Args:
            attrs (dict): Dictionary containing username and password
            
        Returns:
            dict: Validated data with authenticated user instance
            
        Raises:
            serializers.ValidationError: If credentials are invalid
        """
        username = attrs.get('username')
        password = attrs.get('password')
        
        if username and password:
            # Authenticate user using Django's built-in authentication
            # This performs a PostgreSQL query: SELECT * FROM auth_user WHERE username = %s
            user = authenticate(
                request=self.context.get('request'),
                username=username,
                password=password
            )
            
            if not user:
                # Log failed authentication attempt for security monitoring
                logger.warning("Failed login attempt - invalid credentials")
                raise serializers.ValidationError(
                    {
                        'detail': 'Invalid credentials. Please check your username and password.',
                        'code': 'invalid_credentials'
                    }
                )
            
            if not user.is_active:
                # Log attempt to login with inactive account
                logger.warning(f"Login attempt for inactive user ID: {user.id}")
                raise serializers.ValidationError(
                    {
                        'detail': 'User account is disabled.',
                        'code': 'account_disabled'
                    }
                )
            
            # Log successful authentication
            logger.info(f"Successful login for user ID: {user.id}")
            attrs['user'] = user
            
        else:
            raise serializers.ValidationError(
                {
                    'detail': 'Both username and password are required.',
                    'code': 'missing_credentials'
                }
            )
        
        return attrs
    
    def get_tokens_for_user(self, user):
        """
        Generate JWT tokens for authenticated user using SimpleJWT.
        
        Args:
            user (User): Django User instance from PostgreSQL
            
        Returns:
            dict: Dictionary containing access and refresh tokens
        """
        refresh = RefreshToken.for_user(user)
        
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }


class UserSerializer(serializers.ModelSerializer):
    """
    Serializer for Django User model with clean JSON output for Angular frontend.
    
    This serializer provides user data without exposing sensitive information.
    Optimized for PostgreSQL queries and Angular 18+ consumption.
    """
    
    class Meta:
        model = User
        fields = (
            'id', 'username', 'email', 'first_name', 'last_name',
            'is_staff', 'is_active', 'date_joined', 'last_login'
        )
        read_only_fields = ('id', 'date_joined', 'last_login')


class UserProfileSerializer(serializers.ModelSerializer):
    """
    Enhanced serializer for User Profile operations with validation.
    
    This serializer handles both reading and updating user profile data
    with comprehensive validation for Angular 18+ frontend integration.
    
    Frontend Usage (Angular 18+):
    ```typescript
    // GET Profile
    getUserProfile(): Observable<ProfileResponse> {
      return this.http.get<ProfileResponse>('/api/v1/auth/profile/', {
        headers: { Authorization: `Bearer ${this.getAccessToken()}` }
      });
    }
    
    // UPDATE Profile
    updateProfile(profileData: ProfileUpdateRequest): Observable<ProfileResponse> {
      return this.http.put<ProfileResponse>('/api/v1/auth/profile/', profileData, {
        headers: { 
          Authorization: `Bearer ${this.getAccessToken()}`,
          'Content-Type': 'application/json'
        }
      });
    }
    ```
    """
    
    # Add computed fields for better frontend integration
    full_name = serializers.SerializerMethodField()
    initials = serializers.SerializerMethodField()
    
    class Meta:
        model = User
        fields = (
            'id', 'username', 'email', 'first_name', 'last_name',
            'full_name', 'initials', 'is_staff', 'is_active', 
            'date_joined', 'last_login'
        )
        read_only_fields = ('id', 'username', 'is_staff', 'is_active', 'date_joined', 'last_login')
        
    def get_full_name(self, obj):
        """
        Return user's full name for display in Angular frontend.
        
        Args:
            obj (User): User instance from PostgreSQL
            
        Returns:
            str: Combined first and last name or username fallback
        """
        if obj.first_name and obj.last_name:
            return f"{obj.first_name} {obj.last_name}".strip()
        elif obj.first_name:
            return obj.first_name
        elif obj.last_name:
            return obj.last_name
        return obj.username
    
    def get_initials(self, obj):
        """
        Return user's initials for avatar display in Angular frontend.
        
        Args:
            obj (User): User instance from PostgreSQL
            
        Returns:
            str: User initials (max 2 characters)
        """
        if obj.first_name and obj.last_name:
            return f"{obj.first_name[0]}{obj.last_name[0]}".upper()
        elif obj.first_name:
            return obj.first_name[0].upper()
        elif obj.last_name:
            return obj.last_name[0].upper()
        return obj.username[0].upper() if obj.username else "U"
    
    def validate_email(self, value):
        """
        Validate email uniqueness across PostgreSQL database.
        
        Args:
            value (str): Email address to validate
            
        Returns:
            str: Validated email address
            
        Raises:
            serializers.ValidationError: If email is already in use
        """
        if value:
            # Check if email is already in use by another user
            user = self.instance
            existing_user = User.objects.filter(email=value).exclude(pk=user.pk if user else None).first()
            
            if existing_user:
                raise serializers.ValidationError(
                    "A user with this email address already exists."
                )
        
        return value
    
    def validate_first_name(self, value):
        """
        Validate first name field.
        
        Args:
            value (str): First name to validate
            
        Returns:
            str: Validated and cleaned first name
        """
        if value:
            # Clean and validate name
            cleaned_name = value.strip()
            if len(cleaned_name) > 30:
                raise serializers.ValidationError(
                    "First name must be 30 characters or fewer."
                )
            if not cleaned_name.replace(' ', '').replace('-', '').isalpha():
                raise serializers.ValidationError(
                    "First name can only contain letters, spaces, and hyphens."
                )
            return cleaned_name
        return value
    
    def validate_last_name(self, value):
        """
        Validate last name field.
        
        Args:
            value (str): Last name to validate
            
        Returns:
            str: Validated and cleaned last name
        """
        if value:
            # Clean and validate name
            cleaned_name = value.strip()
            if len(cleaned_name) > 30:
                raise serializers.ValidationError(
                    "Last name must be 30 characters or fewer."
                )
            if not cleaned_name.replace(' ', '').replace('-', '').isalpha():
                raise serializers.ValidationError(
                    "Last name can only contain letters, spaces, and hyphens."
                )
            return cleaned_name
        return value
    
    def update(self, instance, validated_data):
        """
        Update user instance in PostgreSQL with validated data.
        
        Args:
            instance (User): Current user instance
            validated_data (dict): Validated data from serializer
            
        Returns:
            User: Updated user instance
        """
        # Log profile update for security monitoring
        logger.info(f"User ID {instance.id} updating profile")
        
        # Update fields with validation
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        
        # Save to PostgreSQL
        instance.save()
        
        return instance


class SignUpSerializer(serializers.Serializer):
    """
    Serializer for user registration with profile fields.
    
    This serializer handles user signup with comprehensive validation,
    password confirmation, and profile data creation in PostgreSQL.
    
    Frontend Usage (Angular 18+):
    ```typescript
    // POST to /auth/signup/
    const signupData = {
      username: 'john.doe',
      password: 'StrongPassw0rd!',
      confirm_password: 'StrongPassw0rd!',
      email: 'john.doe@example.com',
      rank: 'Officer1',
      unitname: 'IGD',
      mobileNo: '+919595422695',
      personalNo: '+919863758455',
      designation: 'sr eng',
      phoneNo: '+95867816686',
      status: true
    };
    
    this.http.post('/auth/signup/', signupData)
      .subscribe(response => {
        if (response.success) {
          console.log('User created:', response.data.user);
        }
      });
    ```
    """
    
    # Django User model fields
    username = serializers.CharField(
        required=True,
        max_length=150,
        error_messages={
            'required': 'Username is required.',
            'blank': 'Username cannot be blank.',
            'max_length': 'Username must be 150 characters or fewer.'
        }
    )
    
    email = serializers.EmailField(
        required=True,
        error_messages={
            'required': 'Email address is required.',
            'invalid': 'Enter a valid email address.'
        }
    )
    
    password = serializers.CharField(
        required=True,
        write_only=True,
        style={'input_type': 'password'},
        error_messages={
            'required': 'Password is required.',
            'blank': 'Password cannot be blank.'
        }
    )
    
    confirm_password = serializers.CharField(
        required=True,
        write_only=True,
        style={'input_type': 'password'},
        error_messages={
            'required': 'Password confirmation is required.',
            'blank': 'Password confirmation cannot be blank.'
        }
    )
    
    # UserProfile model fields
    rank = serializers.CharField(
        required=True,
        max_length=100,
        error_messages={
            'required': 'Rank is required.',
            'blank': 'Rank cannot be blank.',
            'max_length': 'Rank must be 100 characters or fewer.'
        }
    )
    
    unitname = serializers.CharField(
        required=True,
        max_length=200,
        error_messages={
            'required': 'Unit name is required.',
            'blank': 'Unit name cannot be blank.',
            'max_length': 'Unit name must be 200 characters or fewer.'
        }
    )
    
    designation = serializers.CharField(
        required=True,
        max_length=200,
        error_messages={
            'required': 'Designation is required.',
            'blank': 'Designation cannot be blank.',
            'max_length': 'Designation must be 200 characters or fewer.'
        }
    )
    
    mobileNo = serializers.RegexField(
        regex=r'^\+?1?\d{9,15}$',
        required=True,
        error_messages={
            'required': 'Mobile number is required.',
            'invalid': 'Enter a valid mobile number with country code (e.g., +919595422695).'
        }
    )
    
    personalNo = serializers.RegexField(
        regex=r'^\+?1?\d{9,15}$',
        required=True,
        error_messages={
            'required': 'Personal number is required.',
            'invalid': 'Enter a valid personal number with country code (e.g., +919863758455).'
        }
    )
    
    phoneNo = serializers.RegexField(
        regex=r'^\+?1?\d{9,15}$',
        required=True,
        error_messages={
            'required': 'Phone number is required.',
            'invalid': 'Enter a valid phone number with country code (e.g., +95867816686).'
        }
    )
    
    status = serializers.BooleanField(
        required=False,
        default=True
    )
    
    def validate_username(self, value):
        """
        Validate username uniqueness.
        
        Args:
            value (str): Username to validate
            
        Returns:
            str: Validated username
            
        Raises:
            serializers.ValidationError: If username already exists
        """
        if User.objects.filter(username=value).exists():
            raise serializers.ValidationError(
                "Username already exists",
                code='username_conflict'
            )
        return value
    
    def validate_email(self, value):
        """
        Validate email uniqueness.
        
        Args:
            value (str): Email to validate
            
        Returns:
            str: Validated email
            
        Raises:
            serializers.ValidationError: If email already exists
        """
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError(
                "Email already registered",
                code='email_conflict'
            )
        return value
    
    def validate_password(self, value):
        """
        Validate password using Django's password validators.
        
        Args:
            value (str): Password to validate
            
        Returns:
            str: Validated password
            
        Raises:
            serializers.ValidationError: If password doesn't meet requirements
        """
        try:
            validate_password(value)
        except DjangoValidationError as e:
            raise serializers.ValidationError(
                list(e.messages),
                code='validation_error'
            )
        return value
    
    def validate(self, attrs):
        """
        Validate password confirmation and other cross-field validations.
        
        Args:
            attrs (dict): Dictionary of all field values
            
        Returns:
            dict: Validated data
            
        Raises:
            serializers.ValidationError: If passwords don't match
        """
        password = attrs.get('password')
        confirm_password = attrs.get('confirm_password')
        
        if password != confirm_password:
            raise serializers.ValidationError(
                {
                    'confirm_password': [
                        {
                            'message': 'Passwords do not match',
                            'code': 'password_mismatch'
                        }
                    ]
                }
            )
        
        return attrs
    
    def create(self, validated_data):
        """
        Create user and profile with validated data in PostgreSQL transaction.
        
        Args:
            validated_data (dict): Validated data from serializer
            
        Returns:
            tuple: (User instance, UserProfile instance)
            
        Raises:
            Exception: If user or profile creation fails
        """
        # Remove confirm_password from validated data
        validated_data.pop('confirm_password', None)
        
        # Extract profile data
        profile_data = {
            'rank': validated_data.pop('rank'),
            'unitname': validated_data.pop('unitname'),
            'designation': validated_data.pop('designation'),
            'mobileNo': validated_data.pop('mobileNo'),
            'personalNo': validated_data.pop('personalNo'),
            'phoneNo': validated_data.pop('phoneNo'),
            'status': validated_data.pop('status', True),
        }
        
        # Use database transaction for atomicity
        with transaction.atomic():
            # Create User instance
            user = User.objects.create_user(
                username=validated_data['username'],
                email=validated_data['email'],
                password=validated_data['password']
            )
            
            # Create UserProfile instance
            profile = UserProfile.objects.create(
                user=user,
                **profile_data
            )
            
            # Log successful user creation
            logger.info(f"New user created: ID {user.id}, Profile: {profile.id}")
            
            return user, profile
    
    def to_representation(self, instance):
        """
        Convert User and UserProfile instances to JSON representation.
        
        Args:
            instance: Tuple of (User, UserProfile) instances
            
        Returns:
            dict: Serialized user and profile data for API response
        """
        user, profile = instance
        
        return {
            'userId': str(profile.id),  # Use profile UUID as primary identifier
            'username': user.username,
            'email': user.email,
            'rank': profile.rank,
            'unitname': profile.unitname,
            'mobileNo': profile.mobileNo,
            'personalNo': profile.personalNo,
            'designation': profile.designation,
            'phoneNo': profile.phoneNo,
            'status': 'ACTIVE' if profile.status else 'INACTIVE',
            'message': 'User created successfully.'
        }

class InstructionsSerializer(serializers.ModelSerializer):
    class Meta:
        model = HomePageInformation
        fields = ['tab_type', 'title', 'content']

class OfflineSerializer(serializers.ModelSerializer):
    class Meta:
        model = HomePageInformation
        fields = ['tab_type', 'title', 'content']

class DownloadsSerializer(serializers.ModelSerializer):
    class Meta:
        model = HomePageInformation
        fields = ['tab_type', 'file_name', 'content']

class PublicationsSerializer(serializers.ModelSerializer):
    class Meta:
        model = HomePageInformation
        fields = ['tab_type', 'title', 'content']