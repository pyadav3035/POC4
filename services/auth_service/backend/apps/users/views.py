"""
Views for user authentication and management.

This module contains API views for handling user login using Django's built-in User model
with PostgreSQL backend. Optimized for Angular 18+ frontend consumption.
"""

from django.contrib.auth.models import User
from django.db import IntegrityError
from django.utils import timezone
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
import logging

from .serializers import LoginSerializer, UserSerializer, UserProfileSerializer, SignUpSerializer, InstructionsSerializer, OfflineSerializer, DownloadsSerializer, PublicationsSerializer
from .models import HomePageInformation

logger = logging.getLogger(__name__)


class LoginAPIView(APIView):
    """
    API View for user authentication using username and password.
    
    This view handles user login by validating credentials against Django's User model
    stored in PostgreSQL and returns JWT tokens following SimpleJWT specification.
    
    Frontend Integration (Angular 18+):
    ```typescript
    // Login service method
    login(username: string, password: string): Observable<LoginResponse> {
      const loginData = { username, password };
      return this.http.post<LoginResponse>('/api/v1/auth/login/', loginData);
    }
    
    // Response interface
    interface LoginResponse {
      success: boolean;
      message: string;
      data: {
        user: UserData;
        tokens: {
          access: string;
          refresh: string;
        };
      };
    }
    ```
    
    Methods:
        POST: Authenticate user and return JWT tokens
    """
    
    permission_classes = [AllowAny]
    
    def post(self, request, *args, **kwargs):
        """
        Authenticate user with username and password against PostgreSQL.
        
        Args:
            request: HTTP request containing username and password
            
        Returns:
            Response: Clean JSON response optimized for Angular frontend
            
        Request Body:
            {
                "username": "[username]",
                "password": "[password]"
            }
            
        Success Response (200):
            {
                "success": true,
                "message": "Login successful",
                "data": {
                    "user": {
                        "id": 1,
                        "username": "[username]",
                        "email": "[email]",
                        "first_name": "[first_name]",
                        "last_name": "[last_name]",
                        "is_staff": false,
                        "is_active": true,
                        "date_joined": "2024-01-01T12:00:00Z",
                        "last_login": "2024-01-15T10:30:00Z"
                    },
                    "tokens": {
                        "access": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
                        "refresh": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
                    }
                }
            }
            
        Error Response (400):
            {
                "success": false,
                "message": "Invalid credentials",
                "errors": {
                    "detail": "Invalid credentials. Please check your username and password.",
                    "code": "invalid_credentials"
                }
            }
        """
        
        serializer = LoginSerializer(
            data=request.data, 
            context={'request': request}
        )
        
        if serializer.is_valid():
            try:
                # Get validated user from serializer (PostgreSQL query completed)
                user = serializer.validated_data['user']
                
                # Generate JWT tokens using SimpleJWT
                tokens = serializer.get_tokens_for_user(user)
                
                # Update last login timestamp (PostgreSQL UPDATE query)
                user.last_login = timezone.now()
                user.save(update_fields=['last_login'])
                
                # Serialize user data for clean JSON response
                user_serializer = UserSerializer(user)
                
                # Log successful login with client IP for security monitoring
                client_ip = self.get_client_ip(request)
                logger.info(
                    f"User ID {user.id} logged in successfully from IP: {client_ip}"
                )
                
                # Return clean JSON response for Angular frontend
                return Response({
                    'success': True,
                    'message': 'Login successful',
                    'data': {
                        'user': user_serializer.data,
                        'tokens': tokens
                    }
                }, status=status.HTTP_200_OK)
                
            except Exception as e:
                # Log unexpected errors for debugging
                logger.error(f"Unexpected error during login: {str(e)}")
                return Response({
                    'success': False,
                    'message': 'An error occurred during authentication',
                    'errors': {
                        'detail': 'Internal server error',
                        'code': 'server_error'
                    }
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        else:
            # Log failed login attempt for security monitoring
            client_ip = self.get_client_ip(request)
            logger.warning(
                f"Failed login attempt from IP: {client_ip}"
            )
            
            # Return standardized error response for Angular frontend
            return Response({
                'success': False,
                'message': 'Authentication failed',
                'errors': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
    
    def get_client_ip(self, request):
        """
        Extract client IP address from request headers.
        
        Args:
            request: HTTP request object
            
        Returns:
            str: Client IP address
        """
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', 'unknown')
        return ip


class LogoutAPIView(APIView):
    """
    API View for user logout with JWT token blacklisting.
    
    This view handles user logout by blacklisting the refresh token in PostgreSQL
    to prevent further use, following SimpleJWT specification.
    
    Frontend Integration (Angular 18+):
    ```typescript
    logout(): Observable<LogoutResponse> {
      const refreshToken = localStorage.getItem('refresh_token');
      return this.http.post<LogoutResponse>('/api/v1/auth/logout/', {
        refresh: refreshToken
      });
    }
    ```
    
    Methods:
        POST: Logout user and blacklist refresh token
    """
    
    def post(self, request, *args, **kwargs):
        """
        Logout user by blacklisting refresh token in PostgreSQL.
        
        Args:
            request: HTTP request containing refresh token
            
        Returns:
            Response: Clean JSON response for Angular frontend
            
        Request Body:
            {
                "refresh": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
            }
            
        Success Response (200):
            {
                "success": true,
                "message": "Logout successful"
            }
            
        Error Response (400):
            {
                "success": false,
                "message": "Invalid token",
                "errors": {
                    "detail": "Token is invalid or expired",
                    "code": "invalid_token"
                }
            }
        """
        
        try:
            refresh_token = request.data.get('refresh')
            
            if not refresh_token:
                return Response({
                    'success': False,
                    'message': 'Refresh token is required',
                    'errors': {
                        'detail': 'Refresh token not provided',
                        'code': 'missing_token'
                    }
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Blacklist token in PostgreSQL using SimpleJWT
            token = RefreshToken(refresh_token)
            token.blacklist()
            
            # Log successful logout
            user_id = request.user.id if request.user.is_authenticated else 'anonymous'
            logger.info(f"User ID {user_id} logged out successfully")
            
            return Response({
                'success': True,
                'message': 'Logout successful'
            }, status=status.HTTP_200_OK)
            
        except TokenError as e:
            logger.warning(f"Invalid token during logout: {str(e)}")
            return Response({
                'success': False,
                'message': 'Invalid token',
                'errors': {
                    'detail': 'Token is invalid or expired',
                    'code': 'invalid_token'
                }
            }, status=status.HTTP_400_BAD_REQUEST)
            
        except Exception as e:
            logger.error(f"Unexpected error during logout: {str(e)}")
            return Response({
                'success': False,
                'message': 'An error occurred during logout',
                'errors': {
                    'detail': 'Internal server error',
                    'code': 'server_error'
                }
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class UserProfileAPIView(APIView):
    """
    Production-ready API View for authenticated user profile management.
    
    This view handles both retrieving and updating user profile information
    with comprehensive validation, error handling, and PostgreSQL optimization.
    
    Frontend Integration (Angular 18+):
    ```typescript
    // TypeScript interfaces
    interface ProfileResponse {
      success: boolean;
      message: string;
      data: {
        user: UserProfile;
      };
    }
    
    interface UserProfile {
      id: number;
      username: string;
      email: string;
      first_name: string;
      last_name: string;
      full_name: string;
      initials: string;
      is_staff: boolean;
      is_active: boolean;
      date_joined: string;
      last_login: string;
    }
    
    // Service methods
    getUserProfile(): Observable<ProfileResponse> {
      return this.http.get<ProfileResponse>('/api/v1/auth/profile/', {
        headers: { Authorization: `Bearer ${this.getAccessToken()}` }
      });
    }
    
    updateProfile(profileData: Partial<UserProfile>): Observable<ProfileResponse> {
      return this.http.put<ProfileResponse>('/api/v1/auth/profile/', profileData, {
        headers: { 
          Authorization: `Bearer ${this.getAccessToken()}`,
          'Content-Type': 'application/json'
        }
      });
    }
    ```
    
    Methods:
        GET: Retrieve authenticated user's profile
        PUT: Update authenticated user's profile
    """
    
    # Authentication is required (configured globally in settings.py)
    # permission_classes = [IsAuthenticated]  # Default from settings
    # authentication_classes = [JWTAuthentication]  # Default from settings
    
    def get(self, request, *args, **kwargs):
        """
        Retrieve authenticated user's profile from PostgreSQL.
        
        Args:
            request: HTTP request with JWT authentication
            
        Returns:
            Response: Clean JSON response with user profile data
            
        Success Response (200):
            {
                "success": true,
                "message": "Profile retrieved successfully",
                "data": {
                    "user": {
                        "id": 1,
                        "username": "testuser1",
                        "email": "test@example.com",
                        "first_name": "Test",
                        "last_name": "User",
                        "full_name": "Test User",
                        "initials": "TU",
                        "is_staff": false,
                        "is_active": true,
                        "date_joined": "2025-01-01T12:00:00Z",
                        "last_login": "2025-08-15T10:30:00Z"
                    }
                }
            }
            
        Error Response (401):
            {
                "success": false,
                "message": "Authentication required",
                "errors": {
                    "detail": "Authentication credentials were not provided.",
                    "code": "not_authenticated"
                }
            }
        """
        
        try:
            # Use enhanced UserProfileSerializer with computed fields
            serializer = UserProfileSerializer(request.user)
            
            # Log profile access for security monitoring
            logger.info(f"User ID {request.user.id} accessed profile")
            
            return Response({
                'success': True,
                'message': 'Profile retrieved successfully',
                'data': {
                    'user': serializer.data
                }
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Error retrieving user profile for user {request.user.id}: {str(e)}")
            return Response({
                'success': False,
                'message': 'An error occurred while retrieving profile',
                'errors': {
                    'detail': 'Internal server error',
                    'code': 'server_error'
                }
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def put(self, request, *args, **kwargs):
        """
        Update authenticated user's profile in PostgreSQL.
        
        Args:
            request: HTTP request with JWT authentication and profile data
            
        Returns:
            Response: Clean JSON response with updated user profile data
            
        Request Body:
            {
                "email": "newemail@example.com",
                "first_name": "Updated",
                "last_name": "Name"
            }
            
        Success Response (200):
            {
                "success": true,
                "message": "Profile updated successfully",
                "data": {
                    "user": {
                        "id": 1,
                        "username": "testuser1",
                        "email": "newemail@example.com",
                        "first_name": "Updated",
                        "last_name": "Name",
                        "full_name": "Updated Name",
                        "initials": "UN",
                        "is_staff": false,
                        "is_active": true,
                        "date_joined": "2025-01-01T12:00:00Z",
                        "last_login": "2025-08-15T10:30:00Z"
                    }
                }
            }
            
        Error Response (400):
            {
                "success": false,
                "message": "Validation failed",
                "errors": {
                    "email": ["A user with this email address already exists."],
                    "first_name": ["First name can only contain letters, spaces, and hyphens."]
                }
            }
        """
        
        try:
            # Use enhanced UserProfileSerializer for validation and updates
            serializer = UserProfileSerializer(
                request.user, 
                data=request.data, 
                partial=True  # Allow partial updates
            )
            
            if serializer.is_valid():
                # Save updated user data to PostgreSQL
                updated_user = serializer.save()
                
                # Log successful profile update
                logger.info(
                    f"User ID {updated_user.id} updated profile fields: {len(request.data)} fields"
                )
                
                return Response({
                    'success': True,
                    'message': 'Profile updated successfully',
                    'data': {
                        'user': serializer.data
                    }
                }, status=status.HTTP_200_OK)
            
            else:
                # Log validation errors for debugging
                logger.warning(
                    f"Profile update validation failed for user {request.user.id}: "
                    f"{serializer.errors}"
                )
                
                return Response({
                    'success': False,
                    'message': 'Validation failed',
                    'errors': serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)
                
        except Exception as e:
            logger.error(f"Error updating user profile for user {request.user.id}: {str(e)}")
            return Response({
                'success': False,
                'message': 'An error occurred while updating profile',
                'errors': {
                    'detail': 'Internal server error',
                    'code': 'server_error'
                }
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class SignUpAPIView(APIView):
    """
    User registration endpoint with profile fields.
    
    This view handles user signup with comprehensive validation,
    password confirmation, and profile data creation in PostgreSQL.
    Optimized for Angular 18+ frontend integration.
    
    Methods:
        POST: Create new user account with profile
    
    Frontend Integration (Angular 18+):
    ```typescript
    // TypeScript interface for signup
    interface SignUpRequest {
      username: string;
      password: string;
      confirm_password: string;
      email: string;
      rank: string;
      unitname: string;
      mobileNo: string;
      personalNo: string;
      designation: string;
      phoneNo: string;
      status: boolean;
    }
    
    // Service method
    signup(userData: SignUpRequest): Observable<ApiResponse> {
      return this.http.post<ApiResponse>('/auth/signup/', userData);
    }
    ```
    
    Database Operations:
    - Creates User record in auth_user table
    - Creates UserProfile record in users_userprofile table
    - Uses atomic transactions for data consistency
    - Implements proper foreign key relationships
    """
    
    permission_classes = [AllowAny]
    serializer_class = SignUpSerializer
    
    def post(self, request, *args, **kwargs):
        """
        Create new user account with profile.
        
        Args:
            request: Django HTTP request with user signup data
            
        Returns:
            Response: JSON response with user data or validation errors
            
        Request Body:
        ```json
        {
            "username": "john.doe",
            "password": "StrongPassw0rd!",
            "confirm_password": "StrongPassw0rd!",
            "email": "john.doe@example.com",
            "rank": "Officer1",
            "unitname": "IGD",
            "mobileNo": "+919595422695",
            "personalNo": "+919863758455",
            "designation": "sr eng",
            "phoneNo": "+95867816686",
            "status": true
        }
        ```
        
        Success Response (201):
        ```json
        {
            "success": true,
            "message": "User created successfully",
            "data": {
                "user": {
                    "userId": "550e8400-e29b-41d4-a716-446655440000",
                    "username": "john.doe",
                    "email": "john.doe@example.com",
                    "rank": "Officer1",
                    "unitname": "IGD",
                    "mobileNo": "+919595422695",
                    "personalNo": "+919863758455",
                    "designation": "sr eng",
                    "phoneNo": "+95867816686",
                    "status": "ACTIVE",
                    "message": "User created successfully."
                }
            }
        }
        ```
        
        Validation Error Response (400):
        ```json
        {
            "success": false,
            "message": "Validation failed",
            "errors": {
                "username": [
                    {
                        "message": "Username already exists",
                        "code": "username_conflict"
                    }
                ],
                "email": [
                    {
                        "message": "Email already registered",
                        "code": "email_conflict"
                    }
                ],
                "confirm_password": [
                    {
                        "message": "Passwords do not match",
                        "code": "password_mismatch"
                    }
                ]
            }
        }
        ```
        """
        # Log signup attempt
        client_ip = self.get_client_ip(request)
        logger.info(f"User signup attempt from IP: {client_ip}")
        
        try:
            # Validate request data
            serializer = self.serializer_class(data=request.data)
            
            if not serializer.is_valid():
                # Log validation errors
                logger.warning(f"Signup validation failed from IP {client_ip}")
                
                # Transform errors for consistent format
                formatted_errors = {}
                for field, field_errors in serializer.errors.items():
                    formatted_errors[field] = []
                    for error in field_errors:
                        if isinstance(error, dict):
                            formatted_errors[field].append(error)
                        else:
                            formatted_errors[field].append({
                                'message': str(error),
                                'code': 'validation_error'
                            })
                
                return Response(
                    {
                        'success': False,
                        'message': 'Validation failed',
                        'errors': formatted_errors
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Create user and profile
            user, profile = serializer.save()
            
            # Generate response data
            user_data = serializer.to_representation((user, profile))
            
            # Log successful signup
            logger.info(f"User signup successful: ID {user.id}, Profile: {profile.id} from IP: {client_ip}")
            
            return Response(
                {
                    'success': True,
                    'message': 'User created successfully',
                    'data': {
                        'user': user_data
                    }
                },
                status=status.HTTP_201_CREATED
            )
            
        except IntegrityError as e:
            # Handle database integrity errors
            logger.error(f"Database integrity error during signup from IP {client_ip}: {str(e)}")
            
            # Determine specific conflict
            error_message = str(e).lower()
            if 'username' in error_message:
                field_error = {'username': [{'message': 'Username already exists', 'code': 'username_conflict'}]}
            elif 'email' in error_message:
                field_error = {'email': [{'message': 'Email already registered', 'code': 'email_conflict'}]}
            else:
                field_error = {'general': [{'message': 'Data conflict occurred', 'code': 'integrity_error'}]}
            
            return Response(
                {
                    'success': False,
                    'message': 'Signup failed due to data conflict',
                    'errors': field_error
                },
                status=status.HTTP_400_BAD_REQUEST
            )
            
        except Exception as e:
            # Handle unexpected errors
            logger.error(f"Unexpected error during signup from IP {client_ip}: {str(e)}")
            
            return Response(
                {
                    'success': False,
                    'message': 'Signup failed',
                    'errors': {'system': [{'message': 'Internal server error occurred', 'code': 'server_error'}]}
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def get_client_ip(self, request):
        """
        Get client IP address from request headers.
        
        Args:
            request: Django HTTP request
            
        Returns:
            str: Client IP address
        """
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

class HomePageView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        tab_type = request.data.get('tab_type')
        if not tab_type:
            return Response({"error": "tab_type is required"}, status=status.HTTP_400_BAD_REQUEST)
        queryset = HomePageInformation.objects.filter(tab_type=tab_type)
        if tab_type == 'Instructions':
            serializer = InstructionsSerializer(queryset, many=True)
        elif tab_type == 'CMMS Offline':
            serializer = OfflineSerializer(queryset, many=True)
        elif tab_type == 'Downloads':
            serializer = DownloadsSerializer(queryset, many=True)
        elif tab_type == 'Publications':
            serializer = PublicationsSerializer(queryset, many=True)
        else:
            return Response({"error": "Invalid tab_type"}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.data)