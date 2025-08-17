"""
URL Configuration for users app.

This module defines URL patterns for user authentication endpoints.
"""

from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView

from .views import LoginAPIView, LogoutAPIView, UserProfileAPIView, SignUpAPIView, HomePageView, FeedbackAPIView

app_name = 'users'

urlpatterns = [
    # Authentication endpoints
    path('login/', LoginAPIView.as_view(), name='login'),
    path('logout/', LogoutAPIView.as_view(), name='logout'),
    path('signup/', SignUpAPIView.as_view(), name='signup'),
    path('profile/', UserProfileAPIView.as_view(), name='profile'),
    path('home/', HomePageView.as_view(), name='home'),
    path('feedback/', FeedbackAPIView.as_view(), name='feedback'),

    # JWT token refresh endpoint (provided by SimpleJWT)
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
]
