# Django Logout API Documentation

**Version:** 1.0  
**Base URL:** `http://127.0.0.1:8000/api/v1/auth/`  
**Framework:** Django 5.0 + Django REST Framework 3.16.x  
**Authentication:** JWT (djangorestframework-simplejwt 5.3.0)  
**Database:** PostgreSQL 18  
**Frontend Integration:** Angular 18+  

---

## Overview

The Django Logout API provides secure user logout functionality using JWT token blacklisting. When a user logs out, their refresh token is blacklisted in PostgreSQL to prevent further use, ensuring secure session termination. This endpoint is specifically optimized for Angular 18+ frontend consumption with clean JSON responses.

### Key Features
- ✅ JWT refresh token blacklisting using SimpleJWT
- ✅ PostgreSQL-backed token blacklist storage
- ✅ Optional access token validation for enhanced security
- ✅ Client activity logging for security monitoring
- ✅ Clean JSON responses optimized for Angular frontend
- ✅ Comprehensive error handling with standardized error codes

---

## Logout Endpoint

### User Logout

**Endpoint:** `POST /api/v1/auth/logout/`  
**Purpose:** Logout user and blacklist refresh token to prevent further use  
**Authentication Required:** No (Public endpoint - token validated from request body)

#### Request Headers
```http
Content-Type: application/json
Authorization: Bearer <access_token> (Optional - for enhanced security logging)
```

**Note:** While the Authorization header is optional, including it provides better security logging by associating the logout action with the authenticated user.

#### Request Body
```json
{
  "refresh": "string"
}
```

**Field Specifications:**
- `refresh` (string, required): Valid JWT refresh token to be blacklisted
  - Must be a valid JWT token format
  - Token will be permanently blacklisted in PostgreSQL
  - Cannot be blank or null

#### Successful Response (HTTP 200)
```json
{
  "success": true,
  "message": "Logout successful"
}
```

**Response Field Descriptions:**
- `success` (boolean): Always `true` for successful logout
- `message` (string): Human-readable success confirmation

#### Error Responses

##### Missing Refresh Token (HTTP 400)
```json
{
  "success": false,
  "message": "Refresh token is required",
  "errors": {
    "detail": "Refresh token not provided",
    "code": "missing_token"
  }
}
```

##### Invalid or Expired Token (HTTP 400)
```json
{
  "success": false,
  "message": "Invalid token",
  "errors": {
    "detail": "Token is invalid or expired",
    "code": "invalid_token"
  }
}
```

##### Already Blacklisted Token (HTTP 400)
```json
{
  "success": false,
  "message": "Invalid token",
  "errors": {
    "detail": "Token is invalid or expired",
    "code": "invalid_token"
  }
}
```

##### Malformed Token (HTTP 400)
```json
{
  "success": false,
  "message": "Invalid token",
  "errors": {
    "detail": "Token is invalid or expired",
    "code": "invalid_token"
  }
}
```

##### Server Error (HTTP 500)
```json
{
  "success": false,
  "message": "An error occurred during logout",
  "errors": {
    "detail": "Internal server error",
    "code": "server_error"
  }
}
```

#### Security Features
- Permanent token blacklisting in PostgreSQL database
- User activity logging for successful logouts
- Input validation to prevent injection attacks
- Graceful handling of already-blacklisted tokens
- Optional access token validation for enhanced security logging

---

## Angular 18+ Integration

### TypeScript Interface Definitions
```typescript
// Request interface
interface LogoutRequest {
  refresh: string;
}

// Response interface
interface LogoutResponse {
  success: boolean;
  message: string;
}

// Error response interface
interface LogoutError {
  success: false;
  message: string;
  errors: {
    detail: string;
    code: string;
  };
}
```

### Angular Service Implementation
```typescript
import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable } from 'rxjs';
import { tap } from 'rxjs/operators';

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private readonly API_BASE_URL = 'http://127.0.0.1:8000/api/v1/auth/';

  constructor(private http: HttpClient) {}

  /**
   * Logout user and blacklist refresh token
   */
  logout(): Observable<LogoutResponse> {
    const refreshToken = this.getRefreshToken();
    const accessToken = this.getAccessToken();
    
    if (!refreshToken) {
      throw new Error('No refresh token available for logout');
    }

    const logoutData: LogoutRequest = { 
      refresh: refreshToken 
    };
    
    const headers = new HttpHeaders({
      'Content-Type': 'application/json',
      // Optional: Include access token for better security logging
      ...(accessToken && { 'Authorization': `Bearer ${accessToken}` })
    });

    return this.http.post<LogoutResponse>(
      `${this.API_BASE_URL}logout/`,
      logoutData,
      { headers }
    ).pipe(
      tap((response) => {
        if (response.success) {
          // Clear tokens from local storage on successful logout
          this.clearTokens();
        }
      })
    );
  }

  /**
   * Clear all stored tokens
   */
  private clearTokens(): void {
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
    sessionStorage.removeItem('access_token');
    sessionStorage.removeItem('refresh_token');
  }

  /**
   * Get stored access token
   */
  private getAccessToken(): string | null {
    return localStorage.getItem('access_token') || 
           sessionStorage.getItem('access_token');
  }

  /**
   * Get stored refresh token
   */
  private getRefreshToken(): string | null {
    return localStorage.getItem('refresh_token') || 
           sessionStorage.getItem('refresh_token');
  }

  /**
   * Check if user is logged in (has valid tokens)
   */
  isLoggedIn(): boolean {
    return !!(this.getAccessToken() && this.getRefreshToken());
  }
}
```

### Component Usage Example
```typescript
import { Component } from '@angular/core';
import { Router } from '@angular/router';
import { AuthService } from './auth.service';

@Component({
  selector: 'app-header',
  templateUrl: './header.component.html'
})
export class HeaderComponent {
  loading = false;

  constructor(
    private authService: AuthService,
    private router: Router
  ) {}

  onLogout(): void {
    this.loading = true;

    this.authService.logout().subscribe({
      next: (response) => {
        if (response.success) {
          console.log('Logout successful:', response.message);
          
          // Redirect to login page
          this.router.navigate(['/login']);
        }
        this.loading = false;
      },
      error: (errorResponse) => {
        this.loading = false;
        
        console.error('Logout failed:', errorResponse.error?.message || 'Unknown error');
        
        // Even if logout fails, clear tokens and redirect
        // This ensures user is logged out from frontend
        localStorage.clear();
        this.router.navigate(['/login']);
      }
    });
  }
}
```

### Complete Logout Flow with Error Handling
```typescript
import { Injectable } from '@angular/core';
import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { Observable, throwError } from 'rxjs';
import { catchError, tap } from 'rxjs/operators';

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  /**
   * Enhanced logout with comprehensive error handling
   */
  logoutWithErrorHandling(): Observable<LogoutResponse> {
    return this.logout().pipe(
      catchError((error: HttpErrorResponse) => {
        // Log error for debugging
        console.error('Logout API error:', error);

        // Clear tokens even if API call fails
        this.clearTokens();

        if (error.status === 400) {
          const errorData = error.error as LogoutError;
          
          switch (errorData.errors?.code) {
            case 'missing_token':
              console.warn('No refresh token provided');
              break;
            case 'invalid_token':
              console.warn('Token was invalid or already expired');
              break;
            default:
              console.error('Unexpected logout error');
          }
        }

        // Return success even on error to allow UI to proceed
        return throwError(() => error);
      })
    );
  }
}
```

---

## Testing Examples

### Using curl
```bash
# Successful logout
curl -X POST http://127.0.0.1:8000/api/v1/auth/logout/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..." \
  -d '{
    "refresh": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ0b2tlbl90eXBlIjoicmVmcmVzaCIsImV4cCI6MTcyNTE5MDgwMCwiaWF0IjoxNzI0NTg2MDAwLCJqdGkiOiI4NzY1NDMyMSIsInVzZXJfaWQiOjF9.XYZ789"
  }'

# Missing refresh token
curl -X POST http://127.0.0.1:8000/api/v1/auth/logout/ \
  -H "Content-Type: application/json" \
  -d '{}'

# Invalid refresh token
curl -X POST http://127.0.0.1:8000/api/v1/auth/logout/ \
  -H "Content-Type: application/json" \
  -d '{
    "refresh": "invalid_token_string"
  }'
```

### Using Python requests
```python
import requests

# Successful logout
def test_logout_success():
    response = requests.post(
        'http://127.0.0.1:8000/api/v1/auth/logout/',
        json={
            'refresh': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...'
        },
        headers={
            'Content-Type': 'application/json',
            'Authorization': 'Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...'
        }
    )
    
    if response.status_code == 200:
        data = response.json()
        print(f"Logout successful: {data['message']}")
    else:
        print(f"Logout failed: {response.json()}")

# Test missing token
def test_logout_missing_token():
    response = requests.post(
        'http://127.0.0.1:8000/api/v1/auth/logout/',
        json={},
        headers={'Content-Type': 'application/json'}
    )
    
    print(f"Status: {response.status_code}")
    print(f"Response: {response.json()}")

# Test invalid token
def test_logout_invalid_token():
    response = requests.post(
        'http://127.0.0.1:8000/api/v1/auth/logout/',
        json={'refresh': 'invalid_token'},
        headers={'Content-Type': 'application/json'}
    )
    
    print(f"Status: {response.status_code}")
    print(f"Response: {response.json()}")
```

### Complete Test Suite
```python
#!/usr/bin/env python3
"""
Test suite for Django Logout API
"""

import requests
import json

class LogoutAPITester:
    def __init__(self, base_url, access_token=None, refresh_token=None):
        self.base_url = base_url
        self.access_token = access_token
        self.refresh_token = refresh_token
    
    def test_successful_logout(self):
        """Test logout with valid refresh token"""
        if not self.refresh_token:
            print("❌ No refresh token available for testing")
            return False
        
        headers = {'Content-Type': 'application/json'}
        if self.access_token:
            headers['Authorization'] = f'Bearer {self.access_token}'
        
        response = requests.post(
            f"{self.base_url}/logout/",
            json={'refresh': self.refresh_token},
            headers=headers
        )
        
        if response.status_code == 200:
            data = response.json()
            if data.get('success'):
                print("✅ Successful logout test passed")
                return True
        
        print(f"❌ Successful logout test failed: {response.json()}")
        return False
    
    def test_missing_token(self):
        """Test logout without refresh token"""
        response = requests.post(
            f"{self.base_url}/logout/",
            json={},
            headers={'Content-Type': 'application/json'}
        )
        
        if response.status_code == 400:
            data = response.json()
            if (not data.get('success') and 
                data.get('errors', {}).get('code') == 'missing_token'):
                print("✅ Missing token test passed")
                return True
        
        print(f"❌ Missing token test failed: {response.json()}")
        return False
    
    def test_invalid_token(self):
        """Test logout with invalid refresh token"""
        response = requests.post(
            f"{self.base_url}/logout/",
            json={'refresh': 'invalid_token_string'},
            headers={'Content-Type': 'application/json'}
        )
        
        if response.status_code == 400:
            data = response.json()
            if (not data.get('success') and 
                data.get('errors', {}).get('code') == 'invalid_token'):
                print("✅ Invalid token test passed")
                return True
        
        print(f"❌ Invalid token test failed: {response.json()}")
        return False

# Usage example
if __name__ == "__main__":
    tester = LogoutAPITester(
        base_url="http://127.0.0.1:8000/api/v1/auth",
        access_token="your_access_token_here",
        refresh_token="your_refresh_token_here"
    )
    
    # Run all tests
    tester.test_missing_token()
    tester.test_invalid_token()
    tester.test_successful_logout()  # Run this last as it blacklists the token
```

---

## Database Implementation Details

### Token Blacklist Storage (PostgreSQL 18)
The logout functionality uses SimpleJWT's token blacklist feature, which stores blacklisted tokens in PostgreSQL tables:

```sql
-- SimpleJWT creates these tables automatically
CREATE TABLE token_blacklist_blacklistedtoken (
    id SERIAL PRIMARY KEY,
    token_id INTEGER NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    FOREIGN KEY (token_id) REFERENCES token_blacklist_outstandingtoken(id)
);

CREATE TABLE token_blacklist_outstandingtoken (
    id SERIAL PRIMARY KEY,
    user_id INTEGER,
    jti VARCHAR(255) UNIQUE NOT NULL,
    token TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    FOREIGN KEY (user_id) REFERENCES auth_user(id)
);
```

### Blacklist Process Flow
1. **Token Validation:** Refresh token is parsed and validated
2. **Database Lookup:** Token JTI (JWT ID) is checked against outstanding tokens
3. **Blacklist Entry:** Token is added to blacklist table with timestamp
4. **Prevention:** Future use of token is blocked by SimpleJWT middleware

---

## Security Considerations

### Token Security
- **Permanent Blacklisting:** Once blacklisted, tokens cannot be removed from blacklist
- **Database Persistence:** Blacklist survives server restarts and deployments
- **JTI Uniqueness:** Each token has a unique identifier preventing replay attacks
- **Expiration Respect:** Expired tokens are automatically considered invalid

### Best Practices
1. **Always Clear Frontend Tokens:** Clear localStorage/sessionStorage regardless of API response
2. **Handle Network Errors:** Implement fallback token clearing for offline scenarios
3. **Secure Transmission:** Always use HTTPS in production
4. **Log Security Events:** Monitor logout patterns for suspicious activity

### Frontend Security Implementation
```typescript
// Secure logout with offline handling
async secureLogout(): Promise<void> {
  try {
    // Attempt API logout
    await this.authService.logout().toPromise();
  } catch (error) {
    // Log error but continue with local cleanup
    console.warn('Logout API failed, clearing local tokens:', error);
  } finally {
    // Always clear tokens locally
    this.clearAllTokens();
    this.clearUserSession();
    this.redirectToLogin();
  }
}

private clearAllTokens(): void {
  // Clear all possible token storage locations
  localStorage.removeItem('access_token');
  localStorage.removeItem('refresh_token');
  sessionStorage.removeItem('access_token');
  sessionStorage.removeItem('refresh_token');
  
  // Clear any other user-related data
  localStorage.removeItem('user_profile');
  sessionStorage.removeItem('user_preferences');
}
```

---

## Performance Considerations

### Database Optimization
- **Indexes:** JTI field is automatically indexed for fast lookups
- **Cleanup Jobs:** Implement periodic cleanup of expired blacklisted tokens
- **Connection Pooling:** Use PostgreSQL connection pooling for high-traffic scenarios

### Cleanup Script Example
```python
# Django management command to clean expired blacklisted tokens
from django.core.management.base import BaseCommand
from django.utils import timezone
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken

class Command(BaseCommand):
    help = 'Clean up expired blacklisted tokens'
    
    def handle(self, *args, **options):
        expired_tokens = BlacklistedToken.objects.filter(
            token__expires_at__lt=timezone.now()
        )
        count = expired_tokens.count()
        expired_tokens.delete()
        
        self.stdout.write(
            self.style.SUCCESS(
                f'Successfully cleaned up {count} expired tokens'
            )
        )
```

---

## Environment Configuration

### Required Settings
```python
# settings.py
SIMPLE_JWT = {
    'BLACKLIST_AFTER_ROTATION': True,
    'UPDATE_LAST_LOGIN': True,
}

# Add to INSTALLED_APPS
INSTALLED_APPS = [
    # ... other apps
    'rest_framework_simplejwt.token_blacklist',
]
```

### Database Migration
```bash
# Create blacklist tables
python manage.py migrate token_blacklist
```

---

## Related Endpoints

The logout functionality is part of a complete authentication system:

1. **User Login:** `POST /api/v1/auth/login/`
2. **Token Refresh:** `POST /api/v1/auth/token/refresh/`
3. **User Profile:** `GET /api/v1/auth/profile/`

For complete API documentation, refer to the individual endpoint documentation files.

---

*Generated for Django 5.0 + DRF 3.16.x Authentication API*  
*Last Updated: August 15, 2025*
