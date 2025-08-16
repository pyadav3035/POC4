# Django Authentication API Documentation

**Version:** 1.0  
**Base URL:** `http://127.0.0.1:8000/api/v1/auth/`  
**Framework:** Django 5.0 + Django REST Framework 3.16.x  
**Authentication:** JWT (djangorestframework-simplejwt 5.3.0)  
**Database:** PostgreSQL 18  
**Frontend Integration:** Angular 18+  

---

## Overview

The Django Authentication API provides secure user authentication using JWT tokens. It's specifically optimized for Angular 18+ frontend consumption with clean JSON responses and no browsable HTML interface.

### Key Features
- ✅ Username-based authentication with PostgreSQL backend
- ✅ JWT access and refresh token generation using SimpleJWT
- ✅ Secure password validation using Django's built-in authentication
- ✅ Client IP logging for security monitoring
- ✅ Clean JSON responses optimized for Angular frontend
- ✅ Comprehensive error handling with standardized error codes

---

## Authentication Endpoints

### 1. User Login

**Endpoint:** `POST /api/v1/auth/login/`  
**Purpose:** Authenticate user credentials and return JWT tokens  
**Authentication Required:** No (Public endpoint)

#### Request Headers
```http
Content-Type: application/json
```

#### Request Body
```json
{
  "username": "string",
  "password": "string"
}
```

**Field Specifications:**
- `username` (string, required): User's unique username
  - Maximum length: 150 characters
  - Cannot be blank
- `password` (string, required): User's password
  - Write-only field for security
  - Cannot be blank

#### Successful Response (HTTP 200)
```json
{
  "success": true,
  "message": "Login successful",
  "data": {
    "user": {
      "id": 1,
      "username": "testuser1",
      "email": "testuser1@example.com",
      "first_name": "Test",
      "last_name": "User",
      "is_staff": false,
      "is_active": true,
      "date_joined": "2025-01-01T12:00:00Z",
      "last_login": "2025-08-15T13:45:30Z"
    },
    "tokens": {
      "access": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ0b2tlbl90eXBlIjoiYWNjZXNzIiwiZXhwIjoxNzI0NTg2MzAwLCJpYXQiOjE3MjQ1ODYwMDAsImp0aSI6IjEyMzQ1Njc4IiwidXNlcl9pZCI6MX0.ABC123",
      "refresh": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ0b2tlbl90eXBlIjoicmVmcmVzaCIsImV4cCI6MTcyNTE5MDgwMCwiaWF0IjoxNzI0NTg2MDAwLCJqdGkiOiI4NzY1NDMyMSIsInVzZXJfaWQiOjF9.XYZ789"
    }
  }
}
```

**Response Field Descriptions:**
- `success` (boolean): Indicates if the operation was successful
- `message` (string): Human-readable success message
- `data.user` (object): User profile information
  - `id` (integer): Unique user identifier
  - `username` (string): User's username
  - `email` (string): User's email address
  - `first_name` (string): User's first name
  - `last_name` (string): User's last name
  - `is_staff` (boolean): Whether user has staff privileges
  - `is_active` (boolean): Whether user account is active
  - `date_joined` (string): ISO 8601 timestamp of account creation
  - `last_login` (string): ISO 8601 timestamp of last login
- `data.tokens` (object): JWT token pair
  - `access` (string): Short-lived access token (default: 5 minutes)
  - `refresh` (string): Long-lived refresh token (default: 1 day)

#### Error Responses

##### Invalid Credentials (HTTP 400)
```json
{
  "success": false,
  "message": "Authentication failed",
  "errors": {
    "detail": "Invalid credentials. Please check your username and password.",
    "code": "invalid_credentials"
  }
}
```

##### Missing Required Fields (HTTP 400)
```json
{
  "success": false,
  "message": "Authentication failed",
  "errors": {
    "username": ["Username is required."],
    "password": ["Password is required."]
  }
}
```

##### Invalid Field Values (HTTP 400)
```json
{
  "success": false,
  "message": "Authentication failed",
  "errors": {
    "username": ["Username must be 150 characters or fewer."]
  }
}
```

##### Inactive User Account (HTTP 400)
```json
{
  "success": false,
  "message": "Authentication failed",
  "errors": {
    "detail": "User account is inactive. Please contact administrator.",
    "code": "inactive_account"
  }
}
```

##### Server Error (HTTP 500)
```json
{
  "success": false,
  "message": "An error occurred during authentication",
  "errors": {
    "detail": "Internal server error",
    "code": "server_error"
  }
}
```

#### Security Features
- Client IP address logging for failed authentication attempts
- Input sanitization to prevent log injection attacks
- Secure password handling (write-only field)
- Automatic last_login timestamp update on successful authentication

---

## Angular 18+ Integration

### TypeScript Interface Definitions
```typescript
// Request interface
interface LoginRequest {
  username: string;
  password: string;
}

// Response interface
interface LoginResponse {
  success: boolean;
  message: string;
  data: {
    user: UserData;
    tokens: TokenPair;
  };
}

interface UserData {
  id: number;
  username: string;
  email: string;
  first_name: string;
  last_name: string;
  is_staff: boolean;
  is_active: boolean;
  date_joined: string;
  last_login: string;
}

interface TokenPair {
  access: string;
  refresh: string;
}

// Error response interface
interface LoginError {
  success: false;
  message: string;
  errors: {
    [key: string]: string[] | string;
    detail?: string;
    code?: string;
  };
}
```

### Angular Service Implementation
```typescript
import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private readonly API_BASE_URL = 'http://127.0.0.1:8000/api/v1/auth/';

  constructor(private http: HttpClient) {}

  /**
   * Authenticate user with username and password
   */
  login(username: string, password: string): Observable<LoginResponse> {
    const loginData: LoginRequest = { username, password };
    
    const headers = new HttpHeaders({
      'Content-Type': 'application/json'
    });

    return this.http.post<LoginResponse>(
      `${this.API_BASE_URL}login/`,
      loginData,
      { headers }
    );
  }

  /**
   * Store tokens in browser storage
   */
  storeTokens(tokens: TokenPair): void {
    localStorage.setItem('access_token', tokens.access);
    localStorage.setItem('refresh_token', tokens.refresh);
  }

  /**
   * Get stored access token
   */
  getAccessToken(): string | null {
    return localStorage.getItem('access_token');
  }

  /**
   * Get stored refresh token
   */
  getRefreshToken(): string | null {
    return localStorage.getItem('refresh_token');
  }
}
```

### Component Usage Example
```typescript
import { Component } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { Router } from '@angular/router';
import { AuthService } from './auth.service';

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html'
})
export class LoginComponent {
  loginForm: FormGroup;
  loading = false;
  error: string | null = null;

  constructor(
    private fb: FormBuilder,
    private authService: AuthService,
    private router: Router
  ) {
    this.loginForm = this.fb.group({
      username: ['', [Validators.required, Validators.maxLength(150)]],
      password: ['', Validators.required]
    });
  }

  onSubmit(): void {
    if (this.loginForm.invalid) {
      return;
    }

    this.loading = true;
    this.error = null;

    const { username, password } = this.loginForm.value;

    this.authService.login(username, password).subscribe({
      next: (response) => {
        if (response.success) {
          // Store tokens
          this.authService.storeTokens(response.data.tokens);
          
          // Redirect to dashboard
          this.router.navigate(['/dashboard']);
        }
        this.loading = false;
      },
      error: (errorResponse) => {
        this.loading = false;
        
        if (errorResponse.error?.errors?.detail) {
          this.error = errorResponse.error.errors.detail;
        } else {
          this.error = 'Login failed. Please try again.';
        }
      }
    });
  }
}
```

---

## Testing Examples

### Using curl
```bash
# Successful login
curl -X POST http://127.0.0.1:8000/api/v1/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser1",
    "password": "testpass123"
  }'

# Invalid credentials
curl -X POST http://127.0.0.1:8000/api/v1/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{
    "username": "invaliduser",
    "password": "wrongpassword"
  }'
```

### Using Python requests
```python
import requests

# Successful login
response = requests.post(
    'http://127.0.0.1:8000/api/v1/auth/login/',
    json={
        'username': 'testuser1',
        'password': 'testpass123'
    },
    headers={'Content-Type': 'application/json'}
)

if response.status_code == 200:
    data = response.json()
    access_token = data['data']['tokens']['access']
    print(f"Login successful. Access token: {access_token[:50]}...")
else:
    print(f"Login failed: {response.json()}")
```

---

## Related Endpoints

The authentication system also provides these complementary endpoints:

1. **Token Refresh:** `POST /api/v1/auth/token/refresh/`
2. **User Logout:** `POST /api/v1/auth/logout/`
3. **User Profile:** `GET /api/v1/auth/profile/`

For complete API documentation, refer to the individual endpoint documentation files.

---

## Technical Implementation Details

### Database Schema (PostgreSQL 18)
- Uses Django's built-in `auth_user` table
- Username field: `VARCHAR(150)` with unique constraint
- Password field: Hashed using Django's PBKDF2 algorithm
- Additional fields: email, first_name, last_name, is_active, is_staff, date_joined, last_login

### JWT Token Configuration
- **Access Token Lifetime:** 5 minutes (configurable)
- **Refresh Token Lifetime:** 1 day (configurable)
- **Algorithm:** HS256
- **Token Type:** Bearer

### Security Considerations
- Passwords are never stored in plain text
- Client IP addresses are logged for security monitoring
- Input validation prevents common injection attacks
- Failed login attempts are logged for security analysis
- Tokens should be transmitted over HTTPS in production

---

## Environment Configuration

### Required Environment Variables
```bash
# Database Configuration
DB_NAME=auth_service_db
DB_USER=postgres
DB_PASSWORD=your_secure_password
DB_HOST=localhost
DB_PORT=5432

# Django Security
SECRET_KEY=your_secret_key_here
DEBUG=False
ALLOWED_HOSTS=127.0.0.1,localhost

# JWT Configuration (Optional - uses defaults if not set)
ACCESS_TOKEN_LIFETIME=5  # minutes
REFRESH_TOKEN_LIFETIME=1440  # minutes (24 hours)
```

---

*Generated for Django 5.0 + DRF 3.16.x Authentication API*  
*Last Updated: August 15, 2025*
