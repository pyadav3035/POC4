# User Sign-Up API Documentation

## Overview

This document provides comprehensive documentation for the User Sign-Up API endpoint in our Django-based authentication service. The API is designed for production use with Python 3.12, Django 5.0, Django REST Framework 3.16.x, and PostgreSQL 18, optimized for Angular 18+ frontend integration.

## Table of Contents

- [API Endpoint](#api-endpoint)
- [Request Format](#request-format)
- [Response Format](#response-format)
- [Database Schema](#database-schema)
- [Frontend Integration](#frontend-integration)
- [Validation Rules](#validation-rules)
- [Error Handling](#error-handling)
- [Security Considerations](#security-considerations)
- [Testing Guide](#testing-guide)

## API Endpoint

**Endpoint:** `POST /auth/signup/`  
**Authentication:** None required (Public endpoint)  
**Content-Type:** `application/json`  
**Permissions:** `AllowAny`

## Request Format

### Required Headers
```http
Content-Type: application/json
Accept: application/json
```

### Request Body Schema

```json
{
  "username": "string (required, max 150 chars)",
  "password": "string (required, min 8 chars)",
  "confirm_password": "string (required, must match password)",
  "email": "string (required, valid email format)",
  "rank": "string (required, max 100 chars)",
  "unitname": "string (required, max 200 chars)",
  "mobileNo": "string (required, phone format with country code)",
  "personalNo": "string (required, phone format with country code)",
  "designation": "string (required, max 200 chars)",
  "phoneNo": "string (required, phone format with country code)",
  "status": "boolean (optional, default: true)"
}
```

### Example Request

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

## Response Format

### Success Response (HTTP 201 Created)

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

### Validation Error Response (HTTP 400 Bad Request)

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
    ],
    "password": [
      {
        "message": "This password is too common.",
        "code": "validation_error"
      }
    ],
    "mobileNo": [
      {
        "message": "Enter a valid mobile number with country code (e.g., +919595422695).",
        "code": "validation_error"
      }
    ]
  }
}
```

### Server Error Response (HTTP 500 Internal Server Error)

```json
{
  "success": false,
  "message": "Signup failed",
  "errors": {
    "system": [
      {
        "message": "Internal server error occurred",
        "code": "server_error"
      }
    ]
  }
}
```

## Database Schema

### Tables Involved

1. **auth_user (Django's built-in User model)**
   - `id`: Primary key (Auto-incrementing integer)
   - `username`: Unique username (VARCHAR 150)
   - `email`: Email address (VARCHAR 254)
   - `password`: Hashed password (VARCHAR 128)
   - `is_active`: Account status (BOOLEAN, default: true)
   - `date_joined`: Registration timestamp (TIMESTAMP)
   - `last_login`: Last login timestamp (TIMESTAMP, nullable)

2. **users_userprofile (Custom profile model)**
   - `id`: Primary key (UUID)
   - `user_id`: Foreign key to auth_user (One-to-One)
   - `rank`: User rank (VARCHAR 100)
   - `unitname`: Unit name (VARCHAR 200)
   - `designation`: Job designation (VARCHAR 200)
   - `mobileNo`: Mobile number (VARCHAR 20)
   - `personalNo`: Personal number (VARCHAR 20)
   - `phoneNo`: Phone number (VARCHAR 20)
   - `status`: Profile status (BOOLEAN, default: true)
   - `created_at`: Profile creation timestamp (TIMESTAMP)
   - `updated_at`: Profile update timestamp (TIMESTAMP)

### Database Indexes

```sql
-- Optimized indexes for PostgreSQL 18
CREATE INDEX idx_auth_user_username ON auth_user(username);
CREATE INDEX idx_auth_user_email ON auth_user(email);
CREATE INDEX idx_userprofile_user_id ON users_userprofile(user_id);
CREATE INDEX idx_userprofile_status ON users_userprofile(status);
CREATE INDEX idx_userprofile_rank ON users_userprofile(rank);
```

## Frontend Integration

### Angular 18+ TypeScript Integration

#### Service Implementation

```typescript
// auth.service.ts
import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable } from 'rxjs';

export interface SignUpRequest {
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

export interface SignUpResponse {
  success: boolean;
  message: string;
  data?: {
    user: {
      userId: string;
      username: string;
      email: string;
      rank: string;
      unitname: string;
      mobileNo: string;
      personalNo: string;
      designation: string;
      phoneNo: string;
      status: string;
      message: string;
    };
  };
  errors?: Record<string, Array<{
    message: string;
    code: string;
  }>>;
}

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private apiUrl = 'http://localhost:8000/auth';

  constructor(private http: HttpClient) {}

  signup(userData: SignUpRequest): Observable<SignUpResponse> {
    const headers = new HttpHeaders({
      'Content-Type': 'application/json',
      'Accept': 'application/json'
    });

    return this.http.post<SignUpResponse>(
      `${this.apiUrl}/signup/`,
      userData,
      { headers }
    );
  }
}
```

#### Component Implementation

```typescript
// signup.component.ts
import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { Router } from '@angular/router';
import { AuthService, SignUpRequest } from '../services/auth.service';

@Component({
  selector: 'app-signup',
  templateUrl: './signup.component.html',
  styleUrls: ['./signup.component.scss']
})
export class SignupComponent implements OnInit {
  signupForm: FormGroup;
  isLoading = false;
  errors: Record<string, string[]> = {};

  constructor(
    private fb: FormBuilder,
    private authService: AuthService,
    private router: Router
  ) {
    this.signupForm = this.createForm();
  }

  ngOnInit(): void {}

  private createForm(): FormGroup {
    return this.fb.group({
      username: ['', [Validators.required, Validators.maxLength(150)]],
      password: ['', [Validators.required, Validators.minLength(8)]],
      confirm_password: ['', [Validators.required]],
      email: ['', [Validators.required, Validators.email]],
      rank: ['', [Validators.required, Validators.maxLength(100)]],
      unitname: ['', [Validators.required, Validators.maxLength(200)]],
      designation: ['', [Validators.required, Validators.maxLength(200)]],
      mobileNo: ['', [Validators.required, Validators.pattern(/^\+?1?\d{9,15}$/)]],
      personalNo: ['', [Validators.required, Validators.pattern(/^\+?1?\d{9,15}$/)]],
      phoneNo: ['', [Validators.required, Validators.pattern(/^\+?1?\d{9,15}$/)]],
      status: [true]
    }, { validators: this.passwordMatchValidator });
  }

  private passwordMatchValidator(form: FormGroup) {
    const password = form.get('password');
    const confirmPassword = form.get('confirm_password');
    
    if (password && confirmPassword && password.value !== confirmPassword.value) {
      confirmPassword.setErrors({ passwordMismatch: true });
      return { passwordMismatch: true };
    }
    
    return null;
  }

  onSubmit(): void {
    if (this.signupForm.valid) {
      this.isLoading = true;
      this.errors = {};

      const signupData: SignUpRequest = this.signupForm.value;

      this.authService.signup(signupData).subscribe({
        next: (response) => {
          this.isLoading = false;
          if (response.success) {
            console.log('User created successfully:', response.data?.user);
            // Redirect to login or dashboard
            this.router.navigate(['/login']);
          }
        },
        error: (error) => {
          this.isLoading = false;
          if (error.error?.errors) {
            this.errors = this.transformErrors(error.error.errors);
          } else {
            this.errors = { general: ['An unexpected error occurred'] };
          }
        }
      });
    }
  }

  private transformErrors(apiErrors: Record<string, Array<{message: string, code: string}>>): Record<string, string[]> {
    const transformed: Record<string, string[]> = {};
    
    for (const [field, fieldErrors] of Object.entries(apiErrors)) {
      transformed[field] = fieldErrors.map(error => error.message);
    }
    
    return transformed;
  }

  getFieldError(fieldName: string): string | null {
    const fieldErrors = this.errors[fieldName];
    return fieldErrors && fieldErrors.length > 0 ? fieldErrors[0] : null;
  }
}
```

#### Template Implementation

```html
<!-- signup.component.html -->
<div class="signup-container">
  <form [formGroup]="signupForm" (ngSubmit)="onSubmit()" class="signup-form">
    <h2>Create Account</h2>

    <!-- Username Field -->
    <div class="form-group">
      <label for="username">Username</label>
      <input
        type="text"
        id="username"
        formControlName="username"
        class="form-control"
        [class.error]="getFieldError('username')"
      />
      <div class="error-message" *ngIf="getFieldError('username')">
        {{ getFieldError('username') }}
      </div>
    </div>

    <!-- Email Field -->
    <div class="form-group">
      <label for="email">Email</label>
      <input
        type="email"
        id="email"
        formControlName="email"
        class="form-control"
        [class.error]="getFieldError('email')"
      />
      <div class="error-message" *ngIf="getFieldError('email')">
        {{ getFieldError('email') }}
      </div>
    </div>

    <!-- Password Fields -->
    <div class="form-row">
      <div class="form-group">
        <label for="password">Password</label>
        <input
          type="password"
          id="password"
          formControlName="password"
          class="form-control"
          [class.error]="getFieldError('password')"
        />
        <div class="error-message" *ngIf="getFieldError('password')">
          {{ getFieldError('password') }}
        </div>
      </div>

      <div class="form-group">
        <label for="confirm_password">Confirm Password</label>
        <input
          type="password"
          id="confirm_password"
          formControlName="confirm_password"
          class="form-control"
          [class.error]="getFieldError('confirm_password')"
        />
        <div class="error-message" *ngIf="getFieldError('confirm_password')">
          {{ getFieldError('confirm_password') }}
        </div>
      </div>
    </div>

    <!-- Professional Fields -->
    <div class="form-row">
      <div class="form-group">
        <label for="rank">Rank</label>
        <input
          type="text"
          id="rank"
          formControlName="rank"
          class="form-control"
          [class.error]="getFieldError('rank')"
        />
        <div class="error-message" *ngIf="getFieldError('rank')">
          {{ getFieldError('rank') }}
        </div>
      </div>

      <div class="form-group">
        <label for="unitname">Unit Name</label>
        <input
          type="text"
          id="unitname"
          formControlName="unitname"
          class="form-control"
          [class.error]="getFieldError('unitname')"
        />
        <div class="error-message" *ngIf="getFieldError('unitname')">
          {{ getFieldError('unitname') }}
        </div>
      </div>
    </div>

    <div class="form-group">
      <label for="designation">Designation</label>
      <input
        type="text"
        id="designation"
        formControlName="designation"
        class="form-control"
        [class.error]="getFieldError('designation')"
      />
      <div class="error-message" *ngIf="getFieldError('designation')">
        {{ getFieldError('designation') }}
      </div>
    </div>

    <!-- Contact Fields -->
    <div class="form-row">
      <div class="form-group">
        <label for="mobileNo">Mobile Number</label>
        <input
          type="tel"
          id="mobileNo"
          formControlName="mobileNo"
          placeholder="+919595422695"
          class="form-control"
          [class.error]="getFieldError('mobileNo')"
        />
        <div class="error-message" *ngIf="getFieldError('mobileNo')">
          {{ getFieldError('mobileNo') }}
        </div>
      </div>

      <div class="form-group">
        <label for="personalNo">Personal Number</label>
        <input
          type="tel"
          id="personalNo"
          formControlName="personalNo"
          placeholder="+919863758455"
          class="form-control"
          [class.error]="getFieldError('personalNo')"
        />
        <div class="error-message" *ngIf="getFieldError('personalNo')">
          {{ getFieldError('personalNo') }}
        </div>
      </div>
    </div>

    <div class="form-group">
      <label for="phoneNo">Phone Number</label>
      <input
        type="tel"
        id="phoneNo"
        formControlName="phoneNo"
        placeholder="+95867816686"
        class="form-control"
        [class.error]="getFieldError('phoneNo')"
      />
      <div class="error-message" *ngIf="getFieldError('phoneNo')">
        {{ getFieldError('phoneNo') }}
      </div>
    </div>

    <!-- Status Field -->
    <div class="form-group">
      <label class="checkbox-label">
        <input
          type="checkbox"
          formControlName="status"
          class="checkbox"
        />
        Active Status
      </label>
    </div>

    <!-- Submit Button -->
    <button
      type="submit"
      [disabled]="!signupForm.valid || isLoading"
      class="btn btn-primary"
    >
      <span *ngIf="isLoading" class="spinner"></span>
      {{ isLoading ? 'Creating Account...' : 'Create Account' }}
    </button>

    <!-- General Error -->
    <div class="error-message" *ngIf="getFieldError('general')">
      {{ getFieldError('general') }}
    </div>
  </form>
</div>
```

## Validation Rules

### Field Validation

1. **Username**
   - Required field
   - Maximum 150 characters
   - Must be unique across all users
   - Alphanumeric characters and underscores allowed

2. **Password**
   - Required field
   - Minimum 8 characters
   - Must pass Django's built-in password validators:
     - Not too similar to personal information
     - Not a commonly used password
     - Not entirely numeric
     - Minimum length requirements

3. **Confirm Password**
   - Required field
   - Must exactly match the password field

4. **Email**
   - Required field
   - Must be valid email format
   - Must be unique across all users
   - Maximum 254 characters

5. **Professional Fields (rank, unitname, designation)**
   - Required fields
   - Maximum character limits as specified
   - No special validation beyond length

6. **Phone Numbers (mobileNo, personalNo, phoneNo)**
   - Required fields
   - Must match regex pattern: `^\+?1?\d{9,15}$`
   - Should include country code (recommended format: +countrycodephonenumber)

7. **Status**
   - Optional field
   - Boolean value (true/false)
   - Defaults to true if not provided

### Cross-Field Validation

- Password and confirm_password must match exactly
- Username and email uniqueness is checked at database level

## Error Handling

### Error Response Structure

All errors follow a consistent structure for frontend consumption:

```json
{
  "success": false,
  "message": "Error category description",
  "errors": {
    "field_name": [
      {
        "message": "Human-readable error message",
        "code": "machine_readable_error_code"
      }
    ]
  }
}
```

### Error Categories

1. **Validation Errors (400 Bad Request)**
   - Field-specific validation failures
   - Password mismatch
   - Invalid data formats
   - Required field missing

2. **Conflict Errors (400 Bad Request)**
   - Username already exists
   - Email already registered
   - Database integrity constraints

3. **Server Errors (500 Internal Server Error)**
   - Database connection issues
   - Unexpected system errors
   - Transaction rollback failures

### Common Error Codes

- `username_conflict`: Username already exists
- `email_conflict`: Email already registered
- `password_mismatch`: Passwords do not match
- `validation_error`: General field validation error
- `server_error`: Internal server error
- `integrity_error`: Database constraint violation

## Security Considerations

### Password Security

1. **Hashing**: Passwords are hashed using Django's built-in PBKDF2 algorithm
2. **Validation**: Django's password validators ensure strong passwords
3. **Storage**: Plain text passwords are never stored in database

### Data Protection

1. **Input Validation**: All inputs are validated and sanitized
2. **SQL Injection Prevention**: Django ORM prevents SQL injection
3. **Rate Limiting**: Implement rate limiting in production (recommended)

### Logging and Monitoring

1. **Security Logging**: Failed signup attempts are logged with IP addresses
2. **Success Logging**: Successful registrations are logged for audit
3. **Error Tracking**: System errors are logged for debugging

### Recommended Security Headers

```python
# Django settings for production
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
```

## Testing Guide

### Unit Testing with pytest

```python
# test_signup_api.py
import pytest
from django.test import TestCase
from django.contrib.auth.models import User
from rest_framework.test import APIClient
from rest_framework import status
from apps.users.models import UserProfile

class SignUpAPITestCase(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.signup_url = '/auth/signup/'
        self.valid_data = {
            'username': 'testuser',
            'password': 'StrongPassw0rd!',
            'confirm_password': 'StrongPassw0rd!',
            'email': 'test@example.com',
            'rank': 'Officer1',
            'unitname': 'IGD',
            'mobileNo': '+919595422695',
            'personalNo': '+919863758455',
            'designation': 'sr eng',
            'phoneNo': '+95867816686',
            'status': True
        }

    def test_successful_signup(self):
        """Test successful user registration"""
        response = self.client.post(self.signup_url, self.valid_data)
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(response.data['success'])
        self.assertIn('data', response.data)
        self.assertIn('user', response.data['data'])
        
        # Verify user created in database
        user = User.objects.get(username='testuser')
        self.assertEqual(user.email, 'test@example.com')
        
        # Verify profile created
        profile = UserProfile.objects.get(user=user)
        self.assertEqual(profile.rank, 'Officer1')

    def test_duplicate_username(self):
        """Test signup with existing username"""
        # Create initial user
        User.objects.create_user(
            username='testuser',
            email='existing@example.com',
            password='password123'
        )
        
        response = self.client.post(self.signup_url, self.valid_data)
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data['success'])
        self.assertIn('username', response.data['errors'])

    def test_password_mismatch(self):
        """Test signup with mismatched passwords"""
        invalid_data = self.valid_data.copy()
        invalid_data['confirm_password'] = 'DifferentPassword!'
        
        response = self.client.post(self.signup_url, invalid_data)
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('confirm_password', response.data['errors'])

    def test_invalid_email_format(self):
        """Test signup with invalid email"""
        invalid_data = self.valid_data.copy()
        invalid_data['email'] = 'invalid-email'
        
        response = self.client.post(self.signup_url, invalid_data)
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('email', response.data['errors'])

    def test_invalid_phone_format(self):
        """Test signup with invalid phone number"""
        invalid_data = self.valid_data.copy()
        invalid_data['mobileNo'] = 'invalid-phone'
        
        response = self.client.post(self.signup_url, invalid_data)
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('mobileNo', response.data['errors'])

    def test_missing_required_fields(self):
        """Test signup with missing required fields"""
        incomplete_data = {
            'username': 'testuser',
            'password': 'StrongPassw0rd!'
            # Missing other required fields
        }
        
        response = self.client.post(self.signup_url, incomplete_data)
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('errors', response.data)

# Run tests with: python manage.py test apps.users.tests.test_signup_api
```

### Integration Testing with Postman

```json
{
  "info": {
    "name": "User SignUp API Tests",
    "description": "Test suite for user registration endpoint"
  },
  "item": [
    {
      "name": "Successful SignUp",
      "request": {
        "method": "POST",
        "header": [
          {
            "key": "Content-Type",
            "value": "application/json"
          }
        ],
        "body": {
          "mode": "raw",
          "raw": "{\n  \"username\": \"john.doe\",\n  \"password\": \"StrongPassw0rd!\",\n  \"confirm_password\": \"StrongPassw0rd!\",\n  \"email\": \"john.doe@example.com\",\n  \"rank\": \"Officer1\",\n  \"unitname\": \"IGD\",\n  \"mobileNo\": \"+919595422695\",\n  \"personalNo\": \"+919863758455\",\n  \"designation\": \"sr eng\",\n  \"phoneNo\": \"+95867816686\",\n  \"status\": true\n}"
        },
        "url": {
          "raw": "{{base_url}}/auth/signup/",
          "host": ["{{base_url}}"],
          "path": ["auth", "signup", ""]
        }
      },
      "event": [
        {
          "listen": "test",
          "script": {
            "exec": [
              "pm.test(\"Status code is 201\", function () {",
              "    pm.response.to.have.status(201);",
              "});",
              "",
              "pm.test(\"Response has success true\", function () {",
              "    const jsonData = pm.response.json();",
              "    pm.expect(jsonData.success).to.be.true;",
              "});",
              "",
              "pm.test(\"Response contains user data\", function () {",
              "    const jsonData = pm.response.json();",
              "    pm.expect(jsonData.data).to.have.property('user');",
              "    pm.expect(jsonData.data.user).to.have.property('userId');",
              "    pm.expect(jsonData.data.user).to.have.property('username');",
              "});"
            ]
          }
        }
      ]
    },
    {
      "name": "Duplicate Username Error",
      "request": {
        "method": "POST",
        "header": [
          {
            "key": "Content-Type",
            "value": "application/json"
          }
        ],
        "body": {
          "mode": "raw",
          "raw": "{\n  \"username\": \"john.doe\",\n  \"password\": \"AnotherPassword!\",\n  \"confirm_password\": \"AnotherPassword!\",\n  \"email\": \"different@example.com\",\n  \"rank\": \"Officer2\",\n  \"unitname\": \"IGD\",\n  \"mobileNo\": \"+919595422696\",\n  \"personalNo\": \"+919863758456\",\n  \"designation\": \"sr eng\",\n  \"phoneNo\": \"+95867816687\",\n  \"status\": true\n}"
        },
        "url": {
          "raw": "{{base_url}}/auth/signup/",
          "host": ["{{base_url}}"],
          "path": ["auth", "signup", ""]
        }
      },
      "event": [
        {
          "listen": "test",
          "script": {
            "exec": [
              "pm.test(\"Status code is 400\", function () {",
              "    pm.response.to.have.status(400);",
              "});",
              "",
              "pm.test(\"Response has success false\", function () {",
              "    const jsonData = pm.response.json();",
              "    pm.expect(jsonData.success).to.be.false;",
              "});",
              "",
              "pm.test(\"Response contains username error\", function () {",
              "    const jsonData = pm.response.json();",
              "    pm.expect(jsonData.errors).to.have.property('username');",
              "});"
            ]
          }
        }
      ]
    }
  ]
}
```

### Load Testing Recommendations

1. **Apache Bench (ab) Example**:
   ```bash
   ab -n 1000 -c 10 -p signup_payload.json -T application/json http://localhost:8000/auth/signup/
   ```

2. **Performance Benchmarks**:
   - Target: < 500ms response time for 95% of requests
   - Throughput: Handle 100+ concurrent signups
   - Database: Optimize with proper indexing

## Production Deployment Notes

### Environment Variables

```bash
# Required environment variables
DJANGO_SECRET_KEY=your-secret-key-here
DATABASE_URL=postgresql://user:pass@localhost:5432/dbname
DEBUG=False
ALLOWED_HOSTS=yourdomain.com,www.yourdomain.com

# Email configuration for notifications
EMAIL_HOST=smtp.yourmailprovider.com
EMAIL_PORT=587
EMAIL_HOST_USER=your-email@yourdomain.com
EMAIL_HOST_PASSWORD=your-email-password
EMAIL_USE_TLS=True
```

### Database Migrations

```bash
# Apply migrations for UserProfile model
python manage.py makemigrations users
python manage.py migrate

# Create database indexes for performance
python manage.py dbshell
```

### Monitoring and Alerts

1. **Set up monitoring for**:
   - Failed signup attempts (potential attacks)
   - High error rates
   - Database connection issues
   - Response time degradation

2. **Logging configuration**:
   ```python
   LOGGING = {
       'version': 1,
       'handlers': {
           'file': {
               'level': 'INFO',
               'class': 'logging.FileHandler',
               'filename': 'signup_api.log',
           },
       },
       'loggers': {
           'apps.users.views': {
               'handlers': ['file'],
               'level': 'INFO',
           },
       },
   }
   ```

---

**Document Version:** 1.0  
**Last Updated:** January 2025  
**API Version:** v1  
**Django Version:** 5.0  
**DRF Version:** 3.16.x  
**Python Version:** 3.12  
**PostgreSQL Version:** 18
