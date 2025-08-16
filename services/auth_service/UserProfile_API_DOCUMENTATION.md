# Django User Profile API Documentation

**Version:** 1.0  
**Base URL:** `http://127.0.0.1:8000/api/v1/auth/`  
**Framework:** Django 5.0 + Django REST Framework 3.16.x  
**Authentication:** JWT (djangorestframework-simplejwt 5.3.0)  
**Database:** PostgreSQL 18  
**Frontend Integration:** Angular 18+  

---

## Overview

The Django User Profile API provides secure user profile management functionality using JWT authentication. It allows authenticated users to retrieve and update their profile information with comprehensive validation, error handling, and PostgreSQL optimization. This endpoint is specifically optimized for Angular 18+ frontend consumption with clean JSON responses.

### Key Features
- ✅ JWT authentication required for all operations
- ✅ GET profile information for authenticated users
- ✅ PUT profile updates with comprehensive validation
- ✅ Enhanced fields (full_name, initials) for better frontend integration
- ✅ Email uniqueness validation across PostgreSQL database
- ✅ Name field validation with sanitization
- ✅ Security logging for profile access and updates
- ✅ Clean JSON responses optimized for Angular frontend

---

## User Profile Endpoints

### 1. Get User Profile

**Endpoint:** `GET /api/v1/auth/profile/`  
**Purpose:** Retrieve authenticated user's profile information  
**Authentication Required:** Yes (JWT Bearer token)

#### Request Headers
```http
Authorization: Bearer <access_token>
Content-Type: application/json
```

#### Request Body
No request body required for GET requests.

#### Successful Response (HTTP 200)
```json
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
```

**Response Field Descriptions:**
- `success` (boolean): Always `true` for successful requests
- `message` (string): Human-readable success message
- `data.user` (object): User profile information
  - `id` (integer): Unique user identifier (read-only)
  - `username` (string): User's username (read-only)
  - `email` (string): User's email address
  - `first_name` (string): User's first name
  - `last_name` (string): User's last name
  - `full_name` (string): Computed full name for display (read-only)
  - `initials` (string): Computed initials for avatar display (read-only)
  - `is_staff` (boolean): Whether user has staff privileges (read-only)
  - `is_active` (boolean): Whether user account is active (read-only)
  - `date_joined` (string): ISO 8601 timestamp of account creation (read-only)
  - `last_login` (string): ISO 8601 timestamp of last login (read-only)

#### Error Responses

##### Authentication Required (HTTP 401)
```json
{
  "detail": "Authentication credentials were not provided."
}
```

##### Invalid Token (HTTP 401)
```json
{
  "detail": "Given token not valid for any token type",
  "code": "token_not_valid",
  "messages": [
    {
      "token_class": "AccessToken",
      "token_type": "access",
      "message": "Token is invalid or expired"
    }
  ]
}
```

##### Server Error (HTTP 500)
```json
{
  "success": false,
  "message": "An error occurred while retrieving profile",
  "errors": {
    "detail": "Internal server error",
    "code": "server_error"
  }
}
```

---

### 2. Update User Profile

**Endpoint:** `PUT /api/v1/auth/profile/`  
**Purpose:** Update authenticated user's profile information  
**Authentication Required:** Yes (JWT Bearer token)

#### Request Headers
```http
Authorization: Bearer <access_token>
Content-Type: application/json
```

#### Request Body
```json
{
  "email": "newemail@example.com",
  "first_name": "Updated",
  "last_name": "Name"
}
```

**Field Specifications:**
- `email` (string, optional): User's email address
  - Must be valid email format
  - Must be unique across all users
  - Maximum length: 254 characters
- `first_name` (string, optional): User's first name
  - Maximum length: 30 characters
  - Can contain letters, spaces, and hyphens only
  - Automatically trimmed of whitespace
- `last_name` (string, optional): User's last name
  - Maximum length: 30 characters
  - Can contain letters, spaces, and hyphens only
  - Automatically trimmed of whitespace

**Note:** All fields are optional for PUT requests (partial updates supported).

#### Successful Response (HTTP 200)
```json
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
```

#### Error Responses

##### Validation Failed (HTTP 400)
```json
{
  "success": false,
  "message": "Validation failed",
  "errors": {
    "email": ["A user with this email address already exists."],
    "first_name": ["First name can only contain letters, spaces, and hyphens."]
  }
}
```

##### Invalid Email Format (HTTP 400)
```json
{
  "success": false,
  "message": "Validation failed",
  "errors": {
    "email": ["Enter a valid email address."]
  }
}
```

##### Field Length Validation (HTTP 400)
```json
{
  "success": false,
  "message": "Validation failed",
  "errors": {
    "first_name": ["First name must be 30 characters or fewer."],
    "last_name": ["Last name must be 30 characters or fewer."]
  }
}
```

##### Authentication Required (HTTP 401)
```json
{
  "detail": "Authentication credentials were not provided."
}
```

##### Server Error (HTTP 500)
```json
{
  "success": false,
  "message": "An error occurred while updating profile",
  "errors": {
    "detail": "Internal server error",
    "code": "server_error"
  }
}
```

---

## Angular 18+ Integration

### TypeScript Interface Definitions
```typescript
// Request interfaces
interface ProfileUpdateRequest {
  email?: string;
  first_name?: string;
  last_name?: string;
}

// Response interfaces
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

// Error response interface
interface ProfileError {
  success: false;
  message: string;
  errors: {
    [key: string]: string[];
  };
}

// Validation error interface for DRF errors
interface ValidationError {
  detail?: string;
  [field: string]: string[] | string | undefined;
}
```

### Angular Service Implementation
```typescript
import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable } from 'rxjs';
import { map, catchError } from 'rxjs/operators';

@Injectable({
  providedIn: 'root'
})
export class UserProfileService {
  private readonly API_BASE_URL = 'http://127.0.0.1:8000/api/v1/auth/';

  constructor(private http: HttpClient) {}

  /**
   * Get authenticated user's profile
   */
  getUserProfile(): Observable<ProfileResponse> {
    const headers = this.getAuthHeaders();
    
    return this.http.get<ProfileResponse>(
      `${this.API_BASE_URL}profile/`,
      { headers }
    );
  }

  /**
   * Update user profile with partial data
   */
  updateProfile(profileData: ProfileUpdateRequest): Observable<ProfileResponse> {
    const headers = this.getAuthHeaders();
    
    return this.http.put<ProfileResponse>(
      `${this.API_BASE_URL}profile/`,
      profileData,
      { headers }
    );
  }

  /**
   * Update specific profile field
   */
  updateProfileField(field: keyof ProfileUpdateRequest, value: string): Observable<ProfileResponse> {
    const updateData: ProfileUpdateRequest = {};
    updateData[field] = value;
    
    return this.updateProfile(updateData);
  }

  /**
   * Get authorization headers with access token
   */
  private getAuthHeaders(): HttpHeaders {
    const token = this.getAccessToken();
    
    if (!token) {
      throw new Error('No access token available');
    }

    return new HttpHeaders({
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    });
  }

  /**
   * Get stored access token
   */
  private getAccessToken(): string | null {
    return localStorage.getItem('access_token') || 
           sessionStorage.getItem('access_token');
  }
}
```

### Component Usage Example
```typescript
import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { UserProfileService } from './user-profile.service';

@Component({
  selector: 'app-user-profile',
  templateUrl: './user-profile.component.html'
})
export class UserProfileComponent implements OnInit {
  profileForm: FormGroup;
  userProfile: UserProfile | null = null;
  loading = false;
  saving = false;
  error: string | null = null;
  success: string | null = null;

  constructor(
    private fb: FormBuilder,
    private profileService: UserProfileService
  ) {
    this.profileForm = this.fb.group({
      email: ['', [Validators.email, Validators.maxLength(254)]],
      first_name: ['', [Validators.maxLength(30), this.nameValidator]],
      last_name: ['', [Validators.maxLength(30), this.nameValidator]]
    });
  }

  ngOnInit(): void {
    this.loadProfile();
  }

  /**
   * Load user profile from API
   */
  loadProfile(): void {
    this.loading = true;
    this.error = null;

    this.profileService.getUserProfile().subscribe({
      next: (response) => {
        if (response.success) {
          this.userProfile = response.data.user;
          this.populateForm(this.userProfile);
        }
        this.loading = false;
      },
      error: (errorResponse) => {
        this.loading = false;
        this.error = this.extractErrorMessage(errorResponse);
      }
    });
  }

  /**
   * Update user profile
   */
  onSubmit(): void {
    if (this.profileForm.invalid) {
      this.markFormGroupTouched();
      return;
    }

    this.saving = true;
    this.error = null;
    this.success = null;

    const formData = this.profileForm.value;
    
    // Only send changed fields
    const updatedData: ProfileUpdateRequest = {};
    Object.keys(formData).forEach(key => {
      if (formData[key] !== this.userProfile?.[key as keyof UserProfile]) {
        updatedData[key as keyof ProfileUpdateRequest] = formData[key];
      }
    });

    if (Object.keys(updatedData).length === 0) {
      this.saving = false;
      this.success = 'No changes to save.';
      return;
    }

    this.profileService.updateProfile(updatedData).subscribe({
      next: (response) => {
        if (response.success) {
          this.userProfile = response.data.user;
          this.success = response.message;
          this.populateForm(this.userProfile);
        }
        this.saving = false;
      },
      error: (errorResponse) => {
        this.saving = false;
        this.handleValidationErrors(errorResponse);
      }
    });
  }

  /**
   * Populate form with user data
   */
  private populateForm(user: UserProfile): void {
    this.profileForm.patchValue({
      email: user.email,
      first_name: user.first_name,
      last_name: user.last_name
    });
  }

  /**
   * Custom validator for name fields
   */
  private nameValidator(control: any) {
    if (!control.value) return null;
    
    const namePattern = /^[a-zA-Z\s\-]+$/;
    if (!namePattern.test(control.value)) {
      return { invalidName: true };
    }
    return null;
  }

  /**
   * Mark all form fields as touched for validation display
   */
  private markFormGroupTouched(): void {
    Object.keys(this.profileForm.controls).forEach(key => {
      this.profileForm.get(key)?.markAsTouched();
    });
  }

  /**
   * Handle validation errors from API
   */
  private handleValidationErrors(errorResponse: any): void {
    if (errorResponse.error?.errors) {
      const errors = errorResponse.error.errors;
      
      // Set form field errors
      Object.keys(errors).forEach(field => {
        const control = this.profileForm.get(field);
        if (control && Array.isArray(errors[field])) {
          control.setErrors({ serverError: errors[field][0] });
        }
      });
      
      this.error = 'Please correct the errors below.';
    } else {
      this.error = this.extractErrorMessage(errorResponse);
    }
  }

  /**
   * Extract error message from API response
   */
  private extractErrorMessage(errorResponse: any): string {
    if (errorResponse.error?.message) {
      return errorResponse.error.message;
    } else if (errorResponse.error?.detail) {
      return errorResponse.error.detail;
    } else if (errorResponse.message) {
      return errorResponse.message;
    }
    return 'An unexpected error occurred.';
  }
}
```

### HTML Template Example
```html
<!-- user-profile.component.html -->
<div class="profile-container">
  <h2>User Profile</h2>
  
  <!-- Loading indicator -->
  <div *ngIf="loading" class="loading">
    Loading profile...
  </div>
  
  <!-- Error message -->
  <div *ngIf="error" class="alert alert-danger">
    {{ error }}
  </div>
  
  <!-- Success message -->
  <div *ngIf="success" class="alert alert-success">
    {{ success }}
  </div>
  
  <!-- Profile form -->
  <form *ngIf="!loading && userProfile" [formGroup]="profileForm" (ngSubmit)="onSubmit()">
    
    <!-- Read-only user info -->
    <div class="readonly-info">
      <div class="info-row">
        <label>Username:</label>
        <span>{{ userProfile.username }}</span>
      </div>
      <div class="info-row">
        <label>User ID:</label>
        <span>{{ userProfile.id }}</span>
      </div>
      <div class="info-row">
        <label>Member since:</label>
        <span>{{ userProfile.date_joined | date:'medium' }}</span>
      </div>
    </div>
    
    <!-- Editable fields -->
    <div class="form-group">
      <label for="email">Email Address:</label>
      <input 
        type="email" 
        id="email" 
        formControlName="email" 
        class="form-control"
        [class.is-invalid]="profileForm.get('email')?.invalid && profileForm.get('email')?.touched">
      <div *ngIf="profileForm.get('email')?.invalid && profileForm.get('email')?.touched" class="invalid-feedback">
        <div *ngIf="profileForm.get('email')?.errors?.['email']">Please enter a valid email address.</div>
        <div *ngIf="profileForm.get('email')?.errors?.['serverError']">{{ profileForm.get('email')?.errors?.['serverError'] }}</div>
      </div>
    </div>
    
    <div class="form-group">
      <label for="first_name">First Name:</label>
      <input 
        type="text" 
        id="first_name" 
        formControlName="first_name" 
        class="form-control"
        [class.is-invalid]="profileForm.get('first_name')?.invalid && profileForm.get('first_name')?.touched">
      <div *ngIf="profileForm.get('first_name')?.invalid && profileForm.get('first_name')?.touched" class="invalid-feedback">
        <div *ngIf="profileForm.get('first_name')?.errors?.['maxlength']">First name must be 30 characters or fewer.</div>
        <div *ngIf="profileForm.get('first_name')?.errors?.['invalidName']">First name can only contain letters, spaces, and hyphens.</div>
        <div *ngIf="profileForm.get('first_name')?.errors?.['serverError']">{{ profileForm.get('first_name')?.errors?.['serverError'] }}</div>
      </div>
    </div>
    
    <div class="form-group">
      <label for="last_name">Last Name:</label>
      <input 
        type="text" 
        id="last_name" 
        formControlName="last_name" 
        class="form-control"
        [class.is-invalid]="profileForm.get('last_name')?.invalid && profileForm.get('last_name')?.touched">
      <div *ngIf="profileForm.get('last_name')?.invalid && profileForm.get('last_name')?.touched" class="invalid-feedback">
        <div *ngIf="profileForm.get('last_name')?.errors?.['maxlength']">Last name must be 30 characters or fewer.</div>
        <div *ngIf="profileForm.get('last_name')?.errors?.['invalidName']">Last name can only contain letters, spaces, and hyphens.</div>
        <div *ngIf="profileForm.get('last_name')?.errors?.['serverError']">{{ profileForm.get('last_name')?.errors?.['serverError'] }}</div>
      </div>
    </div>
    
    <!-- Submit button -->
    <div class="form-actions">
      <button 
        type="submit" 
        class="btn btn-primary"
        [disabled]="saving || profileForm.invalid">
        <span *ngIf="saving">Saving...</span>
        <span *ngIf="!saving">Update Profile</span>
      </button>
      
      <button 
        type="button" 
        class="btn btn-secondary"
        (click)="loadProfile()"
        [disabled]="saving">
        Reset
      </button>
    </div>
  </form>
</div>
```

---

## Testing Examples

### Using curl

#### Get Profile
```bash
# Get user profile
curl -X GET http://127.0.0.1:8000/api/v1/auth/profile/ \
  -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..." \
  -H "Content-Type: application/json"
```

#### Update Profile
```bash
# Update profile fields
curl -X PUT http://127.0.0.1:8000/api/v1/auth/profile/ \
  -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..." \
  -H "Content-Type: application/json" \
  -d '{
    "email": "newemail@example.com",
    "first_name": "Updated",
    "last_name": "Name"
  }'

# Partial update (single field)
curl -X PUT http://127.0.0.1:8000/api/v1/auth/profile/ \
  -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..." \
  -H "Content-Type: application/json" \
  -d '{
    "email": "newemail@example.com"
  }'
```

### Using Python requests
```python
import requests

# Configuration
BASE_URL = "http://127.0.0.1:8000/api/v1/auth"
ACCESS_TOKEN = "your_access_token_here"

def get_auth_headers():
    return {
        'Authorization': f'Bearer {ACCESS_TOKEN}',
        'Content-Type': 'application/json'
    }

def test_get_profile():
    """Test getting user profile"""
    response = requests.get(
        f'{BASE_URL}/profile/',
        headers=get_auth_headers()
    )
    
    if response.status_code == 200:
        data = response.json()
        user = data['data']['user']
        print(f"Profile retrieved: {user['full_name']} ({user['username']})")
        return user
    else:
        print(f"Failed to get profile: {response.json()}")
        return None

def test_update_profile():
    """Test updating user profile"""
    update_data = {
        'first_name': 'Updated',
        'last_name': 'Name',
        'email': 'updated@example.com'
    }
    
    response = requests.put(
        f'{BASE_URL}/profile/',
        json=update_data,
        headers=get_auth_headers()
    )
    
    if response.status_code == 200:
        data = response.json()
        user = data['data']['user']
        print(f"Profile updated: {user['full_name']} - {user['email']}")
        return user
    else:
        print(f"Failed to update profile: {response.json()}")
        return None

def test_validation_errors():
    """Test validation error handling"""
    invalid_data = {
        'email': 'invalid-email',
        'first_name': 'Name123!@#',  # Invalid characters
        'last_name': 'A' * 50  # Too long
    }
    
    response = requests.put(
        f'{BASE_URL}/profile/',
        json=invalid_data,
        headers=get_auth_headers()
    )
    
    print(f"Validation test status: {response.status_code}")
    print(f"Validation errors: {response.json()}")

# Run tests
if __name__ == "__main__":
    print("Testing User Profile API...")
    
    # Test getting profile
    profile = test_get_profile()
    
    if profile:
        # Test updating profile
        test_update_profile()
        
        # Test validation errors
        test_validation_errors()
```

### Complete Test Suite
```python
#!/usr/bin/env python3
"""
Comprehensive test suite for User Profile API
"""

import requests
import json
from typing import Dict, Any, Optional

class UserProfileAPITester:
    def __init__(self, base_url: str, access_token: str):
        self.base_url = base_url.rstrip('/')
        self.access_token = access_token
        self.headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }
    
    def get_profile(self) -> Optional[Dict[str, Any]]:
        """Test GET profile endpoint"""
        print("🔍 Testing GET /profile/...")
        
        response = requests.get(f"{self.base_url}/profile/", headers=self.headers)
        
        if response.status_code == 200:
            data = response.json()
            if data.get('success'):
                user = data['data']['user']
                print(f"✅ Profile retrieved: {user['full_name']} ({user['username']})")
                print(f"   Email: {user['email']}")
                print(f"   Initials: {user['initials']}")
                return user
        
        print(f"❌ GET profile failed: {response.status_code}")
        print(f"   Response: {response.json()}")
        return None
    
    def update_profile(self, update_data: Dict[str, Any]) -> bool:
        """Test PUT profile endpoint"""
        print(f"📝 Testing PUT /profile/ with data: {update_data}")
        
        response = requests.put(
            f"{self.base_url}/profile/", 
            json=update_data, 
            headers=self.headers
        )
        
        if response.status_code == 200:
            data = response.json()
            if data.get('success'):
                user = data['data']['user']
                print(f"✅ Profile updated successfully")
                print(f"   New full name: {user['full_name']}")
                print(f"   New email: {user['email']}")
                return True
        
        print(f"❌ PUT profile failed: {response.status_code}")
        print(f"   Response: {response.json()}")
        return False
    
    def test_validation_errors(self) -> bool:
        """Test validation error handling"""
        print("⚠️  Testing validation errors...")
        
        # Test invalid email
        invalid_data = {
            'email': 'not-an-email',
            'first_name': 'Test123!',  # Invalid characters
            'last_name': 'A' * 50  # Too long
        }
        
        response = requests.put(
            f"{self.base_url}/profile/", 
            json=invalid_data, 
            headers=self.headers
        )
        
        if response.status_code == 400:
            data = response.json()
            if not data.get('success') and 'errors' in data:
                print("✅ Validation errors correctly returned")
                print(f"   Errors: {data['errors']}")
                return True
        
        print(f"❌ Expected validation errors but got: {response.status_code}")
        return False
    
    def test_partial_update(self) -> bool:
        """Test partial profile updates"""
        print("🔄 Testing partial update...")
        
        # Update only email
        partial_data = {'email': f'test{hash(self.access_token) % 1000}@example.com'}
        
        response = requests.put(
            f"{self.base_url}/profile/", 
            json=partial_data, 
            headers=self.headers
        )
        
        if response.status_code == 200:
            data = response.json()
            if data.get('success'):
                user = data['data']['user']
                print(f"✅ Partial update successful")
                print(f"   Updated email: {user['email']}")
                return True
        
        print(f"❌ Partial update failed: {response.status_code}")
        return False
    
    def test_unauthorized_access(self) -> bool:
        """Test unauthorized access"""
        print("🔒 Testing unauthorized access...")
        
        # Test without token
        response = requests.get(f"{self.base_url}/profile/")
        
        if response.status_code == 401:
            print("✅ Unauthorized access correctly blocked")
            return True
        
        print(f"❌ Expected 401 but got: {response.status_code}")
        return False
    
    def run_all_tests(self) -> Dict[str, bool]:
        """Run complete test suite"""
        print("🧪 Running User Profile API Test Suite")
        print("=" * 50)
        
        results = {
            'get_profile': False,
            'update_profile': False,
            'validation_errors': False,
            'partial_update': False,
            'unauthorized_access': False
        }
        
        # Test unauthorized access first
        results['unauthorized_access'] = self.test_unauthorized_access()
        
        # Test getting profile
        original_profile = self.get_profile()
        results['get_profile'] = original_profile is not None
        
        if original_profile:
            # Test full update
            update_data = {
                'first_name': 'Updated',
                'last_name': 'Test',
                'email': 'updated@example.com'
            }
            results['update_profile'] = self.update_profile(update_data)
            
            # Test partial update
            results['partial_update'] = self.test_partial_update()
        
        # Test validation errors
        results['validation_errors'] = self.test_validation_errors()
        
        # Print summary
        print("\n📊 Test Summary")
        print("=" * 30)
        passed = sum(results.values())
        total = len(results)
        
        for test, result in results.items():
            status = "✅ PASS" if result else "❌ FAIL"
            print(f"{test:20}: {status}")
        
        print(f"\nTests passed: {passed}/{total}")
        print(f"Success rate: {(passed/total)*100:.1f}%")
        
        return results

# Usage example
if __name__ == "__main__":
    # Replace with your actual access token
    tester = UserProfileAPITester(
        base_url="http://127.0.0.1:8000/api/v1/auth",
        access_token="your_access_token_here"
    )
    
    results = tester.run_all_tests()
    
    if all(results.values()):
        print("\n🎉 All tests passed! User Profile API is working correctly.")
    else:
        print("\n⚠️  Some tests failed. Please check the API implementation.")
```

---

## Security Considerations

### Authentication & Authorization
- **JWT Token Required:** All endpoints require valid access token
- **Token Validation:** Automatic validation via DRF JWT authentication
- **User Isolation:** Users can only access/modify their own profile
- **Session Security:** No session-based authentication to prevent CSRF

### Data Validation
- **Email Uniqueness:** Prevents duplicate emails across users
- **Input Sanitization:** Name fields validated for safe characters only
- **Length Limits:** Prevents database overflow attacks
- **SQL Injection Protection:** Django ORM provides automatic protection

### Security Logging
```python
# Security events logged:
# - Profile access attempts
# - Profile update attempts  
# - Validation failures
# - Authentication failures

# Example log entries:
# INFO: User testuser1 (ID: 1) accessed profile
# INFO: User testuser1 (ID: 1) updated profile: ['email', 'first_name']
# WARNING: Profile update validation failed for user 1: {'email': ['A user with this email address already exists.']}
```

### Best Practices
1. **HTTPS Only:** Always use HTTPS in production
2. **Token Expiration:** Configure short access token lifetimes
3. **Rate Limiting:** Implement rate limiting for profile updates
4. **Input Validation:** Validate all input on both frontend and backend
5. **Error Handling:** Don't expose sensitive information in error messages

---

## Database Implementation

### PostgreSQL Schema
The User Profile API uses Django's built-in `auth_user` table:

```sql
-- Django auth_user table structure (PostgreSQL 18)
CREATE TABLE auth_user (
    id SERIAL PRIMARY KEY,
    password VARCHAR(128) NOT NULL,
    last_login TIMESTAMP WITH TIME ZONE,
    is_superuser BOOLEAN NOT NULL,
    username VARCHAR(150) UNIQUE NOT NULL,
    first_name VARCHAR(30) NOT NULL,
    last_name VARCHAR(30) NOT NULL,
    email VARCHAR(254) NOT NULL,
    is_staff BOOLEAN NOT NULL,
    is_active BOOLEAN NOT NULL,
    date_joined TIMESTAMP WITH TIME ZONE NOT NULL
);

-- Indexes for performance
CREATE INDEX auth_user_username_idx ON auth_user(username);
CREATE INDEX auth_user_email_idx ON auth_user(email);
CREATE INDEX auth_user_is_active_idx ON auth_user(is_active);
```

### Query Optimization
- **Select Only Needed Fields:** Serializer specifies exact fields
- **Database Connection Pooling:** Configured in settings.py
- **Index Usage:** Email and username fields are indexed
- **Query Logging:** Enable in development for optimization

---

## Environment Configuration

### Required Settings
```python
# settings.py - Authentication configuration
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_RENDERER_CLASSES': [
        'rest_framework.renderers.JSONRenderer',
        # No BrowsableAPIRenderer for clean JSON responses
    ],
}

# JWT Configuration
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=60),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=7),
    'UPDATE_LAST_LOGIN': True,
}

# Database Configuration for PostgreSQL 18
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'auth_service_db',
        'USER': 'postgres',
        'PASSWORD': 'your_password',
        'HOST': 'localhost',
        'PORT': '5432',
        'CONN_MAX_AGE': 600,
    }
}
```

### URL Configuration
```python
# config/urls.py
urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/v1/auth/', include('apps.users.urls')),
]

# apps/users/urls.py
urlpatterns = [
    path('login/', LoginAPIView.as_view(), name='login'),
    path('logout/', LogoutAPIView.as_view(), name='logout'),
    path('profile/', UserProfileAPIView.as_view(), name='profile'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
]
```

---

## Related Endpoints

The User Profile API is part of a complete authentication system:

1. **User Login:** `POST /api/v1/auth/login/`
2. **User Logout:** `POST /api/v1/auth/logout/`
3. **Token Refresh:** `POST /api/v1/auth/token/refresh/`

For complete API documentation, refer to the individual endpoint documentation files.

---

*Generated for Django 5.0 + DRF 3.16.x Authentication API*  
*Last Updated: August 15, 2025*
