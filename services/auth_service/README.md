# Django Authentication Service

A production-ready authentication service built with Django 5.0, Django REST Framework 3.16.x, and JWT authentication using SimpleJWT.

## Features

- **JWT Authentication**: Secure token-based authentication using `djangorestframework-simplejwt`
- **Email-based Login**: Users can login using their email address and password
- **Django User Model**: Utilizes Django's built-in User model with proper ORM queries
- **Production Ready**: Comprehensive error handling, logging, and security configurations
- **RESTful API**: Clean, well-documented API endpoints following DRF best practices
- **Comprehensive Testing**: Full test coverage for all authentication endpoints

## API Endpoints

### Authentication Endpoints

| Method | Endpoint | Description | Authentication Required |
|--------|----------|-------------|-------------------------|
| POST | `/api/v1/auth/login/` | User login with email/password | No |
| POST | `/api/v1/auth/logout/` | User logout (blacklist refresh token) | Yes |
| GET | `/api/v1/auth/profile/` | Get authenticated user profile | Yes |
| POST | `/api/v1/auth/token/refresh/` | Refresh access token | No (requires refresh token) |

## Installation & Setup

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Environment Configuration

Copy the example environment file and configure your settings:

```bash
cp .env.example .env
```

Edit `.env` with your configuration:

```env
SECRET_KEY=your-very-secure-secret-key-here
DEBUG=False
ALLOWED_HOSTS=yourdomain.com,localhost
ACCESS_TOKEN_LIFETIME_MINUTES=60
REFRESH_TOKEN_LIFETIME_DAYS=7
```

### 3. Database Setup

```bash
python manage.py makemigrations
python manage.py migrate
```

### 4. Create Superuser

```bash
python manage.py createsuperuser
```

### 5. Run Development Server

```bash
python manage.py runserver
```

## API Usage Examples

### 1. User Login

**Request:**
```http
POST /api/v1/auth/login/
Content-Type: application/json

{
    "email": "user@example.com",
    "password": "secure_password"
}
```

**Success Response (200):**
```json
{
    "success": true,
    "message": "Login successful",
    "data": {
        "user": {
            "id": 1,
            "username": "johndoe",
            "email": "user@example.com",
            "first_name": "John",
            "last_name": "Doe",
            "is_staff": false,
            "date_joined": "2024-01-01T12:00:00Z",
            "last_login": "2024-01-15T10:30:00Z"
        },
        "tokens": {
            "access": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
            "refresh": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
        }
    }
}
```

**Error Response (400):**
```json
{
    "success": false,
    "message": "Invalid credentials",
    "errors": {
        "non_field_errors": ["Invalid credentials. Please check your email and password."]
    }
}
```

### 2. Access Protected Endpoints

For protected endpoints, include the access token in the Authorization header:

```http
GET /api/v1/auth/profile/
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
```

### 3. Refresh Access Token

**Request:**
```http
POST /api/v1/auth/token/refresh/
Content-Type: application/json

{
    "refresh": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
}
```

**Response:**
```json
{
    "access": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
}
```

### 4. User Logout

**Request:**
```http
POST /api/v1/auth/logout/
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
Content-Type: application/json

{
    "refresh": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
}
```

**Response:**
```json
{
    "success": true,
    "message": "Logout successful"
}
```

## Frontend Integration Example

### JavaScript/Fetch API

```javascript
// Login function
async function login(email, password) {
    try {
        const response = await fetch('/api/v1/auth/login/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ email, password })
        });
        
        const data = await response.json();
        
        if (data.success) {
            // Store tokens
            localStorage.setItem('access_token', data.data.tokens.access);
            localStorage.setItem('refresh_token', data.data.tokens.refresh);
            
            console.log('Login successful:', data.data.user);
            return data.data;
        } else {
            console.error('Login failed:', data.errors);
            throw new Error(data.message);
        }
    } catch (error) {
        console.error('Login error:', error);
        throw error;
    }
}

// Make authenticated requests
async function makeAuthenticatedRequest(url, options = {}) {
    const accessToken = localStorage.getItem('access_token');
    
    const headers = {
        'Content-Type': 'application/json',
        ...options.headers
    };
    
    if (accessToken) {
        headers['Authorization'] = `Bearer ${accessToken}`;
    }
    
    try {
        const response = await fetch(url, {
            ...options,
            headers
        });
        
        if (response.status === 401) {
            // Token might be expired, try to refresh
            await refreshToken();
            // Retry the request with new token
            return makeAuthenticatedRequest(url, options);
        }
        
        return response;
    } catch (error) {
        console.error('Request error:', error);
        throw error;
    }
}

// Refresh token function
async function refreshToken() {
    const refreshToken = localStorage.getItem('refresh_token');
    
    if (!refreshToken) {
        throw new Error('No refresh token available');
    }
    
    try {
        const response = await fetch('/api/v1/auth/token/refresh/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ refresh: refreshToken })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            localStorage.setItem('access_token', data.access);
            return data.access;
        } else {
            // Refresh token is invalid, redirect to login
            localStorage.removeItem('access_token');
            localStorage.removeItem('refresh_token');
            window.location.href = '/login';
        }
    } catch (error) {
        console.error('Token refresh error:', error);
        throw error;
    }
}
```

### Python Requests Example

```python
import requests

class AuthClient:
    def __init__(self, base_url):
        self.base_url = base_url
        self.access_token = None
        self.refresh_token = None
    
    def login(self, email, password):
        """Login and store tokens."""
        url = f"{self.base_url}/api/v1/auth/login/"
        data = {"email": email, "password": password}
        
        response = requests.post(url, json=data)
        response.raise_for_status()
        
        result = response.json()
        if result['success']:
            tokens = result['data']['tokens']
            self.access_token = tokens['access']
            self.refresh_token = tokens['refresh']
            return result['data']['user']
        else:
            raise Exception(f"Login failed: {result['message']}")
    
    def make_authenticated_request(self, method, endpoint, **kwargs):
        """Make authenticated request with automatic token refresh."""
        url = f"{self.base_url}{endpoint}"
        headers = kwargs.get('headers', {})
        
        if self.access_token:
            headers['Authorization'] = f"Bearer {self.access_token}"
        
        kwargs['headers'] = headers
        response = requests.request(method, url, **kwargs)
        
        if response.status_code == 401:
            # Try to refresh token
            self.refresh_access_token()
            headers['Authorization'] = f"Bearer {self.access_token}"
            response = requests.request(method, url, **kwargs)
        
        return response
    
    def refresh_access_token(self):
        """Refresh the access token."""
        if not self.refresh_token:
            raise Exception("No refresh token available")
        
        url = f"{self.base_url}/api/v1/auth/token/refresh/"
        data = {"refresh": self.refresh_token}
        
        response = requests.post(url, json=data)
        response.raise_for_status()
        
        result = response.json()
        self.access_token = result['access']
    
    def logout(self):
        """Logout and clear tokens."""
        if self.refresh_token:
            url = f"{self.base_url}/api/v1/auth/logout/"
            data = {"refresh": self.refresh_token}
            headers = {}
            
            if self.access_token:
                headers['Authorization'] = f"Bearer {self.access_token}"
            
            requests.post(url, json=data, headers=headers)
        
        self.access_token = None
        self.refresh_token = None

# Usage example
client = AuthClient("http://localhost:8000")

# Login
user_data = client.login("user@example.com", "password")
print(f"Logged in as: {user_data['email']}")

# Make authenticated request
response = client.make_authenticated_request("GET", "/api/v1/auth/profile/")
profile_data = response.json()
print(f"Profile: {profile_data}")

# Logout
client.logout()
```

## Running Tests

```bash
# Run all tests
python manage.py test

# Run tests with coverage
pip install coverage
coverage run --source='.' manage.py test
coverage report
coverage html  # Generate HTML coverage report
```

## Security Considerations

### Production Settings

1. **Environment Variables**: Never commit sensitive data like `SECRET_KEY` to version control
2. **HTTPS Only**: Always use HTTPS in production
3. **Database Security**: Use strong database credentials and restrict access
4. **Token Security**: Configure appropriate token lifetimes
5. **CORS**: Configure CORS settings properly for your frontend domain

### Security Headers

The settings include security headers for production:

- `SECURE_BROWSER_XSS_FILTER`
- `SECURE_CONTENT_TYPE_NOSNIFF`
- `SECURE_HSTS_INCLUDE_SUBDOMAINS`
- `SECURE_SSL_REDIRECT`
- `SESSION_COOKIE_SECURE`
- `CSRF_COOKIE_SECURE`

## Monitoring & Logging

The application includes comprehensive logging:

- Authentication attempts (success/failure)
- Error tracking
- User activities
- IP address logging for security

Logs are stored in `logs/django.log` and can be integrated with log aggregation systems like ELK stack or Splunk.

## API Documentation

For interactive API documentation, you can integrate tools like:

- **Django REST Framework Browsable API**: Built-in API browser
- **drf-spectacular**: OpenAPI 3.0 schema generation
- **Swagger UI**: Interactive API documentation

## Contributing

1. Follow Django coding standards
2. Write tests for new features
3. Update documentation
4. Use proper commit messages
5. Create pull requests for review

## License

This project is licensed under the MIT License.
