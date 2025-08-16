# Django Authentication API - Angular 18+ Integration Guide

This guide demonstrates how to integrate the Django JWT authentication API with Angular 18+ applications.

## API Endpoints Summary

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/api/v1/auth/login/` | Login with username/password | No |
| POST | `/api/v1/auth/logout/` | Logout and blacklist token | Yes |
| GET | `/api/v1/auth/profile/` | Get user profile | Yes |
| POST | `/api/v1/auth/token/refresh/` | Refresh access token | No |

## Angular Service Implementation

### 1. Authentication Service

```typescript
// auth.service.ts
import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable, BehaviorSubject, throwError } from 'rxjs';
import { map, catchError, tap } from 'rxjs/operators';

export interface LoginRequest {
  username: string;
  password: string;
}

export interface LoginResponse {
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

export interface UserData {
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

export interface ApiErrorResponse {
  success: boolean;
  message: string;
  errors: any;
}

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private readonly API_URL = 'http://localhost:8000/api/v1/auth';
  private readonly TOKEN_KEY = 'access_token';
  private readonly REFRESH_KEY = 'refresh_token';
  
  private currentUserSubject = new BehaviorSubject<UserData | null>(null);
  public currentUser$ = this.currentUserSubject.asObservable();
  
  private isAuthenticatedSubject = new BehaviorSubject<boolean>(false);
  public isAuthenticated$ = this.isAuthenticatedSubject.asObservable();

  constructor(private http: HttpClient) {
    this.checkInitialAuthState();
  }

  /**
   * Login with username and password
   */
  login(username: string, password: string): Observable<LoginResponse> {
    const loginData: LoginRequest = { username, password };
    
    return this.http.post<LoginResponse>(`${this.API_URL}/login/`, loginData)
      .pipe(
        tap(response => {
          if (response.success) {
            this.setTokens(response.data.tokens.access, response.data.tokens.refresh);
            this.currentUserSubject.next(response.data.user);
            this.isAuthenticatedSubject.next(true);
          }
        }),
        catchError(this.handleError)
      );
  }

  /**
   * Logout and blacklist refresh token
   */
  logout(): Observable<any> {
    const refreshToken = this.getRefreshToken();
    
    if (refreshToken) {
      return this.http.post(`${this.API_URL}/logout/`, { refresh: refreshToken })
        .pipe(
          tap(() => this.clearTokens()),
          catchError(error => {
            // Clear tokens even if logout request fails
            this.clearTokens();
            return throwError(error);
          })
        );
    } else {
      this.clearTokens();
      return new Observable(observer => observer.next());
    }
  }

  /**
   * Get current user profile
   */
  getUserProfile(): Observable<any> {
    return this.http.get(`${this.API_URL}/profile/`)
      .pipe(
        map((response: any) => response.data.user),
        tap(user => this.currentUserSubject.next(user)),
        catchError(this.handleError)
      );
  }

  /**
   * Refresh access token
   */
  refreshToken(): Observable<any> {
    const refreshToken = this.getRefreshToken();
    
    if (!refreshToken) {
      this.clearTokens();
      return throwError('No refresh token available');
    }

    return this.http.post(`${this.API_URL}/token/refresh/`, { refresh: refreshToken })
      .pipe(
        tap((response: any) => {
          if (response.access) {
            this.setAccessToken(response.access);
          }
        }),
        catchError(error => {
          this.clearTokens();
          return throwError(error);
        })
      );
  }

  /**
   * Get access token
   */
  getAccessToken(): string | null {
    return localStorage.getItem(this.TOKEN_KEY);
  }

  /**
   * Get refresh token
   */
  getRefreshToken(): string | null {
    return localStorage.getItem(this.REFRESH_KEY);
  }

  /**
   * Check if user is authenticated
   */
  isAuthenticated(): boolean {
    const token = this.getAccessToken();
    return !!token && !this.isTokenExpired(token);
  }

  /**
   * Check if token is expired
   */
  private isTokenExpired(token: string): boolean {
    try {
      const payload = JSON.parse(atob(token.split('.')[1]));
      const exp = payload.exp * 1000; // Convert to milliseconds
      return Date.now() >= exp;
    } catch (error) {
      return true;
    }
  }

  /**
   * Set tokens in localStorage
   */
  private setTokens(accessToken: string, refreshToken: string): void {
    localStorage.setItem(this.TOKEN_KEY, accessToken);
    localStorage.setItem(this.REFRESH_KEY, refreshToken);
  }

  /**
   * Set access token only
   */
  private setAccessToken(accessToken: string): void {
    localStorage.setItem(this.TOKEN_KEY, accessToken);
  }

  /**
   * Clear all tokens and user state
   */
  private clearTokens(): void {
    localStorage.removeItem(this.TOKEN_KEY);
    localStorage.removeItem(this.REFRESH_KEY);
    this.currentUserSubject.next(null);
    this.isAuthenticatedSubject.next(false);
  }

  /**
   * Check initial authentication state on service initialization
   */
  private checkInitialAuthState(): void {
    if (this.isAuthenticated()) {
      this.isAuthenticatedSubject.next(true);
      // Optionally fetch user profile
      this.getUserProfile().subscribe();
    }
  }

  /**
   * Handle HTTP errors
   */
  private handleError = (error: any): Observable<never> => {
    console.error('Auth Service Error:', error);
    
    if (error.status === 401) {
      this.clearTokens();
    }
    
    return throwError(error);
  };
}
```

### 2. HTTP Interceptor for JWT Tokens

```typescript
// auth.interceptor.ts
import { Injectable } from '@angular/core';
import { HttpInterceptor, HttpRequest, HttpHandler, HttpEvent, HttpErrorResponse } from '@angular/common/http';
import { Observable, throwError, BehaviorSubject } from 'rxjs';
import { catchError, switchMap, filter, take } from 'rxjs/operators';
import { AuthService } from './auth.service';

@Injectable()
export class AuthInterceptor implements HttpInterceptor {
  private isRefreshing = false;
  private refreshTokenSubject: BehaviorSubject<any> = new BehaviorSubject<any>(null);

  constructor(private authService: AuthService) {}

  intercept(request: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
    // Add auth header if we have a token
    const authRequest = this.addTokenToRequest(request);

    return next.handle(authRequest).pipe(
      catchError((error: HttpErrorResponse) => {
        if (error.status === 401 && !authRequest.url.includes('/login/')) {
          return this.handle401Error(authRequest, next);
        }
        return throwError(error);
      })
    );
  }

  private addTokenToRequest(request: HttpRequest<any>): HttpRequest<any> {
    const token = this.authService.getAccessToken();
    
    if (token) {
      return request.clone({
        setHeaders: {
          Authorization: `Bearer ${token}`
        }
      });
    }
    
    return request;
  }

  private handle401Error(request: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
    if (!this.isRefreshing) {
      this.isRefreshing = true;
      this.refreshTokenSubject.next(null);

      return this.authService.refreshToken().pipe(
        switchMap(() => {
          this.isRefreshing = false;
          this.refreshTokenSubject.next(this.authService.getAccessToken());
          return next.handle(this.addTokenToRequest(request));
        }),
        catchError((error) => {
          this.isRefreshing = false;
          this.authService.logout().subscribe();
          return throwError(error);
        })
      );
    } else {
      return this.refreshTokenSubject.pipe(
        filter(token => token != null),
        take(1),
        switchMap(() => next.handle(this.addTokenToRequest(request)))
      );
    }
  }
}
```

### 3. Login Component

```typescript
// login.component.ts
import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { Router } from '@angular/router';
import { AuthService } from '../services/auth.service';

@Component({
  selector: 'app-login',
  template: `
    <div class="login-container">
      <form [formGroup]="loginForm" (ngSubmit)="onSubmit()" class="login-form">
        <h2>Login</h2>
        
        <div class="form-group">
          <label for="username">Username</label>
          <input 
            type="text" 
            id="username"
            formControlName="username"
            [class.error]="loginForm.get('username')?.invalid && loginForm.get('username')?.touched"
            placeholder="Enter your username"
          >
          <div class="error-message" *ngIf="loginForm.get('username')?.invalid && loginForm.get('username')?.touched">
            Username is required
          </div>
        </div>

        <div class="form-group">
          <label for="password">Password</label>
          <input 
            type="password" 
            id="password"
            formControlName="password"
            [class.error]="loginForm.get('password')?.invalid && loginForm.get('password')?.touched"
            placeholder="Enter your password"
          >
          <div class="error-message" *ngIf="loginForm.get('password')?.invalid && loginForm.get('password')?.touched">
            Password is required
          </div>
        </div>

        <div class="error-message" *ngIf="errorMessage">
          {{ errorMessage }}
        </div>

        <button 
          type="submit" 
          [disabled]="loginForm.invalid || isLoading"
          class="login-button"
        >
          {{ isLoading ? 'Logging in...' : 'Login' }}
        </button>
      </form>
    </div>
  `,
  styleUrls: ['./login.component.css']
})
export class LoginComponent implements OnInit {
  loginForm: FormGroup;
  isLoading = false;
  errorMessage = '';

  constructor(
    private fb: FormBuilder,
    private authService: AuthService,
    private router: Router
  ) {
    this.loginForm = this.fb.group({
      username: ['', [Validators.required]],
      password: ['', [Validators.required]]
    });
  }

  ngOnInit(): void {
    // Redirect if already authenticated
    if (this.authService.isAuthenticated()) {
      this.router.navigate(['/dashboard']);
    }
  }

  onSubmit(): void {
    if (this.loginForm.valid) {
      this.isLoading = true;
      this.errorMessage = '';

      const { username, password } = this.loginForm.value;

      this.authService.login(username, password).subscribe({
        next: (response) => {
          this.isLoading = false;
          console.log('Login successful:', response.data.user);
          this.router.navigate(['/dashboard']);
        },
        error: (error) => {
          this.isLoading = false;
          
          if (error.error && error.error.errors) {
            this.errorMessage = error.error.message || 'Login failed';
          } else {
            this.errorMessage = 'An error occurred during login. Please try again.';
          }
          
          console.error('Login error:', error);
        }
      });
    }
  }
}
```

### 4. Auth Guard

```typescript
// auth.guard.ts
import { Injectable } from '@angular/core';
import { CanActivate, Router, ActivatedRouteSnapshot, RouterStateSnapshot } from '@angular/router';
import { Observable } from 'rxjs';
import { AuthService } from './auth.service';
import { map, take } from 'rxjs/operators';

@Injectable({
  providedIn: 'root'
})
export class AuthGuard implements CanActivate {
  constructor(
    private authService: AuthService,
    private router: Router
  ) {}

  canActivate(
    route: ActivatedRouteSnapshot,
    state: RouterStateSnapshot
  ): Observable<boolean> | Promise<boolean> | boolean {
    
    return this.authService.isAuthenticated$.pipe(
      take(1),
      map(isAuthenticated => {
        if (isAuthenticated) {
          return true;
        } else {
          this.router.navigate(['/login'], { 
            queryParams: { returnUrl: state.url } 
          });
          return false;
        }
      })
    );
  }
}
```

### 5. App Module Configuration

```typescript
// app.module.ts
import { NgModule } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';
import { HttpClientModule, HTTP_INTERCEPTORS } from '@angular/common/http';
import { ReactiveFormsModule } from '@angular/forms';

import { AppRoutingModule } from './app-routing.module';
import { AppComponent } from './app.component';
import { LoginComponent } from './components/login/login.component';
import { AuthInterceptor } from './interceptors/auth.interceptor';

@NgModule({
  declarations: [
    AppComponent,
    LoginComponent
  ],
  imports: [
    BrowserModule,
    AppRoutingModule,
    HttpClientModule,
    ReactiveFormsModule
  ],
  providers: [
    {
      provide: HTTP_INTERCEPTORS,
      useClass: AuthInterceptor,
      multi: true
    }
  ],
  bootstrap: [AppComponent]
})
export class AppModule { }
```

### 6. Example Usage in Components

```typescript
// dashboard.component.ts
import { Component, OnInit } from '@angular/core';
import { AuthService } from '../services/auth.service';

@Component({
  selector: 'app-dashboard',
  template: `
    <div class="dashboard">
      <h1>Welcome, {{ user?.first_name }} {{ user?.last_name }}!</h1>
      <p>Username: {{ user?.username }}</p>
      <p>Email: {{ user?.email }}</p>
      
      <button (click)="logout()" class="logout-button">
        Logout
      </button>
    </div>
  `
})
export class DashboardComponent implements OnInit {
  user: any;

  constructor(private authService: AuthService) {}

  ngOnInit(): void {
    this.authService.currentUser$.subscribe(user => {
      this.user = user;
    });
  }

  logout(): void {
    this.authService.logout().subscribe({
      next: () => {
        console.log('Logged out successfully');
        // Navigation will be handled by the interceptor
      },
      error: (error) => {
        console.error('Logout error:', error);
      }
    });
  }
}
```

## Error Handling

The API returns standardized error responses that Angular can easily handle:

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

## Production Considerations

1. **HTTPS**: Always use HTTPS in production
2. **CORS**: Configure Django CORS settings for your Angular domain
3. **Token Storage**: Consider using secure HTTP-only cookies instead of localStorage for enhanced security
4. **Environment Variables**: Store API URLs in Angular environment files
5. **Error Logging**: Implement proper error logging and monitoring

## Testing the Integration

1. Start the Django server: `python manage.py runserver`
2. Create test users: `python manage.py create_test_users`
3. Start Angular dev server: `ng serve`
4. Test login with: `username: testuser1`, `password: testpass123`

This integration provides a robust, production-ready authentication system that follows Angular and Django best practices.
