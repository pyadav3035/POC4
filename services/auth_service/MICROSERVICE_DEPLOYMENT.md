# Auth Service - Microservice Deployment Guide

## Overview

The Auth Service is a production-ready microservice built with Django REST Framework, implementing JWT authentication with comprehensive security measures and microservice standards.

## Security Features

### ✅ Fixed Security Issues
- **Log Injection Prevention**: All user input removed from log messages
- **Hardcoded Credentials**: Replaced with secure environment variables and secrets management
- **Path Traversal Protection**: Input validation and sanitization implemented
- **XSS Prevention**: Security headers and input validation added
- **Package Vulnerabilities**: Updated to latest secure versions

### Security Implementations
- **Rate Limiting**: Login (5 attempts/15min), Signup (3 attempts/hour)
- **Security Headers**: XSS protection, CSRF protection, HSTS, CSP
- **Secrets Management**: Encrypted storage with rotation capability
- **Input Validation**: Comprehensive validation for all endpoints
- **Secure Logging**: No sensitive data in logs, structured logging

## Microservice Standards Compliance

### ✅ Health Checks & Monitoring
- **Health Endpoint**: `/health/` - Basic service health
- **Readiness Probe**: `/ready/` - Database and dependencies check
- **Liveness Probe**: `/live/` - Service availability check
- **Metrics Endpoint**: `/metrics/` - System and application metrics

### ✅ Service Discovery
- **Service Registry**: Built-in service registration and discovery
- **Heartbeat Mechanism**: Automatic service health reporting
- **Service Location**: Dynamic service endpoint resolution

### ✅ Circuit Breaker Pattern
- **Database Protection**: Automatic failure detection and recovery
- **Retry Logic**: Exponential backoff for transient failures
- **Graceful Degradation**: Service continues operating during partial failures

### ✅ Configuration Management
- **Environment-based Config**: 12-factor app compliance
- **Secrets Management**: Encrypted secrets with secure access
- **Feature Flags**: Environment-specific configurations

### ✅ Security & Compliance
- **Authentication**: JWT with refresh token rotation
- **Authorization**: Role-based access control
- **Audit Logging**: Comprehensive security event logging
- **Data Protection**: Encrypted sensitive data storage

## Deployment Options

### Docker Deployment
```bash
# Build the image
docker build -t auth-service:latest .

# Run with environment variables
docker run -d \
  --name auth-service \
  -p 8000:8000 \
  -e DEBUG=False \
  -e DATABASE_HOST=postgres \
  -e REDIS_URL=redis://redis:6379/1 \
  auth-service:latest
```

### Kubernetes Deployment
```bash
# Apply the deployment
kubectl apply -f k8s-deployment.yaml

# Check deployment status
kubectl get pods -l app=auth-service

# View logs
kubectl logs -l app=auth-service
```

### Docker Compose (Development)
```yaml
version: '3.8'
services:
  auth-service:
    build: .
    ports:
      - "8000:8000"
    environment:
      - DEBUG=True
      - DATABASE_HOST=postgres
      - REDIS_URL=redis://redis:6379/1
    depends_on:
      - postgres
      - redis
```

## Environment Configuration

### Required Environment Variables
```bash
# Core Settings
SECRET_KEY=your-secret-key-here
DEBUG=False
ENVIRONMENT=production
ALLOWED_HOSTS=localhost,auth-service

# Database
DATABASE_NAME=auth_service_db
DATABASE_USER=postgres
DATABASE_PASSWORD=secure-password
DATABASE_HOST=postgres-service
DATABASE_PORT=5432

# Redis Cache
REDIS_URL=redis://redis-service:6379/1

# Service Discovery
SERVICE_NAME=auth_service
SERVICE_HOST=auth-service
SERVICE_PORT=8000

# Security
SECRETS_ENCRYPTION_KEY=base64-encoded-key
JWT_SECRET_KEY=jwt-signing-key

# CORS
CORS_ALLOWED_ORIGINS=http://localhost:3000,http://localhost:4200
```

## API Endpoints

### Authentication
- `POST /api/v1/auth/login/` - User login
- `POST /api/v1/auth/logout/` - User logout
- `POST /api/v1/auth/signup/` - User registration
- `GET /api/v1/auth/profile/` - Get user profile
- `PUT /api/v1/auth/profile/` - Update user profile

### Health & Monitoring
- `GET /health/` - Basic health check
- `GET /ready/` - Readiness probe
- `GET /live/` - Liveness probe
- `GET /metrics/` - Service metrics

## Management Commands

### Service Registration
```bash
python manage.py register_service
```

### Health Checks
```bash
python manage.py health_check --verbose
```

### Create Test Users
```bash
python manage.py create_test_users
```

## Monitoring & Observability

### Metrics Available
- System metrics (CPU, memory, disk)
- Database connection pool status
- Request/response times
- Error rates and types
- Circuit breaker states

### Logging
- Structured JSON logging
- Security event logging
- Performance monitoring
- Error tracking with context

### Health Check Responses
```json
{
  "status": "healthy",
  "timestamp": 1703123456.789,
  "service": "auth_service"
}
```

## Security Considerations

### Production Checklist
- [ ] Change default SECRET_KEY
- [ ] Set DEBUG=False
- [ ] Configure HTTPS/TLS
- [ ] Set up proper database credentials
- [ ] Configure Redis with authentication
- [ ] Set up log aggregation
- [ ] Configure monitoring alerts
- [ ] Review CORS settings
- [ ] Set up backup procedures
- [ ] Configure rate limiting
- [ ] Review security headers

### Network Security
- Use network policies in Kubernetes
- Restrict database access to service only
- Configure firewall rules
- Use service mesh for inter-service communication

## Scaling Considerations

### Horizontal Scaling
- Stateless design allows multiple replicas
- Database connection pooling
- Redis for shared cache/sessions
- Load balancer configuration

### Performance Optimization
- Database query optimization
- Connection pooling
- Caching strategies
- Async processing for heavy operations

## Troubleshooting

### Common Issues
1. **Database Connection**: Check DATABASE_HOST and credentials
2. **Redis Connection**: Verify REDIS_URL configuration
3. **Health Checks Failing**: Check dependencies and migrations
4. **High Memory Usage**: Review connection pool settings

### Debug Commands
```bash
# Check service health
curl http://localhost:8000/health/

# View detailed health status
python manage.py health_check --verbose

# Check database connectivity
python manage.py dbshell

# View logs
docker logs auth-service
```

## Support

For issues and questions:
1. Check the health endpoints first
2. Review application logs
3. Verify environment configuration
4. Check database and Redis connectivity