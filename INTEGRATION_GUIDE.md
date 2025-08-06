# Auth Service Integration Guide

This guide explains how to integrate your applications with the centralized auth
service.

## Overview

The auth service provides centralized authentication for multiple applications.
Each service can validate JWT tokens locally without HTTP calls for better
security and performance.

## Quick Start

### 1. Environment Setup

Add these environment variables to your application:

```env
AUTH_SERVICE_URL=https://your-auth-service.com
AUTH_SERVICE_NAME=your-app-name
JWT_SECRET=your-shared-jwt-secret
```

**⚠️ Security Note:** The JWT_SECRET must be identical across all services for
local validation to work.

### 2. Install Dependencies

```bash
npm install axios jsonwebtoken
```

### 3. Install Auth Client

```bash
# From your authwapi project directory
npm run install-client /path/to/your/app
```

### 4. Basic Integration (Local Validation)

```javascript
const { AuthClient } = require('./utils/authClient');

const authClient = new AuthClient({
  authServiceUrl: process.env.AUTH_SERVICE_URL,
  serviceName: process.env.AUTH_SERVICE_NAME,
  jwtSecret: process.env.JWT_SECRET,
});

// Validate token locally (no HTTP call)
const validation = await authClient.validateTokenLocally(token);
if (validation.valid) {
  console.log('User:', validation.user);
}
```

## Security Best Practices

### 1. Local JWT Validation (Recommended)

Use local validation to avoid HTTP calls:

```javascript
// Fast and secure - no network calls
const validation = await authClient.validateTokenLocally(token);
```

**Benefits:**

- ✅ No network latency
- ✅ Works offline
- ✅ More secure (no secrets over HTTP)
- ✅ Better performance

### 2. Environment-Based Secret Management

```env
# Use the same JWT_SECRET across all services
JWT_SECRET=your-super-secure-256-bit-secret-key
```

### 3. Service-Specific Tokens

```javascript
// Create service-specific tokens
const token = authClient.createToken(userId, 'service-name', ['read', 'write']);
```

## API Endpoints

### Authentication Endpoints

| Endpoint                      | Method | Description              |
| ----------------------------- | ------ | ------------------------ |
| `/api/v1/auth/login`          | POST   | User login               |
| `/api/v1/auth/register`       | POST   | User registration        |
| `/api/v1/auth/validate-token` | POST   | Validate JWT token       |
| `/api/v1/auth/service-login`  | POST   | Service-to-service login |
| `/api/v1/auth/user-info`      | GET    | Get user information     |

### Request Examples

#### Validate Token (HTTP - Fallback)

```javascript
POST /api/v1/auth/validate-token
Content-Type: application/json

{
  "token": "your-jwt-token",
  "service": "your-service-name"
}
```

Response:

```json
{
  "valid": true,
  "user": {
    "id": "user-id",
    "email": "user@example.com",
    "username": "username",
    "firstName": "John",
    "lastName": "Doe",
    "service": "your-service-name",
    "permissions": ["read", "write"]
  }
}
```

#### Service Login

```javascript
POST /api/v1/auth/service-login
Content-Type: application/json

{
  "username": "user@example.com",
  "password": "password",
  "service": "your-service-name",
  "permissions": ["read", "write"]
}
```

## Express.js Middleware

### Local Validation (Recommended)

```javascript
const express = require('express');
const { AuthClient } = require('./utils/authClient');

const app = express();
const authClient = new AuthClient({
  authServiceUrl: process.env.AUTH_SERVICE_URL,
  serviceName: process.env.AUTH_SERVICE_NAME,
  jwtSecret: process.env.JWT_SECRET,
});

// Protected route with local validation
app.get('/protected', authClient.createAuthMiddleware(true), (req, res) => {
  res.json({ user: req.user });
});
```

### HTTP Validation (Fallback)

```javascript
// Use HTTP validation if needed
app.get('/protected', authClient.createAuthMiddleware(false), (req, res) => {
  res.json({ user: req.user });
});
```

## Error Handling

The auth service returns standard HTTP status codes:

- `200`: Success
- `400`: Bad Request (missing parameters)
- `401`: Unauthorized (invalid token)
- `403`: Forbidden (token not valid for this service)
- `404`: Not Found (user not found)
- `500`: Internal Server Error

## Security Considerations

1. **JWT Secret**: Use the same JWT secret across all services
2. **HTTPS**: Always use HTTPS in production
3. **Token Expiration**: Tokens expire after 30 days by default
4. **Service Validation**: Tokens can be restricted to specific services
5. **Rate Limiting**: The auth service implements rate limiting
6. **Local Validation**: Prefer local validation over HTTP calls
7. **Secret Management**: Use secure secret management (AWS Secrets Manager,
   HashiCorp Vault, etc.)

## Migration Checklist

- [ ] Set up environment variables
- [ ] Install required dependencies
- [ ] Run `npm run install-client /path/to/your/app`
- [ ] Implement local token validation
- [ ] Update login/logout flows to use auth service
- [ ] Test authentication flows
- [ ] Update error handling
- [ ] Deploy and monitor
- [ ] Verify JWT_SECRET is identical across services

## Troubleshooting

### Common Issues

1. **Token validation fails**: Check JWT secret matches across all services
2. **Service not authorized**: Verify service name in token
3. **User not found**: User may have been deleted
4. **Password changed**: User needs to login again
5. **Local validation fails**: Ensure JWT_SECRET is identical

### Debug Mode

Enable debug logging by setting:

```env
NODE_ENV=development
```

## Support

For issues or questions, check the logs or contact the development team.
