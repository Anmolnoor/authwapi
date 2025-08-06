# AuthWAPI

Simplified authentication, maximized development.

## Overview

AuthWAPI provides centralized JWT authentication for multiple applications. Each
service can validate JWT tokens locally without HTTP calls for better security
and performance.

## Quick Start

### 1. Build the Project

```bash
npm run build
```

### 2. Install in Your Apps

```bash
# Install TypeScript version (recommended)
npm run install-client-ts /path/to/your/app1
npm run install-client-ts /path/to/your/app2

# Or install JavaScript version
npm run install-client-js /path/to/your/app3
```

### 3. Use in Your Apps

```javascript
const { AuthClient } = require('./utils/authClient');

const authClient = new AuthClient({
  jwtSecret: process.env.JWT_SECRET, // Same across all apps
  serviceName: process.env.AUTH_SERVICE_NAME,
});

// Protected route
app.get('/protected', authClient.createAuthMiddleware(), (req, res) => {
  res.json({ user: req.user });
});
```

## Features

- ✅ **Local JWT validation** - No HTTP calls needed
- ✅ **Express middleware** - Easy integration
- ✅ **Service-specific tokens** - Restrict tokens to specific services
- ✅ **Permission support** - Include permissions in tokens
- ✅ **Cross-app validation** - Same JWT_SECRET works across all apps
- ✅ **Lightweight** - Minimal dependencies

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   App 1         │    │   App 2         │    │   App 3         │
│                 │    │                 │    │                 │
│ JWT_SECRET      │    │ JWT_SECRET      │    │ JWT_SECRET      │
│ (same)          │    │ (same)          │    │ (same)          │
│                 │    │                 │    │                 │
│ Local validation│    │ Local validation│    │ Local validation│
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Environment Variables

```env
# Required (same across all apps)
JWT_SECRET=your-super-secure-jwt-secret-key
AUTH_SERVICE_NAME=your-app-name

# Optional (for user management)
AUTH_SERVICE_URL=https://your-auth-service.com
```

## Installation

### For Your Other Apps

1. **Install the auth client:**

   ```bash
   # TypeScript version (recommended)
   npm run install-client-ts /path/to/your/app

   # JavaScript version
   npm run install-client-js /path/to/your/app
   ```

2. **Install dependencies:**

   ```bash
   cd /path/to/your/app
   npm install jsonwebtoken express
   ```

3. **Configure environment:**

   ```bash
   cp .env.example .env
   # Edit .env and set your JWT_SECRET
   ```

4. **Use in your app:**

   ```javascript
   const { AuthClient } = require('./utils/authClient');

   const authClient = new AuthClient({
     jwtSecret: process.env.JWT_SECRET,
     serviceName: process.env.AUTH_SERVICE_NAME,
   });

   app.get('/protected', authClient.createAuthMiddleware(), (req, res) => {
     res.json({ user: req.user });
   });
   ```

## Testing

### Test the Installation

```bash
# Test the auth client
node test-auth.js
```

### Test the Example

```bash
# Start the example server
node example-integration.js

# Test with curl
curl -X POST http://localhost:3000/create-token \
  -H "Content-Type: application/json" \
  -d '{"userId": "user123", "service": "example-app"}'
```

## Documentation

- [Integration Guide](INTEGRATION_GUIDE.md) - Detailed integration instructions
- [Usage Guide](USAGE_GUIDE.md) - Installation and usage guide

## Security Benefits

- ✅ **No secrets over HTTP** - Local validation only
- ✅ **Faster performance** - No network calls for validation
- ✅ **Works offline** - No dependency on auth service for validation
- ✅ **More secure** - Reduced attack surface
- ✅ **Better scalability** - No auth service bottleneck

## License

MIT
