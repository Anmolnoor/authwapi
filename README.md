git # AuthWAPI

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
# Optional (JWT expiry for tokens issued by auth service)
JWT_EXPIRES_IN=30d
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
   npm install jsonwebtoken express cookie-parser dotenv
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

### Run the Test Suite

See `TESTING.md` for full details. Quick start:

```bash
npm test
```

## Documentation

- [Integration Guide](INTEGRATION_GUIDE.md) - Detailed integration instructions
- [Usage Guide](USAGE_GUIDE.md) - Installation and usage guide

## API Notes

- Login/Register/Password-reset endpoints now include a `token` in the JSON
  response in addition to setting the `jwt` cookie. Use this `token` in your
  other services via `Authorization: Bearer <token>` and validate locally with
  the same `JWT_SECRET`.

### Handle Availability

- Check if a username/handle is available. Valid handles: 3–30 chars, `a-z`,
  `0-9`, `_`, `-`. Reserved: `admin`, `moderator`, `support`, `help`.

POST:

```bash
curl -X POST http://localhost:3000/api/v1/auth/check-handle \
  -H "Content-Type: application/json" \
  -d '{"handle":"my_new-handle"}'
```

GET (path or query):

```bash
curl http://localhost:3000/api/v1/auth/check-handle/my_new-handle
curl "http://localhost:3000/api/v1/auth/check-handle?handle=my_new-handle"
```

## Security Benefits

- ✅ **No secrets over HTTP** - Local validation only
- ✅ **Faster performance** - No network calls for validation
- ✅ **Works offline** - No dependency on auth service for validation
- ✅ **More secure** - Reduced attack surface
- ✅ **Better scalability** - No auth service bottleneck

## License

MIT
