# AuthWAPI Client Installation Guide

## Quick Installation

### TypeScript Version (Default)

```bash
# From your authwapi project directory
npm run install-client-ts /path/to/your/app
```

### JavaScript Version

```bash
# From your authwapi project directory
npm run install-client-js /path/to/your/app
```

### Remove Client

```bash
# Remove auth client from an app
npm run remove-client /path/to/your/app
```

## What Gets Installed

The installer creates these files in your target app:

```
your-app/
├── utils/
│   └── authClient.ts          # TypeScript version (or .js for JS)
├── auth-example.ts            # TypeScript example (or .js for JS)
└── .env.example              # Environment template
```

## What Gets Removed

The remover removes these files:

```
your-app/
├── utils/authClient.ts        # Removed
├── auth-example.ts            # Removed
├── .env.example              # Removed
└── utils/                    # Removed if empty
```

## Setup Steps

### 1. Install Dependencies

```bash
cd /path/to/your/app
npm install jsonwebtoken express
```

### 2. Configure Environment

```bash
cp .env.example .env
# Edit .env and set your JWT_SECRET
```

### 3. Use in Your App

#### TypeScript

```typescript
import { AuthClient } from './utils/authClient';

const authClient = new AuthClient({
  jwtSecret: process.env.JWT_SECRET,
  serviceName: process.env.AUTH_SERVICE_NAME,
});

// Protected route
app.get('/protected', authClient.createAuthMiddleware(), (req, res) => {
  res.json({ user: req.user });
});
```

#### JavaScript

```javascript
const { AuthClient } = require('./utils/authClient');

const authClient = new AuthClient({
  jwtSecret: process.env.JWT_SECRET,
  serviceName: process.env.AUTH_SERVICE_NAME,
});

// Protected route
app.get('/protected', authClient.createAuthMiddleware(), (req, res) => {
  res.json({ user: req.user });
});
```

## Testing

### 1. Start the example

```bash
# TypeScript
npx ts-node auth-example.ts

# JavaScript
node auth-example.js
```

### 2. Test with curl

```bash
# Create a token
curl -X POST http://localhost:3000/create-token \
  -H "Content-Type: application/json" \
  -d '{"userId": "user123", "service": "your-app-name"}'

# Use the token
curl -X GET http://localhost:3000/protected \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

## Environment Variables

```env
# Required
JWT_SECRET=your-super-secure-jwt-secret-key
AUTH_SERVICE_NAME=your-app-name

# Optional (for user management)
AUTH_SERVICE_URL=https://your-auth-service.com
```

## Features

- ✅ **Local JWT validation** - No HTTP calls needed
- ✅ **Express middleware** - Easy integration
- ✅ **Service-specific tokens** - Restrict tokens to specific services
- ✅ **Permission support** - Include permissions in tokens
- ✅ **Cross-app validation** - Same JWT_SECRET works across all apps
- ✅ **TypeScript support** - Both JS and TS versions available
- ✅ **Modern TypeScript** - Uses latest TypeScript features

## Installation Examples

```bash
# Install TypeScript version in multiple apps
npm run install-client-ts /path/to/app1
npm run install-client-ts /path/to/app2
npm run install-client-ts /path/to/app3

# Install JavaScript version in multiple apps
npm run install-client-js /path/to/app1
npm run install-client-js /path/to/app2

# Remove from apps
npm run remove-client /path/to/app1
npm run remove-client /path/to/app2
```

## Troubleshooting

### Common Issues

1. **Module not found**: Make sure you ran `npm run build` in the authwapi
   project
2. **Invalid token**: Check that JWT_SECRET is identical across all apps
3. **Service validation fails**: Ensure service names match
4. **TypeScript errors**: Install ts-node: `npm install -D ts-node`

### Debug Mode

```javascript
// Add this to see detailed validation info
const validation = authClient.validateToken(token);
console.log('Validation details:', validation);
```

## Next Steps

1. **Deploy your auth service** for user registration/login
2. **Add the same JWT_SECRET** to all your apps
3. **Use the AuthClient** in each app for local validation
4. **Test thoroughly** before production

## Support

For issues or questions, check the logs or contact the development team.
