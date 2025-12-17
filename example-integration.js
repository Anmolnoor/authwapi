require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const { AuthClient } = require('./build/utils/authClient');

const app = express();
app.use(express.json());
app.use(cookieParser());

// Initialize auth client (local validation only)
const authClient = new AuthClient({
  jwtSecret: process.env.JWT_SECRET || 'your-secret-key',
  serviceName: process.env.AUTH_SERVICE_NAME || 'example-app',
});

// Public route
app.get('/', (req, res) => {
  res.json({ message: 'Welcome to Example App' });
});

// Protected route with local validation
app.get('/protected', authClient.createAuthMiddleware(), (req, res) => {
  res.json({
    message: 'This is a protected route',
    user: req.user,
  });
});

// Route to validate token manually
app.post('/validate', (req, res) => {
  const { token } = req.body;

  if (!token) {
    return res.status(400).json({ error: 'Token is required' });
  }

  // Use local validation (no HTTP call)
  const validation = authClient.validateToken(token);

  if (validation.valid) {
    res.json({
      valid: true,
      user: validation.user,
    });
  } else {
    res.status(401).json({
      valid: false,
      message: validation.message,
    });
  }
});

// Route to create a test token
app.post('/create-token', (req, res) => {
  const { userId, service, permissions } = req.body;

  const token = authClient.createToken(
    userId,
    service || 'example-app',
    permissions || ['read']
  );

  res.json({ token });
});

// Route to test token creation and validation
app.post('/test-token', (req, res) => {
  const { userId, service } = req.body;

  // Create a token
  const token = authClient.createToken(userId, service);

  // Validate the token immediately
  const validation = authClient.validateToken(token);

  res.json({
    createdToken: token,
    validation: validation,
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Example app listening on port ${PORT}`);
  console.log(
    `Service Name: ${process.env.AUTH_SERVICE_NAME || 'example-app'}`
  );
  console.log(
    `JWT Secret: ${process.env.JWT_SECRET ? 'Set' : 'Using default'}`
  );
});

module.exports = app;
