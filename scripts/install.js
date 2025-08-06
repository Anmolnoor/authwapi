#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

console.log('🔧 AuthWAPI Client Installer\n');

// Get the target directory from command line args
const targetDir = process.argv[2] || process.cwd();

if (!fs.existsSync(targetDir)) {
  console.error('❌ Target directory does not exist:', targetDir);
  process.exit(1);
}

console.log(`📁 Installing to: ${targetDir}`);

// Create utils directory if it doesn't exist
const utilsDir = path.join(targetDir, 'utils');
if (!fs.existsSync(utilsDir)) {
  fs.mkdirSync(utilsDir, { recursive: true });
  console.log('✅ Created utils directory');
}

// Copy the auth client
const sourceFile = path.join(
  __dirname,
  '..',
  'build',
  'utils',
  'authClient.js'
);
const targetFile = path.join(utilsDir, 'authClient.js');

if (!fs.existsSync(sourceFile)) {
  console.error('❌ Auth client not found. Please run "npm run build" first.');
  process.exit(1);
}

fs.copyFileSync(sourceFile, targetFile);
console.log('✅ Copied authClient.js');

// Create a simple example
const exampleCode = `const express = require('express');
const { AuthClient } = require('./utils/authClient');

const app = express();
app.use(express.json());

// Initialize auth client
const authClient = new AuthClient({
  jwtSecret: process.env.JWT_SECRET || 'your-secret-key',
  serviceName: process.env.AUTH_SERVICE_NAME || 'your-app-name',
});

// Protected route
app.get('/protected', authClient.createAuthMiddleware(), (req, res) => {
  res.json({
    message: 'This is a protected route',
    user: req.user,
  });
});

// Validate token manually
app.post('/validate', (req, res) => {
  const { token } = req.body;
  const validation = authClient.validateToken(token);
  res.json(validation);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(\`Server running on port \${PORT}\`);
});
`;

const exampleFile = path.join(targetDir, 'auth-example.js');
fs.writeFileSync(exampleFile, exampleCode);
console.log('✅ Created auth-example.js');

// Create .env template
const envTemplate = `# Auth Configuration
JWT_SECRET=your-super-secure-jwt-secret-key
AUTH_SERVICE_NAME=your-app-name

# Optional: Auth Service URL (for user management)
AUTH_SERVICE_URL=https://your-auth-service.com
`;

const envFile = path.join(targetDir, '.env.example');
fs.writeFileSync(envFile, envTemplate);
console.log('✅ Created .env.example');

// Check if package.json exists and add dependencies
const packageJsonPath = path.join(targetDir, 'package.json');
if (fs.existsSync(packageJsonPath)) {
  const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));

  const requiredDeps = ['jsonwebtoken', 'express'];
  const missingDeps = requiredDeps.filter(
    (dep) => !packageJson.dependencies?.[dep]
  );

  if (missingDeps.length > 0) {
    console.log('📦 Installing required dependencies...');
    try {
      execSync(`cd "${targetDir}" && npm install ${missingDeps.join(' ')}`, {
        stdio: 'inherit',
      });
      console.log('✅ Dependencies installed');
    } catch (error) {
      console.log('⚠️  Please install these dependencies manually:');
      console.log(`   npm install ${missingDeps.join(' ')}`);
    }
  }
} else {
  console.log(
    '⚠️  No package.json found. Please install dependencies manually:'
  );
  console.log('   npm install jsonwebtoken express');
}

console.log('\n🎉 Installation complete!');
console.log('\n📋 Next steps:');
console.log('1. Copy .env.example to .env and configure your JWT_SECRET');
console.log('2. Run: node auth-example.js');
console.log(
  '3. Test with: curl -X GET http://localhost:3000/protected -H "Authorization: Bearer YOUR_TOKEN"'
);
console.log('\n📚 Documentation: See INTEGRATION_GUIDE.md for more details');
