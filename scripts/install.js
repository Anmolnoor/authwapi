#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

console.log('🔧 AuthWAPI Client Installer\n');

// Parse command line arguments
const args = process.argv.slice(2);
let targetDir = null;
let installJs = false;

// Parse arguments
for (let i = 0; i < args.length; i++) {
  if (args[i] === '--js') {
    installJs = true;
  } else if (!targetDir) {
    targetDir = args[i];
  }
}

if (!targetDir) {
  console.error('❌ Please provide target directory');
  console.log('Usage: npm run install-client /path/to/your/app [--js]');
  console.log('  --js: Install JavaScript version instead of TypeScript');
  process.exit(1);
}

if (!fs.existsSync(targetDir)) {
  console.error('❌ Target directory does not exist:', targetDir);
  process.exit(1);
}

console.log(`📁 Installing to: ${targetDir}`);
console.log(
  `📦 Installing: ${installJs ? 'JavaScript' : 'TypeScript'} version`
);

// Create utils directory if it doesn't exist
const utilsDir = path.join(targetDir, 'utils');
if (!fs.existsSync(utilsDir)) {
  fs.mkdirSync(utilsDir, { recursive: true });
  console.log('✅ Created utils directory');
}

// Copy the auth client
const sourceJsFile = path.join(
  __dirname,
  '..',
  'build',
  'utils',
  'authClient.js'
);
const sourceTsFile = path.join(
  __dirname,
  '..',
  'src',
  'utils',
  'authClient.ts'
);

if (!fs.existsSync(sourceJsFile)) {
  console.error('❌ Auth client not found. Please run "npm run build" first.');
  process.exit(1);
}

// Copy the appropriate version
if (installJs) {
  // Install JavaScript version
  const targetJsFile = path.join(utilsDir, 'authClient.js');
  fs.copyFileSync(sourceJsFile, targetJsFile);
  console.log('✅ Copied authClient.js');
} else {
  // Install TypeScript version by default
  if (fs.existsSync(sourceTsFile)) {
    const targetTsFile = path.join(utilsDir, 'authClient.ts');
    fs.copyFileSync(sourceTsFile, targetTsFile);
    console.log('✅ Copied authClient.ts');
  } else {
    console.error(
      '❌ TypeScript version not found. Please run "npm run build" first.'
    );
    process.exit(1);
  }
}

// Create example based on version
if (installJs) {
  // JavaScript example
  const exampleCode = `require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const { AuthClient } = require('./utils/authClient');

const app = express();
app.use(express.json());
app.use(cookieParser());

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
} else {
  // TypeScript example
  const tsExampleCode = `import 'dotenv/config';
import express from 'express';
import cookieParser from 'cookie-parser';
import { AuthClient } from './utils/authClient';

const app = express();
app.use(express.json());
app.use(cookieParser());

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

  const tsExampleFile = path.join(targetDir, 'auth-example.ts');
  fs.writeFileSync(tsExampleFile, tsExampleCode);
  console.log('✅ Created auth-example.ts');
}

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

  const requiredDeps = ['jsonwebtoken', 'express', 'cookie-parser', 'dotenv'];
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

  // Add TypeScript dependencies if installing TypeScript version
  if (!installJs) {
    const tsDeps = [
      'typescript',
      'ts-node',
      '@types/node',
      '@types/express',
      '@types/jsonwebtoken',
      '@types/cookie-parser',
    ];
    const missingTsDeps = tsDeps.filter(
      (dep) =>
        !packageJson.dependencies?.[dep] && !packageJson.devDependencies?.[dep]
    );

    if (missingTsDeps.length > 0) {
      console.log('📦 Installing TypeScript dependencies...');
      try {
        execSync(
          `cd "${targetDir}" && npm install -D ${missingTsDeps.join(' ')}`,
          {
            stdio: 'inherit',
          }
        );
        console.log('✅ TypeScript dependencies installed');
      } catch (error) {
        console.log('⚠️  Please install TypeScript dependencies manually:');
        console.log(`   npm install -D ${missingTsDeps.join(' ')}`);
      }
    }
  }
} else {
  console.log(
    '⚠️  No package.json found. Please install dependencies manually:'
  );
  if (installJs) {
    console.log('   npm install jsonwebtoken express');
  } else {
    console.log('   npm install jsonwebtoken express');
    console.log('   npm install -D typescript ts-node @types/node');
  }
}

console.log('\n🎉 Installation complete!');
console.log('\n📋 Next steps:');
console.log('1. Copy .env.example to .env and configure your JWT_SECRET');
if (installJs) {
  console.log('2. Run: node auth-example.js');
} else {
  console.log('2. Run: npx ts-node auth-example.ts');
}
console.log(
  '3. Test with: curl -X GET http://localhost:3000/protected -H "Authorization: Bearer YOUR_TOKEN"'
);
console.log('\n📚 Documentation: See INTEGRATION_GUIDE.md for more details');
