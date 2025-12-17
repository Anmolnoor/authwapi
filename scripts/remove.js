#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

console.log('🗑️  AuthWAPI Client Remover\n');

// Get the target directory from command line args
const targetDir = process.argv[2] || process.cwd();

if (!fs.existsSync(targetDir)) {
  console.error('❌ Target directory does not exist:', targetDir);
  process.exit(1);
}

console.log(`📁 Removing from: ${targetDir}`);

// Check which version was installed
const jsFile = path.join(targetDir, 'utils', 'authClient.js');
const tsFile = path.join(targetDir, 'utils', 'authClient.ts');
const jsExample = path.join(targetDir, 'auth-example.js');
const tsExample = path.join(targetDir, 'auth-example.ts');

const hasJs = fs.existsSync(jsFile);
const hasTs = fs.existsSync(tsFile);
const hasJsExample = fs.existsSync(jsExample);
const hasTsExample = fs.existsSync(tsExample);

// Files to remove (only the ones that exist)
const filesToRemove = [];

if (hasJs) filesToRemove.push('utils/authClient.js');
if (hasTs) filesToRemove.push('utils/authClient.ts');
if (hasJsExample) filesToRemove.push('auth-example.js');
if (hasTsExample) filesToRemove.push('auth-example.ts');
filesToRemove.push('.env.example');

// Directories to remove if empty
const dirsToRemove = ['utils'];

let removedCount = 0;

// Remove files
filesToRemove.forEach((file) => {
  const filePath = path.join(targetDir, file);
  if (fs.existsSync(filePath)) {
    fs.unlinkSync(filePath);
    console.log(`✅ Removed: ${file}`);
    removedCount++;
  } else {
    console.log(`⚠️  Not found: ${file}`);
  }
});

// Remove directories if empty
dirsToRemove.forEach((dir) => {
  const dirPath = path.join(targetDir, dir);
  if (fs.existsSync(dirPath)) {
    try {
      const files = fs.readdirSync(dirPath);
      if (files.length === 0) {
        fs.rmdirSync(dirPath);
        console.log(`✅ Removed empty directory: ${dir}`);
        removedCount++;
      } else {
        console.log(`⚠️  Directory not empty, keeping: ${dir}`);
      }
    } catch (error) {
      console.log(`⚠️  Could not check directory: ${dir}`);
    }
  }
});

// Check for auth-related code in package.json
const packageJsonPath = path.join(targetDir, 'package.json');
if (fs.existsSync(packageJsonPath)) {
  try {
    const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
    const authDeps = ['jsonwebtoken', 'cookie-parser', 'dotenv'];
    const hasAuthDeps = authDeps.some((dep) => packageJson.dependencies?.[dep]);

    if (hasAuthDeps) {
      console.log('\n📦 Note: You may want to remove auth dependencies:');
      console.log('   npm uninstall jsonwebtoken cookie-parser dotenv');
    }

    // Check for TypeScript dependencies if TypeScript version was installed
    if (hasTs) {
      const tsDeps = [
        'typescript',
        'ts-node',
        '@types/node',
        '@types/express',
        '@types/jsonwebtoken',
        '@types/cookie-parser',
      ];
      const hasTsDeps = tsDeps.some(
        (dep) =>
          packageJson.dependencies?.[dep] || packageJson.devDependencies?.[dep]
      );

      if (hasTsDeps) {
        console.log(
          '\n📦 Note: You may want to remove TypeScript dependencies:'
        );
        console.log(
          '   npm uninstall -D typescript ts-node @types/node @types/express @types/jsonwebtoken @types/cookie-parser'
        );
      }
    }
  } catch (error) {
    console.log('⚠️  Could not read package.json');
  }
}

console.log(`\n🎉 Removal complete! Removed ${removedCount} items.`);
console.log('\n📋 Next steps:');
console.log('1. Remove any auth-related code from your app');
console.log('2. Remove auth dependencies: npm uninstall jsonwebtoken');
if (hasTs) {
  console.log(
    '3. Remove TypeScript dependencies: npm uninstall -D typescript ts-node @types/node'
  );
}
console.log('4. Update your environment variables');
console.log('5. Test your app to ensure it still works');
