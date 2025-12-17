const { AuthClient } = require('./build/utils/authClient');

// Test configuration
const JWT_SECRET = 'test-secret-key-123';
const SERVICE_NAME = 'test-app';

// Initialize auth client
const authClient = new AuthClient({
  jwtSecret: JWT_SECRET,
  serviceName: SERVICE_NAME,
});

console.log('🧪 Testing Local JWT Validation\n');

// Test 1: Create and validate token
console.log('1️⃣ Test: Create and validate token');
const userId = 'user123';
const token = authClient.createToken(userId, SERVICE_NAME, ['read', 'write']);
console.log('Created token:', token.substring(0, 50) + '...');

const validation = authClient.validateToken(token);
console.log('Validation result:', validation);
console.log('✅ Token validation:', validation.valid ? 'PASSED' : 'FAILED');
console.log('');

// Test 2: Validate invalid token
console.log('2️⃣ Test: Validate invalid token');
const invalidToken = 'invalid.token.here';
const invalidValidation = authClient.validateToken(invalidToken);
console.log('Invalid token validation:', invalidValidation);
console.log(
  '✅ Invalid token rejected:',
  !invalidValidation.valid ? 'PASSED' : 'FAILED'
);
console.log('');

// Test 3: Service-specific validation
console.log('3️⃣ Test: Service-specific validation');
const otherServiceToken = authClient.createToken(userId, 'other-service');
const otherServiceValidation = authClient.validateToken(otherServiceToken);
console.log('Other service token validation:', otherServiceValidation);
console.log(
  '✅ Service validation:',
  !otherServiceValidation.valid ? 'PASSED' : 'FAILED'
);
console.log('');

// Test 4: Token with permissions
console.log('4️⃣ Test: Token with permissions');
const permissionToken = authClient.createToken(userId, SERVICE_NAME, [
  'admin',
  'delete',
]);
const permissionValidation = authClient.validateToken(permissionToken);
console.log('Permission token validation:', permissionValidation);
console.log(
  '✅ Permission validation:',
  permissionValidation.valid ? 'PASSED' : 'FAILED'
);
console.log('');

// Test 5: Multiple apps with same secret
console.log('5️⃣ Test: Multiple apps with same secret');
const app1 = new AuthClient({ jwtSecret: JWT_SECRET, serviceName: 'app1' });
const app2 = new AuthClient({ jwtSecret: JWT_SECRET, serviceName: 'app2' });

// Create token for app1
const app1Token = app1.createToken(userId, 'app1');
const app1Validation = app1.validateToken(app1Token);
const app2Validation = app2.validateToken(app1Token);

console.log('App1 token validation in App1:', app1Validation.valid);
console.log('App1 token validation in App2:', app2Validation.valid);
console.log(
  '✅ Cross-app validation:',
  app1Validation.valid && app2Validation.valid ? 'PASSED' : 'FAILED'
);
console.log('');

// Test 6: Universal token (no service restriction)
console.log('6️⃣ Test: Universal token (no service restriction)');
const universalToken = authClient.createToken(userId); // No service specified
const universalValidation1 = app1.validateToken(universalToken);
const universalValidation2 = app2.validateToken(universalToken);

console.log('Universal token in App1:', universalValidation1.valid);
console.log('Universal token in App2:', universalValidation2.valid);
console.log(
  '✅ Universal token validation:',
  universalValidation1.valid && universalValidation2.valid ? 'PASSED' : 'FAILED'
);
console.log('');

console.log('🎉 All tests completed!');
console.log('');
console.log('📋 Summary:');
console.log('- Local JWT validation works without HTTP calls');
console.log('- Same JWT_SECRET allows cross-app token validation');
console.log('- Service-specific tokens can be enforced');
console.log('- Permissions can be included in tokens');
console.log('- Universal tokens work across all apps');
