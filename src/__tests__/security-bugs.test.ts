// Regression tests for bugs 1-4 in .solofounder/gap-analysis.md.
// Needs a throwaway MongoDB: TEST_DATABASE_URL=mongodb://127.0.0.1:27099 npm test
import type { Server } from 'http';
import type { AddressInfo } from 'net';
import mongoose from 'mongoose';

jest.mock('../utils/email', () => ({ __esModule: true, default: jest.fn() }));

const RESET_BASE = 'https://auth.example.test/api/v1/auth/reset-password/';
process.env.JWT_SECRET = 'test-secret';
process.env.EMAIL_URL = RESET_BASE;
/* eslint-disable @typescript-eslint/no-var-requires */
const app = require('../app').default;
const sendMail: jest.Mock = require('../utils/email').default;
const User = require('../models/user.model').default;

const dbUrl = process.env.TEST_DATABASE_URL;
if (!dbUrl) throw new Error('TEST_DATABASE_URL is required (a throwaway MongoDB)');

let server: Server;
let base: string;

beforeAll(async () => {
  await mongoose.connect(`${dbUrl}/authwapi-test-${process.pid}`);
  server = app.listen(0);
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}/api/v1`;
});

afterAll(async () => {
  await mongoose.connection.dropDatabase();
  await mongoose.disconnect();
  server.close();
});

beforeEach(() => sendMail.mockReset());

const post = (path: string, body: unknown, headers: Record<string, string> = {}) =>
  fetch(base + path, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: JSON.stringify(body),
  });

const tokenFrom = (res: Response): string =>
  /jwt=([^;]+)/.exec(res.headers.get('set-cookie') ?? '')![1];

const me = (token: string) =>
  fetch(`${base}/user/me`, { headers: { authorization: `Bearer ${token}` } });

let n = 0;
const register = async () => {
  n += 1;
  const user = { username: `owner${n}`, email: `owner${n}@ex.com`, password: 'Passw0rd!' };
  const res = await post('/auth/register', {
    ...user,
    passwordConfirm: user.password,
    firstName: 'A',
    lastName: 'B',
  });
  expect(res.status).toBe(201);
  return { ...user, res };
};

const resetTokenFromMail = (): string => {
  const { msg } = sendMail.mock.calls[0][0];
  return /([0-9a-f]{64})/.exec(msg)![1];
};

describe('bug 1: NoSQL injection in login and forget-password', () => {
  test('login with a $regex username never reaches the database', async () => {
    await register();
    const findOne = jest.spyOn(User, 'findOne');
    try {
      const hit = await post('/auth/login', { username: { $regex: '^owner' }, password: 'x' });
      const miss = await post('/auth/login', { username: { $regex: '^zzz' }, password: 'x' });
      expect(hit.status).toBe(401);
      expect(miss.status).toBe(401);
      expect(await hit.json()).toEqual(await miss.json());
      expect(findOne).not.toHaveBeenCalled();
    } finally {
      findOne.mockRestore();
    }
  });

  test('forget-password rejects a non-string email without sending mail', async () => {
    await register();
    const res = await post('/auth/forget-password', { email: { $regex: '^owner' } });
    expect(res.status).toBe(400);
    expect(sendMail).not.toHaveBeenCalled();
  });
});

describe('bug 2: password and reset-token hashes never leave the server', () => {
  const assertClean = (body: unknown) => {
    const text = JSON.stringify(body);
    expect(text).not.toMatch(/\$2[aby]\$/);
    for (const key of ['password', 'passwordConfirm', 'resetToken', 'resetTokenTimer']) {
      expect(text).not.toContain(`"${key}"`);
    }
  };

  test('register, login and /me responses contain no hashes', async () => {
    const u = await register();
    assertClean(await u.res.json());
    const login = await post('/auth/login', { username: u.username, password: u.password });
    expect(login.status).toBe(201);
    assertClean(await login.json());
    await post('/auth/forget-password', { email: u.email }); // sets resetToken in the DB
    const profile = await me(tokenFrom(login));
    expect(profile.status).toBe(200);
    assertClean(await profile.json());
  });

  test('reset-password response contains no hashes', async () => {
    const u = await register();
    await post('/auth/forget-password', { email: u.email });
    const res = await fetch(`${base}/auth/reset-password/${resetTokenFromMail()}`, {
      method: 'PATCH',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ password: 'NewPassw0rd!', passwordConfirm: 'NewPassw0rd!' }),
    });
    expect(res.status).toBe(201);
    assertClean(await res.json());
  });
});

describe('bug 3: old tokens stop working after a password change or reset', () => {
  // No waiting: a token issued milliseconds before the change must still be revoked.
  test('update-password revokes the old token', async () => {
    const u = await register();
    const old = tokenFrom(await post('/auth/login', { username: u.username, password: u.password }));
    const change = await post(
      '/user/update-password',
      { password: u.password, newPassword: 'NewPassw0rd!', newPasswordConfirm: 'NewPassw0rd!' },
      { authorization: `Bearer ${old}` }
    );
    expect(change.status).toBe(201);
    expect((await me(old)).status).toBe(401);
    expect((await me(tokenFrom(change))).status).toBe(200);
  });

  test('two concurrent password saves cannot both succeed', async () => {
    const u = await register();
    const [a, b] = await Promise.all([
      User.findOne({ email: u.email }),
      User.findOne({ email: u.email }),
    ]);
    a.password = a.passwordConfirm = 'FirstPassw0rd!';
    b.password = b.passwordConfirm = 'SecondPassw0rd!';
    await a.save();
    await expect(b.save()).rejects.toThrow(/No matching document|version/i);
  });

  test('reset-password revokes the old token', async () => {
    const u = await register();
    const old = tokenFrom(await post('/auth/login', { username: u.username, password: u.password }));
    await post('/auth/forget-password', { email: u.email });
    const reset = await fetch(`${base}/auth/reset-password/${resetTokenFromMail()}`, {
      method: 'PATCH',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ password: 'NewPassw0rd!', passwordConfirm: 'NewPassw0rd!' }),
    });
    expect(reset.status).toBe(201);
    expect((await me(old)).status).toBe(401);
    expect((await me(tokenFrom(reset))).status).toBe(200);
  });
});

describe('bug 4: reset link ignores spoofed X-Forwarded-Proto', () => {
  test('the emailed link always starts with the configured EMAIL_URL', async () => {
    const u = await register();
    const res = await post(
      '/auth/forget-password',
      { email: u.email },
      { 'x-forwarded-proto': 'https://evil.example/?t=' }
    );
    expect(res.status).toBe(201);
    const { msg } = sendMail.mock.calls[0][0];
    expect(msg).not.toContain('evil.example');
    expect(msg).toContain(`\n${RESET_BASE}${resetTokenFromMail()}\n`);
  });

  test('a bad EMAIL_URL fails before touching the DB, so an earlier link still works', async () => {
    const u = await register();
    await post('/auth/forget-password', { email: u.email });
    const token = resetTokenFromMail();
    for (const bad of [
      'auth.example.test/reset/',
      'https://auth.example.test/reset',
      'https://auth.example.test/reset/?next=/',
      'https://bad host/reset/',
      'https://auth.example.test/reset link/',
    ]) {
      process.env.EMAIL_URL = bad;
      try {
        expect((await post('/auth/forget-password', { email: u.email })).status).toBe(500);
      } finally {
        process.env.EMAIL_URL = RESET_BASE;
      }
    }
    const reset = await fetch(`${base}/auth/reset-password/${token}`, {
      method: 'PATCH',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ password: 'NewPassw0rd!', passwordConfirm: 'NewPassw0rd!' }),
    });
    expect(reset.status).toBe(201);
  });
});
