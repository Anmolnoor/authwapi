import request from 'supertest';
import mongoose from 'mongoose';
import { MongoMemoryServer } from 'mongodb-memory-server';
import app from '../src/app';

describe('AuthWAPI E2E', () => {
  let mongoServer: MongoMemoryServer;

  beforeAll(async () => {
    process.env.JWT_SECRET = 'testsecret';
    process.env.JWT_EXPIRES_IN = '1h';
    process.env.NODE_ENV = 'test';

    mongoServer = await MongoMemoryServer.create();
    const uri = mongoServer.getUri();
    await mongoose.connect(uri);
  });

  afterAll(async () => {
    await mongoose.disconnect();
    await mongoServer.stop();
  });

  it('registers a user and returns token', async () => {
    const res = await request(app)
      .post('/api/v1/auth/register')
      .send({
        email: 'user@example.com',
        username: 'user1',
        password: 'Password123!',
        passwordConfirm: 'Password123!',
        firstName: 'Test',
        lastName: 'User',
        phone: 1234567890,
        service: 'Amend',
      })
      .expect(201);

    expect(res.body?.data?.user?.email).toBe('user@example.com');
    expect(typeof res.body?.data?.token).toBe('string');
    expect(res.headers['set-cookie']?.[0]).toMatch(/jwt=/);
  });

  it('logs in and returns token', async () => {
    const res = await request(app)
      .post('/api/v1/auth/login')
      .send({
        username: 'user@example.com',
        password: 'Password123!',
        service: 'Amend',
      })
      .expect(201);

    expect(typeof res.body?.data?.token).toBe('string');
  });

  it('gets user info with bearer token', async () => {
    const login = await request(app)
      .post('/api/v1/auth/login')
      .send({
        username: 'user@example.com',
        password: 'Password123!',
        service: 'Amend',
      })
      .expect(201);

    const token = login.body?.data?.token as string;

    const res = await request(app)
      .get('/api/v1/auth/user-info')
      .set('Authorization', `Bearer ${token}`)
      .expect(200);

    expect(res.body?.data?.user?.email).toBe('user@example.com');
  });

  it('validates token via HTTP endpoint', async () => {
    const login = await request(app)
      .post('/api/v1/auth/login')
      .send({
        username: 'user@example.com',
        password: 'Password123!',
        service: 'Amend',
      })
      .expect(201);

    const token = login.body?.data?.token as string;

    const res = await request(app)
      .post('/api/v1/auth/validate-token')
      .send({ token, service: 'Amend' })
      .expect(200);

    expect(res.body?.data?.valid).toBe(true);
    expect(res.body?.data?.user?.email).toBe('user@example.com');
  });
});
