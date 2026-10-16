const request = require('supertest');
const app = require('../server');

describe('Authentication API', () => {
  const email = `test${Date.now()}@example.com`;
  const password = 'StrongPass123';
  let refreshToken;

  test('registers a user', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({ email, password });

    expect(res.status).toBe(201);
  });

  test('logs in successfully and returns tokens', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ email, password });

    expect(res.status).toBe(200);
    expect(res.body.accessToken).toBeDefined();
    expect(res.body.refreshToken).toBeDefined();

    refreshToken = res.body.refreshToken;
  });

  test('rejects incorrect password', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ email, password: 'WrongPassword123' });

    expect(res.status).toBe(401);
  });

  test('refreshes access token and revokes old refresh token', async () => {
    const res = await request(app)
      .post('/api/auth/refresh')
      .send({ refreshToken });

    expect(res.status).toBe(200);
    expect(res.body.accessToken).toBeDefined();

    const reuse = await request(app)
      .post('/api/auth/refresh')
      .send({ refreshToken });

    expect(reuse.status).toBe(401);
  });

  test('rate limits after 5 failed login attempts', async () => {
    let lastResponse;

    for (let i = 0; i < 6; i++) {
      lastResponse = await request(app)
        .post('/api/auth/login')
        .send({ email: 'ratelimit@example.com', password: 'wrong' });
    }

    expect(lastResponse.status).toBe(429);
  });

  test('includes security headers', async () => {
    const res = await request(app).get('/');

    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['content-security-policy']).toBeDefined();
  });
});
