import request from 'supertest';
import app from '../index.js'; // Adjust based on your actual file structure

test('Register new user', async () => {
  const res = await request(app)
    .post('/register')
    .send({
      username: 'testuser',
      email: 'test@example.com',
      password: 'password',
    });
  expect(res.statusCode).toBe(201);
  expect(res.body).toHaveProperty('token');
});

