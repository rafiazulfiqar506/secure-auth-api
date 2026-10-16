require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');

const app = express();
app.use(express.json());

app.use(helmet());
app.use((req, res, next) => {
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:"
  );
  next();
});

const users = [];
const refreshTokens = new Map();

const loginLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 5,
  message: { error: 'Too many attempts' }
});

app.get('/', (req, res) => {
  res.json({ message: 'Secure Auth API is running' });
});

app.post('/api/auth/register', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password || password.length < 8) {
    return res.status(400).json({ error: 'Valid email and 8+ character password required' });
  }

  if (users.find(u => u.email === email)) {
    return res.status(409).json({ error: 'User already exists' });
  }

  const passwordHash = await bcrypt.hash(password, 12);
  const user = { id: users.length + 1, email, passwordHash };
  users.push(user);

  res.status(201).json({ id: user.id, email: user.email });
});

app.post('/api/auth/login', loginLimiter, async (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email);

  if (!user || !(await bcrypt.compare(password || '', user.passwordHash))) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const accessToken = jwt.sign(
    { sub: user.id, email: user.email },
    process.env.JWT_ACCESS_SECRET,
    { expiresIn: '15m' }
  );

  const refreshToken = jwt.sign(
    { sub: user.id },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: '7d' }
  );

  refreshTokens.set(refreshToken, user.id);

  res.json({ accessToken, refreshToken });
});

app.post('/api/auth/refresh', (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken || !refreshTokens.has(refreshToken)) {
    return res.status(401).json({ error: 'Invalid refresh token' });
  }

  try {
    const payload = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    refreshTokens.delete(refreshToken);

    const newAccessToken = jwt.sign(
      { sub: payload.sub },
      process.env.JWT_ACCESS_SECRET,
      { expiresIn: '15m' }
    );

    const newRefreshToken = jwt.sign(
      { sub: payload.sub },
      process.env.JWT_REFRESH_SECRET,
      { expiresIn: '7d' }
    );

    refreshTokens.set(newRefreshToken, payload.sub);

    res.json({ accessToken: newAccessToken, refreshToken: newRefreshToken });
  } catch {
    refreshTokens.delete(refreshToken);
    res.status(401).json({ error: 'Invalid refresh token' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  const { refreshToken } = req.body;
  refreshTokens.delete(refreshToken);
  res.json({ message: 'Logged out' });
});

module.exports = app;

if (require.main === module) {
  app.listen(process.env.PORT || 3000, () => {
    console.log('Server running on port 3000');
  });
}
