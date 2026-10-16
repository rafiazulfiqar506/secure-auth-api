# Secure Auth API

A secure Node.js/Express authentication API built for a cybersecurity internship task.

## Features

- User registration with bcrypt password hashing (cost factor 12)
- JWT-based login with 15-minute access tokens
- Refresh tokens stored server-side and revoked on refresh/logout
- Rate limiting: maximum 5 failed login attempts per IP every 10 minutes
- Helmet security headers and a custom Content-Security-Policy
- Jest and Supertest integration tests

## Setup

```bash
npm install
cp .env.example .env
npm start
```

## Testing

```bash
npm test
```

## API Endpoints

- POST /api/auth/register
- POST /api/auth/login
- POST /api/auth/refresh
- POST /api/auth/logout
