// src/config.ts
import { Secret } from 'jsonwebtoken';

export const config = {
  jwt: {
    secret: (process.env.JWT_SECRET || 'your-secret-key') as Secret,
    expiresIn: '7d',
  },
  server: {
    port: parseInt(process.env.PORT || '3000'),
  },
  redis: {
    host: process.env.REDIS_HOST || 'localhost',
    port: parseInt(process.env.REDIS_PORT || '6379'),
  },
  db: {
    url: process.env.DATABASE_URL,
  }
};