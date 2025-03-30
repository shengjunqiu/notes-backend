// src/lib/redis.ts
import Redis from 'ioredis';
import { config } from '../config';

// 创建Redis客户端
export const redis = new Redis({
  host: config.redis.host,
  port: config.redis.port,
});

// 处理连接错误
redis.on('error', (err) => {
  console.error('Redis connection error:', err);
});

// 处理连接成功
redis.on('connect', () => {
  console.log('Redis connected successfully');
});