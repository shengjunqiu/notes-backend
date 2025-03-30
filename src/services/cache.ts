// src/services/cache.ts
import { redis } from '../lib/redis';
import { User } from '@prisma/client';

export const cacheService = {
  // 设置用户缓存
  setUserCache: async (user: User): Promise<void> => {
    await redis.set(
      `user:${user.id}`,
      JSON.stringify(user),
      'EX',
      3600
    );
  },
  
  // 获取用户缓存
  getUserCache: async (userId: number): Promise<User | null> => {
    const cachedUser = await redis.get(`user:${userId}`);
    if (cachedUser) {
      return JSON.parse(cachedUser);
    }
    return null;
  },
  
  // 清除用户缓存
  clearUserCache: async (userId: number): Promise<void> => {
    await redis.del(`user:${userId}`);
  },
  
  // 清除用户相关的所有缓存
  clearAllUserCache: async (userId: number): Promise<void> => {
    // 清除用户缓存
    await redis.del(`user:${userId}`);
    
    // 如果有其他与用户相关的缓存，也可以在这里清除
    // 例如，用户的笔记列表缓存
    await redis.del(`user:${userId}:notes`);
  }
};