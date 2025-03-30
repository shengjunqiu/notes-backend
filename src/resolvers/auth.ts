// src/resolvers/auth.ts
import { prisma } from '../lib/prisma';
import bcrypt from 'bcryptjs';
import { User } from '@prisma/client';
import { Context, AuthPayload, BearerPayload } from '../types';
import { cacheService } from '../services/cache';
import { DuplicateError, ValidationError } from '../utils/errors';
import { createLogger } from '../services/logger';

const logger = createLogger('AuthResolver');

export const authResolvers = {
  Mutation: {
    register: async (
      _: any, 
      { email, password }: { email: string; password: string }, 
      { sign }: Context
    ): Promise<AuthPayload> => {
      try {
        // 验证密码强度
        if (password.length < 8) {
          throw new ValidationError('Password must be at least 8 characters long');
        }
        
        // 检查邮箱是否已被注册
        const existingUser = await prisma.user.findUnique({
          where: { email },
        });
        
        if (existingUser) {
          throw new DuplicateError('User', 'email', email);
        }
        
        // 加密密码
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // 创建用户
        const user = await prisma.user.create({
          data: {
            email,
            password: hashedPassword,
          },
        });
        
        logger.info(`User registered: ${user.id}`);
        
        // 缓存用户数据
        await cacheService.setUserCache(user);
        
        // 生成JWT令牌
        const token = sign({ userId: user.id } as BearerPayload);
        
        return { token, user };
      } catch (error) {
        if (error instanceof ValidationError || error instanceof DuplicateError) {
          // 这些是已知的业务逻辑错误，直接抛出
          throw error;
        }
        
        // 记录意外错误
        logger.error('Registration failed', error as Error, { email });
        throw new Error('Registration failed. Please try again later.');
      }
    },
    
    login: async (
      _: any, 
      { email, password }: { email: string; password: string }, 
      { sign }: Context
    ): Promise<AuthPayload> => {
      try {
        // 查找用户
        const user = await prisma.user.findUnique({
          where: { email },
        });
        
        if (!user) {
          throw new Error('Invalid email or password');
        }
        
        // 验证密码
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
          throw new Error('Invalid email or password');
        }
        
        logger.info(`User logged in: ${user.id}`);
        
        // 更新/设置用户缓存
        await cacheService.setUserCache(user);
        
        // 生成JWT令牌
        const token = sign({ userId: user.id } as BearerPayload);
        
        return { token, user };
      } catch (error) {
        // 记录登录失败，但不泄露具体原因
        logger.warn('Login failed', { email, error: (error as Error).message });
        
        // 为了安全，不要泄露是邮箱还是密码错误
        throw new Error('Invalid email or password');
      }
    },
  },
};