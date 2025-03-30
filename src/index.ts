// src/index.ts
import { Elysia } from 'elysia';
import { yoga } from '@elysiajs/graphql-yoga';
import jwt, { Secret } from 'jsonwebtoken';
import { makeExecutableSchema } from '@graphql-tools/schema';
import { typeDefs } from './schema';
import { resolvers } from './resolvers';
import { prisma } from './lib/prisma';
import { Context, BearerPayload } from './types';
import { config } from './config';
import { createLogger } from './services/logger';
import { cacheService } from './services/cache';

const logger = createLogger('App');

// 创建GraphQL Schema
const schema = makeExecutableSchema({
  typeDefs,
  resolvers,
});

// 明确定义JWT密钥，确保类型正确
const jwtSecret: Secret = config.jwt.secret;

const app = new Elysia()
  .get('/health', () => {
    return {
      status: 'ok',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
    };
  })
  .use(
    yoga({
      schema,
      context: async ({ request }): Promise<Context> => {
        // 获取授权头
        const authHeader = request.headers.get('authorization');
        let user = null;
        
        if (authHeader && authHeader.startsWith('Bearer ')) {
          const token = authHeader.split(' ')[1];
          try {
            // 验证JWT令牌
            const decoded = jwt.verify(token, jwtSecret) as BearerPayload;
            
            if (decoded && decoded.userId) {
              // 先尝试从Redis获取用户
              user = await cacheService.getUserCache(decoded.userId);
              
              if (!user) {
                // 从数据库获取并缓存
                user = await prisma.user.findUnique({
                  where: { id: decoded.userId },
                });
                
                if (user) {
                  // 缓存用户数据
                  await cacheService.setUserCache(user);
                }
              }
            }
          } catch (error) {
            // 无效令牌，用户保持为null
            logger.error('Token verification error', error as Error);
          }
        }
        
        return { 
          user,
          sign: (payload: any) => {
            return jwt.sign(payload, jwtSecret, { 
              // 直接使用字符串字面量，避免类型问题
              expiresIn: '7d' 
            });
          }
        };
      },
    })
  )
  .listen(config.server.port);

logger.info(`🦊 GraphQL API is running at http://${app.server?.hostname}:${app.server?.port}/graphql`);