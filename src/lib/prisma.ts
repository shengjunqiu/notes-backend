import { PrismaClient } from '@prisma/client'

// 创建Prisma客户端的单例实例
export const prisma = new PrismaClient()