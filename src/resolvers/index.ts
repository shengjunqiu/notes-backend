// src/resolvers/index.ts
import { userResolvers } from './user';
import { noteResolvers } from './note';
import { authResolvers } from './auth';

// 合并所有解析器
export const resolvers = {
  Query: {
    ...userResolvers.Query,
    ...noteResolvers.Query,
  },
  Mutation: {
    ...authResolvers.Mutation,
    ...noteResolvers.Mutation,
  },
  User: userResolvers.User,
  Note: noteResolvers.Note,
};