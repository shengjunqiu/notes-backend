// src/resolvers/user.ts
import { prisma } from '../lib/prisma';
import { User, Note } from '@prisma/client';
import { Context } from '../types';

export const userResolvers = {
  Query: {
    me: async (_: any, __: any, { user }: Context): Promise<User | null> => {
      if (!user) throw new Error('Authentication required');
      return prisma.user.findUnique({
        where: { id: user.id },
      });
    },
  },
  User: {
    notes: (parent: User): Promise<Note[]> => {
      return prisma.note.findMany({
        where: { userId: parent.id },
      });
    },
  },
};