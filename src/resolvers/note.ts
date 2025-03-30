// src/resolvers/note.ts
import { prisma } from '../lib/prisma';
import { User, Note } from '@prisma/client';
import { Context } from '../types';

export const noteResolvers = {
  Query: {
    notes: async (_: any, __: any, { user }: Context): Promise<Note[]> => {
      if (!user) throw new Error('Authentication required');
      return prisma.note.findMany({
        where: { userId: user.id },
      });
    },
    note: async (_: any, { id }: { id: number }, { user }: Context): Promise<Note | null> => {
      if (!user) throw new Error('Authentication required');
      return prisma.note.findFirst({
        where: { id, userId: user.id },
      });
    },
  },
  Mutation: {
    createNote: async (
      _: any, 
      { title, content }: { title: string; content: string }, 
      { user }: Context
    ): Promise<Note> => {
      if (!user) throw new Error('Authentication required');
      
      return prisma.note.create({
        data: {
          title,
          content,
          userId: user.id,
        },
      });
    },
    updateNote: async (
      _: any, 
      { id, title, content }: { id: number; title?: string; content?: string }, 
      { user }: Context
    ): Promise<Note> => {
      if (!user) throw new Error('Authentication required');
      
      // 确保笔记属于当前用户
      const note = await prisma.note.findFirst({
        where: { id, userId: user.id },
      });
      if (!note) throw new Error('Note not found');
      
      return prisma.note.update({
        where: { id },
        data: {
          ...(title && { title }),
          ...(content && { content }),
        },
      });
    },
    deleteNote: async (
      _: any, 
      { id }: { id: number }, 
      { user }: Context
    ): Promise<Note> => {
      if (!user) throw new Error('Authentication required');
      
      // 确保笔记属于当前用户
      const note = await prisma.note.findFirst({
        where: { id, userId: user.id },
      });
      if (!note) throw new Error('Note not found');
      
      return prisma.note.delete({
        where: { id },
      });
    },
  },
  Note: {
    user: (parent: Note): Promise<User | null> => {
      return prisma.user.findUnique({
        where: { id: parent.userId },
      });
    },
  },
};