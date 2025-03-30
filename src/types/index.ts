// src/types/index.ts
import { User } from '@prisma/client';

export interface Context {
  user: User | null;
  sign: (payload: any) => string;
}

export interface AuthPayload {
  token: string;
  user: User;
}

export interface BearerPayload {
  userId: number;
}