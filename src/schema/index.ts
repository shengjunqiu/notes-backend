// src/schema/index.ts
import { userTypeDefs } from './user';
import { noteTypeDefs } from './note';
import { authTypeDefs } from './auth';

export const typeDefs = `
  ${authTypeDefs}
  ${userTypeDefs}
  ${noteTypeDefs}
`;