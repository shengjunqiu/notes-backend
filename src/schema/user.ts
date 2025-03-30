// src/schema/user.ts
export const userTypeDefs = `
  type User {
    id: Int!
    email: String!
    notes: [Note!]!
  }

  extend type Query {
    me: User
  }
`;