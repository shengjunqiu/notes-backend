// src/schema/auth.ts
export const authTypeDefs = `
  type AuthPayload {
    token: String!
    user: User!
  }

  type Mutation {
    register(email: String!, password: String!): AuthPayload!
    login(email: String!, password: String!): AuthPayload!
  }

  type Query {
    _empty: String
  }
`;