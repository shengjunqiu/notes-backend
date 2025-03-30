// src/schema/note.ts
export const noteTypeDefs = `
  type Note {
    id: Int!
    title: String!
    content: String!
    createdAt: String!
    updatedAt: String!
    user: User!
  }

  extend type Query {
    notes: [Note!]!
    note(id: Int!): Note
  }

  extend type Mutation {
    createNote(title: String!, content: String!): Note!
    updateNote(id: Int!, title: String, content: String): Note!
    deleteNote(id: Int!): Note!
  }
`;