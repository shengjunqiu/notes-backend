// src/utils/errors.ts
export class AuthenticationError extends Error {
    constructor(message = 'Authentication required') {
      super(message);
      this.name = 'AuthenticationError';
    }
  }
  
  export class NotFoundError extends Error {
    constructor(entity = 'Resource', id?: number | string) {
      const message = id ? `${entity} with ID ${id} not found` : `${entity} not found`;
      super(message);
      this.name = 'NotFoundError';
    }
  }
  
  export class ValidationError extends Error {
    constructor(message = 'Validation failed') {
      super(message);
      this.name = 'ValidationError';
    }
  }
  
  export class DuplicateError extends Error {
    constructor(entity = 'Resource', field?: string, value?: string) {
      const message = field && value 
        ? `${entity} with ${field} ${value} already exists` 
        : `${entity} already exists`;
      super(message);
      this.name = 'DuplicateError';
    }
  }