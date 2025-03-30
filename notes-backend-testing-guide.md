# 笔记应用后端测试方法指南

## 目录

1. [测试概述](#测试概述)
2. [测试环境准备](#测试环境准备)
3. [手动测试API](#手动测试api)
   - [使用GraphQL Playground](#使用graphql-playground)
   - [使用curl命令](#使用curl命令)
   - [使用Postman/Insomnia](#使用postmaninsomnia)
4. [自动化测试](#自动化测试)
   - [单元测试](#单元测试)
   - [集成测试](#集成测试)
   - [端到端测试](#端到端测试)
5. [性能测试](#性能测试)
6. [安全测试](#安全测试)
7. [测试最佳实践](#测试最佳实践)
8. [持续集成](#持续集成)

## 测试概述

为笔记应用后端进行测试是确保应用质量和可靠性的关键步骤。本指南涵盖了从手动测试到自动化测试的各种方法，可以帮助你验证应用的功能、性能和安全性。

测试策略应涵盖以下几个层次：
- **单元测试**：测试独立的代码单元（如解析器函数）
- **集成测试**：测试多个组件一起工作的场景（如身份验证流程）
- **端到端测试**：测试完整的用户流程
- **性能测试**：评估应用在负载下的表现
- **安全测试**：检查潜在的安全漏洞

## 测试环境准备

在开始测试前，需要设置专门的测试环境：

1. **创建测试数据库**：
```bash
# 在.env.test文件中添加测试数据库配置
DATABASE_URL="postgresql://username:password@localhost:5432/notes_test_db?schema=public"
```

2. **设置测试环境变量**：
```bash
# 创建.env.test文件
NODE_ENV=test
JWT_SECRET=test_secret_key
PORT=3001
REDIS_HOST=localhost
REDIS_PORT=6379
```

3. **安装测试依赖**：
```bash
bun add -D bun:test supertest jest-mock
```

4. **添加测试脚本**到package.json：
```json
{
  "scripts": {
    "test": "NODE_ENV=test bun test",
    "test:watch": "NODE_ENV=test bun test --watch"
  }
}
```

## 手动测试API

### 使用GraphQL Playground

GraphQL Playground是一个交互式工具，可以直接在浏览器中测试GraphQL API。以下是测试各个功能的步骤：

1. **启动应用**：
```bash
bun run --watch src/index.ts
```

2. **打开GraphQL Playground**：
浏览器访问 `http://localhost:3000/graphql`

3. **测试用户注册**：
```graphql
mutation {
  register(email: "test@example.com", password: "password123") {
    token
    user {
      id
      email
    }
  }
}
```

4. **测试用户登录**：
```graphql
mutation {
  login(email: "test@example.com", password: "password123") {
    token
    user {
      id
      email
    }
  }
}
```

5. **添加认证头**：
在GraphQL Playground的左下角，添加HTTP头：
```json
{
  "Authorization": "Bearer YOUR_TOKEN_HERE"
}
```

6. **测试创建笔记**：
```graphql
mutation {
  createNote(title: "Test Note", content: "This is a test note content") {
    id
    title
    content
    createdAt
    updatedAt
  }
}
```

7. **测试获取所有笔记**：
```graphql
query {
  notes {
    id
    title
    content
    createdAt
    updatedAt
  }
}
```

8. **测试获取单个笔记**：
```graphql
query {
  note(id: 1) {
    id
    title
    content
    createdAt
    updatedAt
    user {
      id
      email
    }
  }
}
```

9. **测试更新笔记**：
```graphql
mutation {
  updateNote(id: 1, title: "Updated Title", content: "Updated content") {
    id
    title
    content
    updatedAt
  }
}
```

10. **测试删除笔记**：
```graphql
mutation {
  deleteNote(id: 1) {
    id
    title
  }
}
```

### 使用curl命令

如果你更喜欢命令行操作，可以使用curl命令测试API：

1. **注册用户**：
```bash
curl -X POST http://localhost:3000/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation { register(email: \"test@example.com\", password: \"password123\") { token user { id email } } }"}'
```

2. **登录用户**：
```bash
curl -X POST http://localhost:3000/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation { login(email: \"test@example.com\", password: \"password123\") { token user { id email } } }"}'
```

3. **创建笔记**（需要认证）：
```bash
curl -X POST http://localhost:3000/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"query":"mutation { createNote(title: \"Test Note\", content: \"This is a test note\") { id title content } }"}'
```

4. **查询笔记**（需要认证）：
```bash
curl -X POST http://localhost:3000/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"query":"query { notes { id title content } }"}'
```

### 使用Postman/Insomnia

图形化API测试工具如Postman或Insomnia提供了更友好的界面：

1. **创建一个新的请求**
   - 设置请求方法为POST
   - 设置URL为http://localhost:3000/graphql
   - 设置Content-Type为application/json

2. **设置GraphQL查询**
   - 在请求体中使用上面的GraphQL查询示例
   - 对于需要认证的请求，添加Authorization头

3. **创建集合**
   - 创建请求集合组织不同的测试场景
   - 使用环境变量存储和重用token

## 自动化测试

### 单元测试

单元测试专注于测试独立的代码单元。以下是一个测试认证解析器的例子：

```typescript
// tests/resolvers/auth.test.ts
import { describe, it, expect, beforeEach, mock } from 'bun:test';
import { authResolvers } from '../../src/resolvers/auth';
import { prisma } from '../../src/lib/prisma';
import { cacheService } from '../../src/services/cache';
import bcrypt from 'bcryptjs';

// 模拟依赖
mock.module('../../src/lib/prisma', () => ({
  prisma: {
    user: {
      findUnique: mock(() => null),
      create: mock(() => ({ 
        id: 1, 
        email: 'test@example.com',
        password: 'hashedpassword',
        createdAt: new Date(),
        updatedAt: new Date()
      }))
    }
  }
}));

mock.module('../../src/services/cache', () => ({
  cacheService: {
    setUserCache: mock(async () => {})
  }
}));

mock.module('bcryptjs', () => ({
  hash: mock(() => 'hashedpassword'),
  compare: mock(() => true)
}));

describe('Auth Resolvers', () => {
  const mockContext = {
    sign: mock(() => 'jwt-token')
  };

  beforeEach(() => {
    // 重置所有模拟函数
    mock.resetAll();
  });

  describe('register', () => {
    it('should register a new user', async () => {
      const args = { email: 'test@example.com', password: 'password123' };
      
      const result = await authResolvers.Mutation.register(null, args, mockContext);
      
      expect(result).toHaveProperty('token', 'jwt-token');
      expect(result.user).toHaveProperty('id', 1);
      expect(result.user).toHaveProperty('email', 'test@example.com');
      expect(bcrypt.hash).toHaveBeenCalledWith('password123', 10);
      expect(cacheService.setUserCache).toHaveBeenCalled();
    });

    it('should throw error if password is too short', async () => {
      const args = { email: 'test@example.com', password: 'short' };
      
      await expect(authResolvers.Mutation.register(null, args, mockContext))
        .rejects.toThrow('Password must be at least 8 characters long');
    });

    it('should throw error if email already exists', async () => {
      // 模拟找到已存在的用户
      prisma.user.findUnique.mockImplementationOnce(() => ({
        id: 1,
        email: 'test@example.com',
        password: 'hashedpassword',
        createdAt: new Date(),
        updatedAt: new Date()
      }));
      
      const args = { email: 'test@example.com', password: 'password123' };
      
      await expect(authResolvers.Mutation.register(null, args, mockContext))
        .rejects.toThrow('User with email test@example.com already exists');
    });
  });

  describe('login', () => {
    it('should login user with valid credentials', async () => {
      // 模拟找到用户
      prisma.user.findUnique.mockImplementationOnce(() => ({
        id: 1,
        email: 'test@example.com',
        password: 'hashedpassword',
        createdAt: new Date(),
        updatedAt: new Date()
      }));
      
      const args = { email: 'test@example.com', password: 'password123' };
      
      const result = await authResolvers.Mutation.login(null, args, mockContext);
      
      expect(result).toHaveProperty('token', 'jwt-token');
      expect(result.user).toHaveProperty('id', 1);
      expect(bcrypt.compare).toHaveBeenCalledWith('password123', 'hashedpassword');
    });

    it('should throw error if user not found', async () => {
      // 模拟未找到用户
      prisma.user.findUnique.mockImplementationOnce(() => null);
      
      const args = { email: 'nonexistent@example.com', password: 'password123' };
      
      await expect(authResolvers.Mutation.login(null, args, mockContext))
        .rejects.toThrow('Invalid email or password');
    });

    it('should throw error if password is incorrect', async () => {
      // 模拟找到用户
      prisma.user.findUnique.mockImplementationOnce(() => ({
        id: 1,
        email: 'test@example.com',
        password: 'hashedpassword',
        createdAt: new Date(),
        updatedAt: new Date()
      }));
      
      // 模拟密码比较失败
      bcrypt.compare.mockImplementationOnce(() => false);
      
      const args = { email: 'test@example.com', password: 'wrongpassword' };
      
      await expect(authResolvers.Mutation.login(null, args, mockContext))
        .rejects.toThrow('Invalid email or password');
    });
  });
});
```

### 集成测试

集成测试验证多个组件一起工作的功能。这里是一个测试GraphQL端点的例子：

```typescript
// tests/integration/graphql.test.ts
import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from 'bun:test';
import { Elysia } from 'elysia';
import { createServer } from '../../src/server';
import { prisma } from '../../src/lib/prisma';
import supertest from 'supertest';
import jwt from 'jsonwebtoken';
import { config } from '../../src/config';

describe('GraphQL API Integration Tests', () => {
  let app: Elysia;
  let server: any;
  let request: supertest.SuperTest<supertest.Test>;
  let testUserToken: string;
  let testNoteId: number;

  beforeAll(async () => {
    // 设置测试数据库并启动服务器
    process.env.NODE_ENV = 'test';
    app = await createServer();
    server = app.listen(0); // 随机端口
    request = supertest(server);

    // 创建测试用户
    const hashedPassword = await bcrypt.hash('testpassword', 10);
    const user = await prisma.user.create({
      data: {
        email: 'integration@test.com',
        password: hashedPassword
      }
    });

    // 创建测试令牌
    testUserToken = jwt.sign({ userId: user.id }, config.jwt.secret);
  });

  afterAll(async () => {
    // 清理测试数据并关闭服务器
    await prisma.note.deleteMany();
    await prisma.user.deleteMany();
    await prisma.$disconnect();
    server.close();
  });

  describe('Authentication', () => {
    it('should register a new user', async () => {
      const response = await request
        .post('/graphql')
        .send({
          query: `
            mutation {
              register(email: "newuser@test.com", password: "password123") {
                token
                user {
                  id
                  email
                }
              }
            }
          `
        });

      expect(response.status).toBe(200);
      expect(response.body.data.register).toHaveProperty('token');
      expect(response.body.data.register.user).toHaveProperty('email', 'newuser@test.com');
    });

    it('should login an existing user', async () => {
      const response = await request
        .post('/graphql')
        .send({
          query: `
            mutation {
              login(email: "integration@test.com", password: "testpassword") {
                token
                user {
                  id
                  email
                }
              }
            }
          `
        });

      expect(response.status).toBe(200);
      expect(response.body.data.login).toHaveProperty('token');
      expect(response.body.data.login.user).toHaveProperty('email', 'integration@test.com');
    });
  });

  describe('Note Operations', () => {
    it('should create a new note', async () => {
      const response = await request
        .post('/graphql')
        .set('Authorization', `Bearer ${testUserToken}`)
        .send({
          query: `
            mutation {
              createNote(title: "Integration Test Note", content: "This is a test note") {
                id
                title
                content
              }
            }
          `
        });

      expect(response.status).toBe(200);
      expect(response.body.data.createNote).toHaveProperty('title', 'Integration Test Note');
      
      // 保存注释ID用于后续测试
      testNoteId = response.body.data.createNote.id;
    });

    it('should get all notes for authenticated user', async () => {
      const response = await request
        .post('/graphql')
        .set('Authorization', `Bearer ${testUserToken}`)
        .send({
          query: `
            query {
              notes {
                id
                title
                content
              }
            }
          `
        });

      expect(response.status).toBe(200);
      expect(response.body.data.notes).toBeInstanceOf(Array);
      expect(response.body.data.notes.length).toBeGreaterThan(0);
    });

    it('should update an existing note', async () => {
      const response = await request
        .post('/graphql')
        .set('Authorization', `Bearer ${testUserToken}`)
        .send({
          query: `
            mutation {
              updateNote(id: ${testNoteId}, title: "Updated Title", content: "Updated content") {
                id
                title
                content
              }
            }
          `
        });

      expect(response.status).toBe(200);
      expect(response.body.data.updateNote).toHaveProperty('title', 'Updated Title');
      expect(response.body.data.updateNote).toHaveProperty('content', 'Updated content');
    });

    it('should delete a note', async () => {
      const response = await request
        .post('/graphql')
        .set('Authorization', `Bearer ${testUserToken}`)
        .send({
          query: `
            mutation {
              deleteNote(id: ${testNoteId}) {
                id
                title
              }
            }
          `
        });

      expect(response.status).toBe(200);
      expect(response.body.data.deleteNote).toHaveProperty('id', testNoteId);
    });
  });
});
```

### 端到端测试

端到端测试验证从用户角度的完整流程：

```typescript
// tests/e2e/user-flow.test.ts
import { describe, it, expect, beforeAll, afterAll } from 'bun:test';
import { createServer } from '../../src/server';
import { prisma } from '../../src/lib/prisma';
import supertest from 'supertest';

describe('End-to-end User Flow', () => {
  let app;
  let server;
  let request;
  let userToken;
  let noteId;

  beforeAll(async () => {
    app = await createServer();
    server = app.listen(0);
    request = supertest(server);
  });

  afterAll(async () => {
    await prisma.note.deleteMany();
    await prisma.user.deleteMany();
    await prisma.$disconnect();
    server.close();
  });

  it('should register a new user', async () => {
    const response = await request
      .post('/graphql')
      .send({
        query: `
          mutation {
            register(email: "e2e@test.com", password: "password123") {
              token
              user {
                id
                email
              }
            }
          }
        `
      });

    expect(response.status).toBe(200);
    expect(response.body.data.register).toHaveProperty('token');
    expect(response.body.data.register.user).toHaveProperty('email', 'e2e@test.com');
    
    userToken = response.body.data.register.token;
  });

  it('should create a note', async () => {
    const response = await request
      .post('/graphql')
      .set('Authorization', `Bearer ${userToken}`)
      .send({
        query: `
          mutation {
            createNote(title: "E2E Test Note", content: "This is an end-to-end test") {
              id
              title
              content
            }
          }
        `
      });

    expect(response.status).toBe(200);
    expect(response.body.data.createNote).toHaveProperty('title', 'E2E Test Note');
    
    noteId = response.body.data.createNote.id;
  });

  it('should retrieve the created note', async () => {
    const response = await request
      .post('/graphql')
      .set('Authorization', `Bearer ${userToken}`)
      .send({
        query: `
          query {
            note(id: ${noteId}) {
              id
              title
              content
            }
          }
        `
      });

    expect(response.status).toBe(200);
    expect(response.body.data.note).toHaveProperty('id', noteId);
    expect(response.body.data.note).toHaveProperty('title', 'E2E Test Note');
  });

  it('should update the note', async () => {
    const response = await request
      .post('/graphql')
      .set('Authorization', `Bearer ${userToken}`)
      .send({
        query: `
          mutation {
            updateNote(id: ${noteId}, title: "Updated E2E Note") {
              id
              title
              content
            }
          }
        `
      });

    expect(response.status).toBe(200);
    expect(response.body.data.updateNote).toHaveProperty('title', 'Updated E2E Note');
  });

  it('should delete the note', async () => {
    const response = await request
      .post('/graphql')
      .set('Authorization', `Bearer ${userToken}`)
      .send({
        query: `
          mutation {
            deleteNote(id: ${noteId}) {
              id
            }
          }
        `
      });

    expect(response.status).toBe(200);
    expect(response.body.data.deleteNote).toHaveProperty('id', noteId);
  });

  it('should no longer find the deleted note', async () => {
    const response = await request
      .post('/graphql')
      .set('Authorization', `Bearer ${userToken}`)
      .send({
        query: `
          query {
            note(id: ${noteId}) {
              id
              title
            }
          }
        `
      });

    expect(response.status).toBe(200);
    expect(response.body.errors).toBeDefined();
    expect(response.body.errors[0].message).toContain('not found');
  });
});
```

## 性能测试

性能测试可以帮助识别系统的瓶颈：

1. **安装性能测试工具**：
```bash
npm install -g autocannon
```

2. **编写性能测试脚本**：
```bash
// performance-test.js
const autocannon = require('autocannon');

// 登录请求以获取token
async function getToken() {
  const result = await fetch('http://localhost:3000/graphql', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      query: `mutation { login(email: "test@example.com", password: "password123") { token } }`
    })
  });
  
  const response = await result.json();
  return response.data.login.token;
}

async function runTest() {
  const token = await getToken();
  
  const instance = autocannon({
    url: 'http://localhost:3000/graphql',
    connections: 10,
    duration: 10,
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`
    },
    requests: [
      {
        method: 'POST',
        body: JSON.stringify({
          query: `query { notes { id title } }`
        })
      }
    ]
  });
  
  autocannon.track(instance);
  
  instance.on('done', (results) => {
    console.log(results);
  });
}

runTest();
```

3. **运行性能测试**：
```bash
node performance-test.js
```

4. **分析结果**：
关注指标如每秒请求数（RPS）、延迟、错误率等。

## 安全测试

安全测试检查应用的潜在漏洞：

1. **测试身份验证边界**：
```graphql
# 测试无效令牌
query {
  notes {
    id
    title
  }
}
```

2. **测试授权边界**：
用用户A的令牌尝试访问用户B的笔记。

3. **测试输入验证**：
```graphql
# 测试特殊字符和注入
mutation {
  register(email: "test'; DROP TABLE users;--", password: "<script>alert('XSS')</script>") {
    token
  }
}
```

4. **使用安全扫描工具**：
- OWASP ZAP
- Burp Suite

## 测试最佳实践

1. **测试环境隔离**：使用专门的测试数据库和环境变量

2. **测试数据管理**：
   - 使用工厂模式创建测试数据
   - 测试后清理数据
   - 避免依赖特定数据状态

3. **断言最佳实践**：
   - 测试正向和反向案例
   - 覆盖边界条件
   - 验证状态和行为

4. **模拟外部依赖**：
   - 模拟数据库操作
   - 模拟Redis缓存
   - 模拟外部API调用

5. **代码覆盖率**：
   - 使用覆盖率工具监控测试覆盖范围
   - 针对未覆盖的代码路径添加测试

## 持续集成

将测试集成到CI/CD工作流中：

1. **设置GitHub Actions**：
```yaml
# .github/workflows/test.yml
name: Run Tests

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: ubuntu-latest

    services:
      postgres:
        image: postgres:14
        env:
          POSTGRES_USER: postgres
          POSTGRES_PASSWORD: postgres
          POSTGRES_DB: notes_test_db
        ports:
          - 5432:5432
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
      
      redis:
        image: redis
        ports:
          - 6379:6379
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5

    steps:
    - uses: actions/checkout@v2
    
    - name: Setup Bun
      uses: oven-sh/setup-bun@v1
      with:
        bun-version: latest
    
    - name: Install dependencies
      run: bun install
    
    - name: Run linting
      run: bun run lint
    
    - name: Setup test database
      run: |
        cp .env.example .env.test
        sed -i 's/notes_db/notes_test_db/g' .env.test
        sed -i 's/your-secret-key/test-secret-key/g' .env.test
        bunx prisma migrate deploy --schema=./prisma/schema.prisma
      env:
        DATABASE_URL: postgresql://postgres:postgres@localhost:5432/notes_test_db?schema=public
    
    - name: Run tests
      run: bun test
      env:
        DATABASE_URL: postgresql://postgres:postgres@localhost:5432/notes_test_db?schema=public
        JWT_SECRET: test-secret-key
        REDIS_HOST: localhost
        REDIS_PORT: 6379
```

2. **配置测试报告**：
   - 设置测试覆盖率报告
   - 配置测试结果通知
   - 在PR中显示测试状态

通过执行这些测试方法，你可以确保笔记应用后端的质量、性能和安全性。测试不仅可以捕获错误，还能帮助维护代码质量并支持未来的功能扩展。