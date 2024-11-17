## docs/orm/prisma.md
# Prisma ORM Integration Guide

A comprehensive guide for integrating and using Prisma ORM in TypeScript/Node.js applications.

## Table of Contents
- [Setup & Configuration](#setup--configuration)
- [Schema Design](#schema-design)
- [CRUD Operations](#crud-operations)
- [Relationships](#relationships)
- [Migrations](#migrations)
- [Framework Integrations](#framework-integrations)
- [Advanced Features](#advanced-features)
- [Best Practices](#best-practices)

## Setup & Configuration

### Installation
```bash
# Install dependencies
npm install @prisma/client
npm install prisma --save-dev

# Initialize Prisma
npx prisma init

# After schema changes
npx prisma generate
```

### Basic Configuration
```typescript
// prisma/schema.prisma
datasource db {
  provider = "postgresql" // or "mysql" or "sqlite"
  url      = env("DATABASE_URL")
}

generator client {
  provider = "prisma-client-js"
  // Enable specific preview features if needed
  previewFeatures = ["fullTextSearch", "filteredRelationCount"]
}
```

## Schema Design

### Basic Models
```prisma
// prisma/schema.prisma

model User {
  id        String    @id @default(uuid())
  email     String    @unique
  password  String
  name      String?
  role      Role      @default(USER)
  posts     Post[]
  profile   Profile?
  createdAt DateTime  @default(now())
  updatedAt DateTime  @updatedAt

  @@index([email])
}

model Post {
  id        String    @id @default(uuid())
  title     String
  content   String
  published Boolean   @default(false)
  author    User      @relation(fields: [authorId], references: [id])
  authorId  String
  tags      Tag[]
  createdAt DateTime  @default(now())
  updatedAt DateTime  @updatedAt

  @@index([authorId])
  @@fulltext([title, content])
}

model Profile {
  id       String  @id @default(uuid())
  bio      String?
  avatar   String?
  user     User    @relation(fields: [userId], references: [id])
  userId   String  @unique
}

model Tag {
  id    String @id @default(uuid())
  name  String @unique
  posts Post[]
}

enum Role {
  USER
  ADMIN
  MODERATOR
}
```

## CRUD Operations

### Client Setup
```typescript
// lib/prisma.ts
import { PrismaClient } from '@prisma/client';

declare global {
  var prisma: PrismaClient | undefined;
}

export const prisma = global.prisma || new PrismaClient({
  log: process.env.NODE_ENV === 'development' 
    ? ['query', 'error', 'warn'] 
    : ['error'],
});

if (process.env.NODE_ENV !== 'production') {
  global.prisma = prisma;
}
```

### Basic Operations
```typescript
// services/user.service.ts
import { prisma } from '../lib/prisma';
import { Prisma, User } from '@prisma/client';

export class UserService {
  // Create
  async create(data: Prisma.UserCreateInput): Promise<User> {
    return prisma.user.create({
      data,
      include: {
        profile: true
      }
    });
  }

  // Read
  async findById(id: string): Promise<User | null> {
    return prisma.user.findUnique({
      where: { id },
      include: {
        profile: true,
        posts: {
          take: 5,
          orderBy: { createdAt: 'desc' }
        }
      }
    });
  }

  // Update
  async update(
    id: string,
    data: Prisma.UserUpdateInput
  ): Promise<User> {
    return prisma.user.update({
      where: { id },
      data,
      include: {
        profile: true
      }
    });
  }

  // Delete
  async delete(id: string): Promise<User> {
    return prisma.user.delete({
      where: { id }
    });
  }

  // List with pagination
  async findMany(params: {
    skip?: number;
    take?: number;
    where?: Prisma.UserWhereInput;
    orderBy?: Prisma.UserOrderByWithRelationInput;
  }) {
    const { skip, take, where, orderBy } = params;
    
    const [users, total] = await prisma.$transaction([
      prisma.user.findMany({
        skip,
        take,
        where,
        orderBy,
        include: {
          profile: true
        }
      }),
      prisma.user.count({ where })
    ]);

    return {
      users,
      metadata: {
        total,
        skip,
        take
      }
    };
  }
}
```

## Framework Integrations

### Express.js Integration
```typescript
// routes/users.routes.ts
import express from 'express';
import { UserService } from '../services/user.service';

const router = express.Router();
const userService = new UserService();

router.get('/', async (req, res) => {
  try {
    const page = parseInt(req.query.page as string) || 1;
    const limit = parseInt(req.query.limit as string) || 10;
    const search = req.query.search as string;

    const result = await userService.findMany({
      skip: (page - 1) * limit,
      take: limit,
      where: search ? {
        OR: [
          { email: { contains: search } },
          { name: { contains: search } }
        ]
      } : undefined,
      orderBy: { createdAt: 'desc' }
    });

    res.json({
      success: true,
      data: result.users,
      metadata: {
        ...result.metadata,
        page
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to fetch users'
    });
  }
});
```

### Next.js Integration
```typescript
// app/api/users/route.ts
import { NextResponse } from 'next/server';
import { prisma } from '@/lib/prisma';

export async function GET(request: Request) {
  try {
    const { searchParams } = new URL(request.url);
    const page = parseInt(searchParams.get('page') ?? '1');
    const limit = parseInt(searchParams.get('limit') ?? '10');
    const search = searchParams.get('q');

    const [users, total] = await prisma.$transaction([
      prisma.user.findMany({
        where: search ? {
          OR: [
            { email: { contains: search } },
            { name: { contains: search } }
          ]
        } : undefined,
        include: {
          profile: true
        },
        skip: (page - 1) * limit,
        take: limit,
        orderBy: { createdAt: 'desc' }
      }),
      prisma.user.count()
    ]);

    return NextResponse.json({
      success: true,
      data: users,
      metadata: {
        total,
        page,
        limit
      }
    });
  } catch (error) {
    return NextResponse.json(
      { success: false, error: 'Failed to fetch users' },
      { status: 500 }
    );
  }
}
```

### Nest.js Integration
```typescript
// prisma/prisma.service.ts
import { Injectable, OnModuleInit } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';

@Injectable()
export class PrismaService extends PrismaClient implements OnModuleInit {
  async onModuleInit() {
    await this.$connect();
  }
}

// users/users.service.ts
import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class UsersService {
  constructor(private prisma: PrismaService) {}

  async findAll(params: {
    skip?: number;
    take?: number;
    search?: string;
  }) {
    const { skip, take, search } = params;

    const [users, total] = await this.prisma.$transaction([
      this.prisma.user.findMany({
        where: search ? {
          OR: [
            { email: { contains: search } },
            { name: { contains: search } }
          ]
        } : undefined,
        include: {
          profile: true
        },
        skip,
        take,
        orderBy: { createdAt: 'desc' }
      }),
      this.prisma.user.count()
    ]);

    return { users, total };
  }
}
```

## Advanced Features

### Transactions
```typescript
// services/transaction.service.ts
async function transferPoints(
  fromUserId: string,
  toUserId: string,
  points: number
) {
  return prisma.$transaction(async (tx) => {
    // Get current balances
    const [fromUser, toUser] = await Promise.all([
      tx.user.findUnique({ where: { id: fromUserId } }),
      tx.user.findUnique({ where: { id: toUserId } })
    ]);

    if (!fromUser || !toUser) {
      throw new Error('User not found');
    }

    // Update balances
    await Promise.all([
      tx.user.update({
        where: { id: fromUserId },
        data: { points: { decrement: points } }
      }),
      tx.user.update({
        where: { id: toUserId },
        data: { points: { increment: points } }
      })
    ]);

    // Create transaction record
    await tx.pointTransaction.create({
      data: {
        fromUserId,
        toUserId,
        points,
        type: 'TRANSFER'
      }
    });
  });
}
```

### Middleware
```typescript
// middleware/prisma.middleware.ts
prisma.$use(async (params, next) => {
  const before = Date.now();

  const result = await next(params);

  const after = Date.now();
  console.log(`Query ${params.model}.${params.action} took ${after - before}ms`);

  return result;
});

// Soft Delete Middleware
prisma.$use(async (params, next) => {
  if (params.action === 'delete') {
    params.action = 'update';
    params.args['data'] = { deleted: true };
  }
  if (params.action === 'deleteMany') {
    params.action = 'updateMany';
    if (params.args.data !== undefined) {
      params.args.data['deleted'] = true;
    } else {
      params.args['data'] = { deleted: true };
    }
  }
  return next(params);
});
```

## Best Practices

### 1. Error Handling
```typescript
// utils/prisma-error.ts
export class PrismaError extends Error {
  constructor(
    public code: string,
    message: string,
    public status: number = 500
  ) {
    super(message);
    this.name = 'PrismaError';
  }
}

export function handlePrismaError(error: any): PrismaError {
  if (error.code === 'P2002') {
    return new PrismaError(
      'UNIQUE_CONSTRAINT',
      'Record already exists',
      409
    );
  }
  if (error.code === 'P2025') {
    return new PrismaError(
      'NOT_FOUND',
      'Record not found',
      404
    );
  }
  return new PrismaError(
    'INTERNAL_ERROR',
    'Internal server error',
    500
  );
}
```

### 2. Repository Pattern
```typescript
// repositories/base.repository.ts
export class BaseRepository<T> {
  constructor(
    protected readonly model: any,
    protected readonly prisma: PrismaClient
  ) {}

  async create(data: any): Promise<T> {
    return this.prisma[this.model].create({
      data
    });
  }

  async findMany(params: {
    skip?: number;
    take?: number;
    where?: any;
    orderBy?: any;
  }): Promise<{ data: T[]; total: number }> {
    const [data, total] = await this.prisma.$transaction([
      this.prisma[this.model].findMany(params),
      this.prisma[this.model].count({
        where: params.where
      })
    ]);

    return { data, total };
  }
}
```

### 3. Validation
```typescript
import { z } from 'zod';

const UserSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
  name: z.string().optional(),
  role: z.enum(['USER', 'ADMIN', 'MODERATOR'])
});

type UserInput = z.infer<typeof UserSchema>;

async function createUser(data: UserInput) {
  const validated = UserSchema.parse(data);
  return prisma.user.create({
    data: validated
  });
}
```

Remember to:
1. Use environment variables for database URLs
2. Implement proper error handling
3. Use transactions for data consistency
4. Keep schemas normalized
5. Use appropriate indexes
6. Implement proper validation
7. Use migrations for schema changes
8. Monitor query performance
9. Implement proper logging
10. Maintain good documentation