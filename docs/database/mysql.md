## docs/database/mysql.md
# MySQL Integration Guide

A comprehensive guide for MySQL integration with Express.js, Next.js, and Nest.js using various ORMs and query builders.

## Table of Contents
- [Basic Setup](#basic-setup)
- [TypeORM Integration](#typeorm-integration)
- [Prisma Integration](#prisma-integration)
- [Raw Query Examples](#raw-query-examples)
- [Express.js Implementation](#expressjs-implementation)
- [Next.js Implementation](#nextjs-implementation)
- [Nest.js Implementation](#nestjs-implementation)
- [Migrations](#migrations)
- [Best Practices](#best-practices)

## Basic Setup

### Installation
```bash
# TypeORM
npm install typeorm mysql2 reflect-metadata

# Prisma
npm install @prisma/client
npm install prisma --save-dev

# Raw MySQL
npm install mysql2
```

### Database Configuration
```typescript
// config/database.config.ts
export const databaseConfig = {
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '3306'),
  username: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  connectionLimit: parseInt(process.env.DB_POOL_SIZE || '10')
};
```

## TypeORM Integration

### Entity Definition
```typescript
// entities/user.entity.ts
import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn
} from 'typeorm';

@Entity('users')
export class User {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ unique: true })
  email: string;

  @Column()
  password: string;

  @Column({ nullable: true })
  name: string;

  @Column({ default: 'user' })
  role: string;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}
```

### TypeORM Configuration
```typescript
// config/typeorm.config.ts
import { DataSource } from 'typeorm';
import { User } from '../entities/user.entity';

export const AppDataSource = new DataSource({
  type: 'mysql',
  host: process.env.DB_HOST,
  port: parseInt(process.env.DB_PORT || '3306'),
  username: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  synchronize: process.env.NODE_ENV !== 'production',
  logging: process.env.NODE_ENV !== 'production',
  entities: [User],
  migrations: ['src/migrations/*.ts'],
  subscribers: ['src/subscribers/*.ts'],
});
```

## Prisma Integration

### Prisma Schema
```prisma
// prisma/schema.prisma
datasource db {
  provider = "mysql"
  url      = env("DATABASE_URL")
}

generator client {
  provider = "prisma-client-js"
}

model User {
  id        String   @id @default(uuid())
  email     String   @unique
  password  String
  name      String?
  role      String   @default("user")
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt
}
```

## Express.js Implementation

### TypeORM Repository Pattern
```typescript
// repositories/user.repository.ts
import { Repository } from 'typeorm';
import { User } from '../entities/user.entity';

export class UserRepository {
  constructor(private repository: Repository<User>) {}

  async findAll(page: number = 1, limit: number = 10): Promise<[User[], number]> {
    return this.repository.findAndCount({
      skip: (page - 1) * limit,
      take: limit,
      order: { createdAt: 'DESC' }
    });
  }

  async findById(id: string): Promise<User | null> {
    return this.repository.findOneBy({ id });
  }

  async create(data: Partial<User>): Promise<User> {
    const user = this.repository.create(data);
    return this.repository.save(user);
  }

  async update(id: string, data: Partial<User>): Promise<User | null> {
    await this.repository.update(id, data);
    return this.findById(id);
  }

  async delete(id: string): Promise<boolean> {
    const result = await this.repository.delete(id);
    return result.affected !== 0;
  }
}

// controllers/user.controller.ts
import { Router } from 'express';
import { UserRepository } from '../repositories/user.repository';
import { AppDataSource } from '../config/typeorm.config';

const router = Router();
const userRepository = new UserRepository(
  AppDataSource.getRepository(User)
);

router.get('/', async (req, res) => {
  try {
    const page = parseInt(req.query.page as string) || 1;
    const limit = parseInt(req.query.limit as string) || 10;
    
    const [users, total] = await userRepository.findAll(page, limit);
    
    res.json({
      success: true,
      data: users,
      metadata: {
        total,
        page,
        limit
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

### Prisma Service
```typescript
// services/prisma.service.ts
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

export class UserService {
  async findAll(page: number = 1, limit: number = 10) {
    const [users, total] = await Promise.all([
      prisma.user.findMany({
        skip: (page - 1) * limit,
        take: limit,
        orderBy: { createdAt: 'desc' }
      }),
      prisma.user.count()
    ]);

    return { users, total };
  }

  async findById(id: string) {
    return prisma.user.findUnique({
      where: { id }
    });
  }

  async create(data: any) {
    return prisma.user.create({
      data
    });
  }

  async update(id: string, data: any) {
    return prisma.user.update({
      where: { id },
      data
    });
  }

  async delete(id: string) {
    await prisma.user.delete({
      where: { id }
    });
    return true;
  }
}
```

## Next.js Implementation

### API Routes with Prisma
```typescript
// app/api/users/route.ts
import { NextResponse } from 'next/server';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

export async function GET(request: Request) {
  try {
    const { searchParams } = new URL(request.url);
    const page = parseInt(searchParams.get('page') ?? '1');
    const limit = parseInt(searchParams.get('limit') ?? '10');

    const [users, total] = await Promise.all([
      prisma.user.findMany({
        skip: (page - 1) * limit,
        take: limit,
        orderBy: { createdAt: 'desc' },
        select: {
          id: true,
          email: true,
          name: true,
          role: true,
          createdAt: true
        }
      }),
      prisma.user.count()
    ]);

    return NextResponse.json({
      success: true,
      data: users,
      metadata: { total, page, limit }
    });
  } catch (error) {
    return NextResponse.json(
      { success: false, error: 'Failed to fetch users' },
      { status: 500 }
    );
  }
}

// app/api/users/[id]/route.ts
export async function GET(
  request: Request,
  { params }: { params: { id: string } }
) {
  try {
    const user = await prisma.user.findUnique({
      where: { id: params.id },
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
        createdAt: true
      }
    });

    if (!user) {
      return NextResponse.json(
        { success: false, error: 'User not found' },
        { status: 404 }
      );
    }

    return NextResponse.json({ success: true, data: user });
  } catch (error) {
    return NextResponse.json(
      { success: false, error: 'Failed to fetch user' },
      { status: 500 }
    );
  }
}
```

### Database Hooks
```typescript
// hooks/useUsers.ts
import useSWR from 'swr';

export function useUsers(page: number = 1, limit: number = 10) {
  const { data, error, mutate } = useSWR(
    `/api/users?page=${page}&limit=${limit}`
  );

  return {
    users: data?.data ?? [],
    metadata: data?.metadata,
    isLoading: !error && !data,
    isError: error,
    mutate
  };
}

export function useUser(id: string) {
  const { data, error, mutate } = useSWR(
    id ? `/api/users/${id}` : null
  );

  return {
    user: data?.data,
    isLoading: !error && !data,
    isError: error,
    mutate
  };
}
```

## Nest.js Implementation

### MySQL Module
```typescript
// database/database.module.ts
import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from './entities/user.entity';

@Module({
  imports: [
    TypeOrmModule.forRoot({
      type: 'mysql',
      host: process.env.DB_HOST,
      port: parseInt(process.env.DB_PORT || '3306'),
      username: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME,
      entities: [User],
      synchronize: process.env.NODE_ENV !== 'production'
    }),
    TypeOrmModule.forFeature([User])
  ]
})
export class DatabaseModule {}

// users/users.service.ts
import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from './entities/user.entity';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User)
    private usersRepository: Repository<User>
  ) {}

  async findAll(page: number = 1, limit: number = 10) {
    const [users, total] = await this.usersRepository.findAndCount({
      skip: (page - 1) * limit,
      take: limit,
      order: { createdAt: 'DESC' }
    });

    return { users, total };
  }

  async findOne(id: string) {
    return this.usersRepository.findOneBy({ id });
  }

  async create(data: Partial<User>) {
    const user = this.usersRepository.create(data);
    return this.usersRepository.save(user);
  }

  async update(id: string, data: Partial<User>) {
    await this.usersRepository.update(id, data);
    return this.findOne(id);
  }

  async remove(id: string) {
    const result = await this.usersRepository.delete(id);
    return result.affected !== 0;
  }
}

// users/users.controller.ts
import {
  Controller,
  Get,
  Post,
  Put,
  Delete,
  Body,
  Param,
  Query
} from '@nestjs/common';
import { UsersService } from './users.service';

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Get()
  async findAll(
    @Query('page') page: number = 1,
    @Query('limit') limit: number = 10
  ) {
    const { users, total } = await this.usersService.findAll(page, limit);
    return {
      success: true,
      data: users,
      metadata: { total, page, limit }
    };
  }

  @Get(':id')
  async findOne(@Param('id') id: string) {
    const user = await this.usersService.findOne(id);
    return { success: true, data: user };
  }

  @Post()
  async create(@Body() data: any) {
    const user = await this.usersService.create(data);
    return { success: true, data: user };
  }

  @Put(':id')
  async update(@Param('id') id: string, @Body() data: any) {
    const user = await this.usersService.update(id, data);
    return { success: true, data: user };
  }

  @Delete(':id')
  async remove(@Param('id') id: string) {
    await this.usersService.remove(id);
    return { success: true, message: 'User deleted' };
  }
}
```

## Migrations

### TypeORM Migrations
```typescript
// migrations/1634567890-CreateUsers.ts
import { MigrationInterface, QueryRunner, Table } from 'typeorm';

export class CreateUsers1634567890 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.createTable(
      new Table({
        name: 'users',
        columns: [
          {
            name: 'id',
            type: 'varchar',
            length: '36',
            isPrimary: true,
            generationStrategy: 'uuid'
          },
          {
            name: 'email',
            type: 'varchar',
            length: '255',
            isUnique: true
          },
          {
            name: 'password',
            type: 'varchar',
            length: '255'
          },
          {
            name: 'name',
            type: 'varchar',
            length: '255',
            isNullable: true
          },
          {
            name: 'role',
            type: 'varchar',
            length: '50',
            default: "'user'"
          },
          {
            name: 'created_at',
            type: 'timestamp',
            default: 'CURRENT_TIMESTAMP'
          },
          {
            name: 'updated_at',
            type: 'timestamp',
            default: 'CURRENT_TIMESTAMP',
            onUpdate: 'CURRENT_TIMESTAMP'
          }
        ]
      })
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropTable('users');
  }
}
```

## Best Practices

### 1. Connection Pool Management
```typescript
const pool = mysql.createPool({
  ...databaseConfig,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

process.on('SIGINT', async () => {
  await pool.end();
  process.exit();
});
```

### 2. Query Logging
```typescript
const queryLogger = (query: string, parameters?: any[]) => {
  console.log('Query:', query);
  if (parameters) {
    console.log('Parameters:', parameters);
  }
};
```