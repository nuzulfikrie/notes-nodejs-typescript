## docs/database/postgresql.md
# PostgreSQL Integration Guide

A comprehensive guide for PostgreSQL integration with Express.js, Next.js, and Nest.js using various ORMs and query builders.

## Table of Contents
- [Basic Setup](#basic-setup)
- [TypeORM Integration](#typeorm-integration)
- [Prisma Integration](#prisma-integration)
- [Raw Query Examples](#raw-query-examples)
- [Express.js Implementation](#expressjs-implementation)
- [Next.js Implementation](#nextjs-implementation)
- [Nest.js Implementation](#nestjs-implementation)
- [Advanced Features](#advanced-features)
- [Best Practices](#best-practices)

## Basic Setup

### Installation
```bash
# TypeORM
npm install typeorm pg reflect-metadata

# Prisma
npm install @prisma/client
npm install prisma --save-dev

# Raw PostgreSQL
npm install pg
```

### Database Configuration
```typescript
// config/database.config.ts
export const databaseConfig = {
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '5432'),
  username: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  ssl: process.env.DB_SSL === 'true' ? {
    rejectUnauthorized: false
  } : false
};
```

## TypeORM Integration

### Entity Definition with PostgreSQL Features
```typescript
// entities/user.entity.ts
import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  Index
} from 'typeorm';

@Entity('users')
export class User {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'varchar', length: 255 })
  @Index({ unique: true })
  email: string;

  @Column({ type: 'varchar', length: 255 })
  password: string;

  @Column({ type: 'jsonb', nullable: true })
  profile: any;

  @Column({
    type: 'enum',
    enum: ['user', 'admin', 'moderator'],
    default: 'user'
  })
  role: string;

  @Column('text', { array: true, default: [] })
  permissions: string[];

  @CreateDateColumn({ type: 'timestamptz' })
  createdAt: Date;

  @UpdateDateColumn({ type: 'timestamptz' })
  updatedAt: Date;

  @Column({ type: 'tstzrange', nullable: true })
  validityPeriod: any;
}
```

### PostgreSQL-Specific TypeORM Configuration
```typescript
// config/typeorm.config.ts
import { DataSource } from 'typeorm';
import { User } from '../entities/user.entity';

export const AppDataSource = new DataSource({
  type: 'postgres',
  host: process.env.DB_HOST,
  port: parseInt(process.env.DB_PORT || '5432'),
  username: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  synchronize: process.env.NODE_ENV !== 'production',
  logging: process.env.NODE_ENV !== 'production',
  entities: [User],
  migrations: ['src/migrations/*.ts'],
  subscribers: ['src/subscribers/*.ts'],
  ssl: process.env.DB_SSL === 'true' ? {
    rejectUnauthorized: false
  } : false,
  extra: {
    max: 20,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 2000,
  }
});
```

## Prisma Integration

### Prisma Schema with PostgreSQL Features
```prisma
// prisma/schema.prisma
datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}

generator client {
  provider = "prisma-client-js"
  previewFeatures = ["fullTextSearch"]
}

model User {
  id             String    @id @default(uuid())
  email          String    @unique
  password       String
  profile        Json?
  role           Role      @default(USER)
  permissions    String[]
  createdAt      DateTime  @default(now())
  updatedAt      DateTime  @updatedAt
  validityPeriod Json?     // Stored as JSONB

  @@index([email])
}

enum Role {
  USER
  ADMIN
  MODERATOR
}
```

## Express.js Implementation

### Repository Pattern with PostgreSQL Features
```typescript
// repositories/user.repository.ts
import { Repository } from 'typeorm';
import { User } from '../entities/user.entity';

export class UserRepository {
  constructor(private repository: Repository<User>) {}

  async findAllWithSearch(
    search: string,
    page: number = 1,
    limit: number = 10
  ): Promise<[User[], number]> {
    return this.repository
      .createQueryBuilder('user')
      .where(
        'user.email ILIKE :search OR user.profile->\'name\' ILIKE :search',
        { search: `%${search}%` }
      )
      .skip((page - 1) * limit)
      .take(limit)
      .orderBy('user.createdAt', 'DESC')
      .getManyAndCount();
  }

  async findByPermissions(permissions: string[]): Promise<User[]> {
    return this.repository
      .createQueryBuilder('user')
      .where('user.permissions @> ARRAY[:...permissions]::text[]', {
        permissions
      })
      .getMany();
  }

  async updateProfile(id: string, profile: any): Promise<User | null> {
    await this.repository
      .createQueryBuilder()
      .update(User)
      .set({ profile })
      .where('id = :id', { id })
      .execute();

    return this.findById(id);
  }

  async searchFullText(query: string): Promise<User[]> {
    return this.repository
      .createQueryBuilder('user')
      .where(
        `to_tsvector('english', 
          user.email || ' ' || 
          COALESCE(user.profile->>'name', '') || ' ' || 
          COALESCE(user.profile->>'bio', '')
        ) @@ to_tsquery('english', :query)`,
        { query: query.split(' ').join(' & ') }
      )
      .getMany();
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

router.get('/search', async (req, res) => {
  try {
    const { query } = req.query;
    const users = await userRepository.searchFullText(query as string);
    res.json({ success: true, data: users });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Search failed'
    });
  }
});
```

## Next.js Implementation

### API Routes with Advanced PostgreSQL Features
```typescript
// app/api/users/search/route.ts
import { NextResponse } from 'next/server';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

export async function GET(request: Request) {
  try {
    const { searchParams } = new URL(request.url);
    const query = searchParams.get('q') ?? '';
    const page = parseInt(searchParams.get('page') ?? '1');
    const limit = parseInt(searchParams.get('limit') ?? '10');

    const users = await prisma.$queryRaw`
      SELECT *
      FROM "User"
      WHERE to_tsvector('english', 
        email || ' ' || 
        COALESCE(profile->>'name', '') || ' ' || 
        COALESCE(profile->>'bio', '')
      ) @@ to_tsquery('english', ${query.split(' ').join(' & ')})
      ORDER BY "createdAt" DESC
      LIMIT ${limit}
      OFFSET ${(page - 1) * limit}
    `;

    const total = await prisma.$queryRaw`
      SELECT COUNT(*)
      FROM "User"
      WHERE to_tsvector('english', 
        email || ' ' || 
        COALESCE(profile->>'name', '') || ' ' || 
        COALESCE(profile->>'bio', '')
      ) @@ to_tsquery('english', ${query.split(' ').join(' & ')})
    `;

    return NextResponse.json({
      success: true,
      data: users,
      metadata: { total: total[0].count, page, limit }
    });
  } catch (error) {
    return NextResponse.json(
      { success: false, error: 'Search failed' },
      { status: 500 }
    );
  }
}
```

### Database Hooks with PostgreSQL Features
```typescript
// hooks/useUserSearch.ts
import useSWR from 'swr';

export function useUserSearch(
  query: string,
  page: number = 1,
  limit: number = 10
) {
  const { data, error, mutate } = useSWR(
    query ? `/api/users/search?q=${query}&page=${page}&limit=${limit}` : null
  );

  return {
    users: data?.data ?? [],
    metadata: data?.metadata,
    isLoading: !error && !data,
    isError: error,
    mutate
  };
}
```

## Nest.js Implementation

### PostgreSQL-Specific Service
```typescript
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

  async searchUsers(
    query: string,
    page: number = 1,
    limit: number = 10
  ) {
    const queryBuilder = this.usersRepository.createQueryBuilder('user');
    
    if (query) {
      queryBuilder.where(
        `to_tsvector('english', 
          user.email || ' ' || 
          COALESCE(user.profile->>'name', '') || ' ' || 
          COALESCE(user.profile->>'bio', '')
        ) @@ to_tsquery('english', :query)`,
        { query: query.split(' ').join(' & ') }
      );
    }

    const [users, total] = await queryBuilder
      .skip((page - 1) * limit)
      .take(limit)
      .getManyAndCount();

    return { users, total };
  }

  async updateUserProfile(id: string, profile: any) {
    return this.usersRepository
      .createQueryBuilder()
      .update(User)
      .set({ profile })
      .where('id = :id', { id })
      .returning('*')
      .execute()
      .then(result => result.raw[0]);
  }

  async getUsersByPermissions(permissions: string[]) {
    return this.usersRepository
      .createQueryBuilder('user')
      .where('user.permissions @> ARRAY[:...permissions]::text[]', {
        permissions
      })
      .getMany();
  }
}

// users/users.controller.ts
import {
  Controller,
  Get,
  Post,
  Put,
  Query,
  Body,
  Param
} from '@nestjs/common';
import { UsersService } from './users.service';

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Get('search')
  async searchUsers(
    @Query('q') query: string,
    @Query('page') page: number = 1,
    @Query('limit') limit: number = 10
  ) {
    const { users, total } = await this.usersService
      .searchUsers(query, page, limit);
      
    return {
      success: true,
      data: users,
      metadata: { total, page, limit }
    };
  }

  @Put(':id/profile')
  async updateProfile(
    @Param('id') id: string,
    @Body() profile: any
  ) {
    const user = await this.usersService
      .updateUserProfile(id, profile);
      
    return { success: true, data: user };
  }
}
```

## Advanced Features

### Full-Text Search Implementation
```typescript
// utils/search.utils.ts
export const createSearchQuery = (
  fields: string[],
  query: string
) => {
  const vectorFields = fields
    .map(field => `COALESCE(${field}, '')`)
    .join(" || ' ' || ");

  return `
    to_tsvector('english', ${vectorFields}) @@ 
    to_tsquery('english', '${query.split(' ').join(' & ')}')
  `;
};

// Usage
const searchUsers = async (query: string) => {
  return prisma.$queryRaw`
    SELECT *
    FROM "User"
    WHERE ${createSearchQuery(
      ['email', 'profile->>\'name\'', 'profile->>\'bio\''],
      query
    )}
    ORDER BY ts_rank(
      to_tsvector('english', 
        email || ' ' || 
        COALESCE(profile->>'name', '') || ' ' || 
        COALESCE(profile->>'bio', '')
      ),
      to_tsquery('english', ${query.split(' ').join(' & ')})
    ) DESC
  `;
};
```

### JSON/JSONB Operations
```typescript
// utils/jsonb.utils.ts
export const jsonbOperations = {
  updateNestedField: (
    table: string,
    jsonField: string,
    path: string[],
    value: any
  ) => `
    UPDATE "${table}"
    SET ${jsonField} = jsonb_set(
      ${jsonField},
      '{${path.join(',')}}',
      '${JSON.stringify(value)}'::jsonb
    )
  `,

  appendToArray: (
    table: string,
    jsonField: string,
    path: string[],
    value: any
  ) => `
    UPDATE "${table}"
    SET ${jsonField} = jsonb_set(
      ${jsonField},
      '{${path.join(',')}}',
      (
        COALESCE(
          ${jsonField}#>'{${path.join(',')}}'::text[],
          '[]'::jsonb
        ) || '${JSON.stringify(value)}'::jsonb
      )
    )
  `
};
```

### Database Functions and Triggers
```sql
-- functions/update_updated_at.sql
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_user_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at();

-- functions/audit_log.sql
CREATE TABLE audit_logs (
    id SERIAL PRIMARY KEY,
    table_name TEXT NOT NULL,
    record_id UUID NOT NULL,
    action TEXT NOT NULL,
    old_data JSONB,
    new_data JSONB,
    user_id UUID,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE OR REPLACE FUNCTION audit_log()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO audit_logs (
        table_name,
        record_id,
        action,
        old_data,
        new_data,
        user_id
    ) VALUES (
        TG_TABLE_NAME,
        COALESCE(NEW.id, OLD.id),
        TG_OP,
        CASE WHEN TG_OP = 'DELETE' THEN row_to_json(OLD)::jsonb ELSE NULL END,
        CASE WHEN TG_OP IN ('INSERT', 'UPDATE') THEN row_to_json(NEW)::jsonb ELSE NULL END,
        current_setting('app.current_user_id', TRUE)::uuid
    );
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER audit_users
    AFTER INSERT OR UPDATE OR DELETE ON users
    FOR EACH ROW
    EXECUTE FUNCTION audit_log();
```

### Database Migrations

```typescript
// migrations/1634567890-CreateUsersWithAdvancedFeatures.ts
import { MigrationInterface, QueryRunner } from 'typeorm';

export class CreateUsersWithAdvancedFeatures1634567890 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    // Create enum type
    await queryRunner.query(`
      CREATE TYPE user_role AS ENUM ('user', 'admin', 'moderator');
    `);

    // Create users table with advanced PostgreSQL features
    await queryRunner.query(`
      CREATE TABLE users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        profile JSONB,
        role user_role DEFAULT 'user',
        permissions TEXT[] DEFAULT ARRAY[]::TEXT[],
        created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
        validity_period TSTZRANGE,
        search_vector TSVECTOR
      );

      -- Create indexes
      CREATE INDEX users_email_idx ON users (email);
      CREATE INDEX users_profile_gin_idx ON users USING GIN (profile);
      CREATE INDEX users_permissions_gin_idx ON users USING GIN (permissions);
      CREATE INDEX users_search_vector_idx ON users USING GIN (search_vector);

      -- Create search vector update trigger
      CREATE TRIGGER users_vector_update
        BEFORE INSERT OR UPDATE ON users
        FOR EACH ROW
        EXECUTE FUNCTION 
          tsvector_update_trigger(
            search_vector, 'pg_catalog.english',
            email, profile->>'name', profile->>'bio'
          );
    `);

    // Create audit logging
    await queryRunner.query(`
      CREATE TABLE audit_logs (
        id SERIAL PRIMARY KEY,
        table_name TEXT NOT NULL,
        record_id UUID NOT NULL,
        action TEXT NOT NULL,
        old_data JSONB,
        new_data JSONB,
        user_id UUID,
        created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
      );

      CREATE INDEX audit_logs_record_id_idx ON audit_logs (record_id);
      CREATE INDEX audit_logs_user_id_idx ON audit_logs (user_id);
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP TABLE IF EXISTS audit_logs`);
    await queryRunner.query(`DROP TABLE IF EXISTS users`);
    await queryRunner.query(`DROP TYPE IF EXISTS user_role`);
  }
}
```

### Connection Management and Pooling

```typescript
// utils/db-pool.ts
import { Pool } from 'pg';

export class DatabasePool {
  private static instance: Pool;
  
  private static config = {
    max: 20,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 2000,
    statement_timeout: 10000, // 10s
    query_timeout: 10000,     // 10s
    application_name: 'your_app_name'
  };

  static getInstance(): Pool {
    if (!DatabasePool.instance) {
      DatabasePool.instance = new Pool({
        ...databaseConfig,
        ...DatabasePool.config
      });

      DatabasePool.instance.on('error', (err) => {
        console.error('Unexpected error on idle client', err);
        process.exit(-1);
      });

      DatabasePool.instance.on('connect', (client) => {
        client.query(`SET application_name TO '${DatabasePool.config.application_name}'`);
      });
    }
    return DatabasePool.instance;
  }

  static async end(): Promise<void> {
    if (DatabasePool.instance) {
      await DatabasePool.instance.end();
    }
  }
}

// Graceful shutdown
process.on('SIGTERM', async () => {
  await DatabasePool.end();
  process.exit(0);
});
```

### Query Builder Utilities

```typescript
// utils/query-builder.ts
export class PostgresQueryBuilder {
  static fullTextSearch(fields: string[], query: string) {
    const searchQuery = query
      .split(' ')
      .filter(Boolean)
      .map(term => `${term}:*`)
      .join(' & ');

    return `
      to_tsvector('english', ${fields.join(" || ' ' || ")}) @@ 
      to_tsquery('english', '${searchQuery}')
    `;
  }

  static jsonbQuery(path: string[], operator: string, value: any) {
    const jsonPath = path.join('->');
    return `profile->${jsonPath} ${operator} '${JSON.stringify(value)}'`;
  }

  static arrayContains(field: string, values: any[]) {
    return `${field} @> ARRAY[${values.map(v => `'${v}'`).join(',')}]::text[]`;
  }

  static dateRangeOverlaps(field: string, start: Date, end: Date) {
    return `${field} && daterange('${start.toISOString()}', '${end.toISOString()}')`;
  }
}
```

### Transaction Management

```typescript
// utils/transaction.ts
export class TransactionManager {
  static async execute<T>(
    callback: (client: PoolClient) => Promise<T>
  ): Promise<T> {
    const client = await DatabasePool.getInstance().connect();
    
    try {
      await client.query('BEGIN');
      const result = await callback(client);
      await client.query('COMMIT');
      return result;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }
}

// Usage example
async function transferFunds(
  fromUserId: string,
  toUserId: string,
  amount: number
) {
  return TransactionManager.execute(async (client) => {
    // Deduct from sender
    await client.query(
      'UPDATE accounts SET balance = balance - $1 WHERE user_id = $2',
      [amount, fromUserId]
    );

    // Add to receiver
    await client.query(
      'UPDATE accounts SET balance = balance + $1 WHERE user_id = $2',
      [amount, toUserId]
    );

    // Return updated balances
    const { rows } = await client.query(
      'SELECT user_id, balance FROM accounts WHERE user_id = ANY($1)',
      [[fromUserId, toUserId]]
    );
    
    return rows;
  });
}
```

### Performance Optimization

```typescript
// utils/query-optimization.ts
export class QueryOptimizer {
  static async analyzeTable(tableName: string) {
    const client = await DatabasePool.getInstance().connect();
    try {
      await client.query(`ANALYZE ${tableName}`);
    } finally {
      client.release();
    }
  }

  static createIndexes(tableName: string) {
    return [
      `CREATE INDEX IF NOT EXISTS ${tableName}_created_at_idx 
       ON ${tableName} (created_at DESC)`,
      `CREATE INDEX IF NOT EXISTS ${tableName}_updated_at_idx 
       ON ${tableName} (updated_at DESC)`,
      `CREATE INDEX IF NOT EXISTS ${tableName}_search_gin_idx 
       ON ${tableName} USING GIN (search_vector)`
    ];
  }

  static async vacuum(tableName: string) {
    const client = await DatabasePool.getInstance().connect();
    try {
      // Disable connection timeout for VACUUM
      await client.query('SET statement_timeout = 0');
      await client.query(`VACUUM ANALYZE ${tableName}`);
    } finally {
      client.release();
    }
  }
}
```

### Error Handling

```typescript
// utils/db-error-handler.ts
export class DatabaseError extends Error {
  constructor(
    public code: string,
    message: string,
    public details?: any
  ) {
    super(message);
    this.name = 'DatabaseError';
  }
}

export class DatabaseErrorHandler {
  static handle(error: any) {
    switch (error.code) {
      case '23505': // unique_violation
        throw new DatabaseError(
          'DUPLICATE_ENTRY',
          'Record already exists',
          error.detail
        );
      
      case '23503': // foreign_key_violation
        throw new DatabaseError(
          'FOREIGN_KEY_VIOLATION',
          'Referenced record does not exist',
          error.detail
        );
      
      case '42P01': // undefined_table
        throw new DatabaseError(
          'TABLE_NOT_FOUND',
          'Table does not exist',
          error.message
        );
      
      default:
        throw new DatabaseError(
          'UNKNOWN_ERROR',
          'An unexpected database error occurred',
          error
        );
    }
  }
}
```

## Best Practices

1. **Connection Management**
   - Use connection pooling
   - Implement proper error handling
   - Set appropriate timeouts
   - Monitor connection usage

2. **Query Optimization**
   - Use appropriate indexes
   - Implement efficient search strategies
   - Use EXPLAIN ANALYZE for query optimization
   - Implement query caching when appropriate

3. **Data Integrity**
   - Use transactions for data consistency
   - Implement proper constraints
   - Use triggers for data validation
   - Implement audit logging

4. **Security**
   - Use parameterized queries
   - Implement proper access controls
   - Use SSL for connections
   - Regular security audits

5. **Monitoring**
   - Track query performance
   - Monitor connection pools
   - Implement proper logging
   - Set up alerts for potential issues

6. **Maintenance**
   - Regular VACUUM and ANALYZE
   - Index maintenance
   - Regular backups
   - Database cleanup routines

Remember to:
- Always use connection pools
- Implement proper error handling
- Use transactions when necessary
- Optimize queries for performance
- Implement proper security measures
- Maintain good documentation