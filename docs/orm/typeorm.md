## docs/orm/typeorm.md
# TypeORM Integration Guide

A comprehensive guide for integrating and using TypeORM in TypeScript/Node.js applications.

## Table of Contents
- [Setup & Configuration](#setup--configuration)
- [Entity Design](#entity-design)
- [Database Operations](#database-operations)
- [Relationships](#relationships)
- [Migrations](#migrations)
- [Framework Integrations](#framework-integrations)
- [Advanced Features](#advanced-features)
- [Best Practices](#best-practices)

## Setup & Configuration

### Installation
```bash
# Install TypeORM and required dependencies
npm install typeorm reflect-metadata @types/node

# Install database driver
npm install pg # for PostgreSQL
# or
npm install mysql2 # for MySQL
```

### Basic Configuration
```typescript
// config/database.config.ts
import { DataSource } from 'typeorm';
import { User } from '../entities/user.entity';
import { Post } from '../entities/post.entity';

export const AppDataSource = new DataSource({
  type: 'postgres', // or 'mysql'
  host: process.env.DB_HOST,
  port: parseInt(process.env.DB_PORT || '5432'),
  username: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  synchronize: process.env.NODE_ENV !== 'production',
  logging: process.env.NODE_ENV === 'development',
  entities: [User, Post],
  migrations: ['src/migrations/**/*.ts'],
  subscribers: ['src/subscribers/**/*.ts'],
  ssl: process.env.DB_SSL === 'true' ? {
    rejectUnauthorized: false
  } : false,
});
```

## Entity Design

### Basic Entities
```typescript
// entities/base.entity.ts
import {
  PrimaryGeneratedColumn,
  CreateDateColumn,
  UpdateDateColumn,
  DeleteDateColumn
} from 'typeorm';

export abstract class BaseEntity {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  @DeleteDateColumn()
  deletedAt?: Date;
}

// entities/user.entity.ts
import {
  Entity,
  Column,
  OneToMany,
  Index,
  BeforeInsert
} from 'typeorm';
import * as bcrypt from 'bcrypt';
import { BaseEntity } from './base.entity';
import { Post } from './post.entity';

@Entity('users')
export class User extends BaseEntity {
  @Column({ unique: true })
  @Index()
  email: string;

  @Column({ select: false })
  password: string;

  @Column({ nullable: true })
  name?: string;

  @Column({
    type: 'enum',
    enum: ['user', 'admin', 'moderator'],
    default: 'user'
  })
  role: string;

  @Column('jsonb', { nullable: true })
  profile: any;

  @OneToMany(() => Post, post => post.author)
  posts: Post[];

  @BeforeInsert()
  async hashPassword() {
    if (this.password) {
      this.password = await bcrypt.hash(this.password, 10);
    }
  }

  async comparePassword(candidatePassword: string): Promise<boolean> {
    return bcrypt.compare(candidatePassword, this.password);
  }
}

// entities/post.entity.ts
import {
  Entity,
  Column,
  ManyToOne,
  ManyToMany,
  JoinTable,
  Index
} from 'typeorm';
import { BaseEntity } from './base.entity';
import { User } from './user.entity';
import { Tag } from './tag.entity';

@Entity('posts')
export class Post extends BaseEntity {
  @Column()
  @Index()
  title: string;

  @Column('text')
  content: string;

  @Column({ default: false })
  published: boolean;

  @ManyToOne(() => User, user => user.posts)
  author: User;

  @ManyToMany(() => Tag)
  @JoinTable()
  tags: Tag[];
}
```

## Database Operations

### Repository Pattern
```typescript
// repositories/base.repository.ts
import { Repository, FindOptionsWhere } from 'typeorm';

export class BaseRepository<T> {
  constructor(private repository: Repository<T>) {}

  async find(options?: FindOptionsWhere<T>): Promise<T[]> {
    return this.repository.find({ where: options });
  }

  async findOne(options: FindOptionsWhere<T>): Promise<T | null> {
    return this.repository.findOne({ where: options });
  }

  async create(data: Partial<T>): Promise<T> {
    const entity = this.repository.create(data);
    return this.repository.save(entity);
  }

  async update(
    id: string,
    data: Partial<T>
  ): Promise<T | null> {
    await this.repository.update(id, data);
    return this.findOne({ id } as FindOptionsWhere<T>);
  }

  async delete(id: string): Promise<boolean> {
    const result = await this.repository.delete(id);
    return result.affected !== 0;
  }

  async paginate(options: {
    page?: number;
    limit?: number;
    where?: FindOptionsWhere<T>;
    order?: { [key: string]: 'ASC' | 'DESC' };
  }) {
    const {
      page = 1,
      limit = 10,
      where,
      order
    } = options;

    const [data, total] = await this.repository.findAndCount({
      where,
      order,
      skip: (page - 1) * limit,
      take: limit
    });

    return {
      data,
      metadata: {
        total,
        page,
        limit,
        totalPages: Math.ceil(total / limit)
      }
    };
  }
}

// repositories/user.repository.ts
import { User } from '../entities/user.entity';
import { BaseRepository } from './base.repository';

export class UserRepository extends BaseRepository<User> {
  async findByEmail(email: string): Promise<User | null> {
    return this.findOne({ email });
  }

  async findWithPosts(id: string): Promise<User | null> {
    return this.repository.findOne({
      where: { id },
      relations: ['posts']
    });
  }
}
```

## Framework Integrations

### Express.js Integration
```typescript
// routes/users.routes.ts
import express from 'express';
import { AppDataSource } from '../config/database.config';
import { User } from '../entities/user.entity';
import { UserRepository } from '../repositories/user.repository';

const router = express.Router();
const userRepository = new UserRepository(
  AppDataSource.getRepository(User)
);

router.get('/', async (req, res) => {
  try {
    const page = parseInt(req.query.page as string) || 1;
    const limit = parseInt(req.query.limit as string) || 10;
    const search = req.query.search as string;

    const result = await userRepository.paginate({
      page,
      limit,
      where: search ? [
        { email: Like(`%${search}%`) },
        { name: Like(`%${search}%`) }
      ] : undefined,
      order: { createdAt: 'DESC' }
    });

    res.json({
      success: true,
      ...result
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
import { AppDataSource } from '@/config/database.config';
import { User } from '@/entities/user.entity';

export async function GET(request: Request) {
  try {
    const { searchParams } = new URL(request.url);
    const page = parseInt(searchParams.get('page') ?? '1');
    const limit = parseInt(searchParams.get('limit') ?? '10');
    const search = searchParams.get('q');

    const userRepository = AppDataSource.getRepository(User);
    const queryBuilder = userRepository.createQueryBuilder('user');

    if (search) {
      queryBuilder.where(
        'user.email LIKE :search OR user.name LIKE :search',
        { search: `%${search}%` }
      );
    }

    const [users, total] = await queryBuilder
      .skip((page - 1) * limit)
      .take(limit)
      .getManyAndCount();

    return NextResponse.json({
      success: true,
      data: users,
      metadata: {
        total,
        page,
        limit,
        totalPages: Math.ceil(total / limit)
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

  async findAll(params: {
    page?: number;
    limit?: number;
    search?: string;
  }) {
    const { page = 1, limit = 10, search } = params;

    const queryBuilder = this.usersRepository
      .createQueryBuilder('user');

    if (search) {
      queryBuilder.where(
        'user.email LIKE :search OR user.name LIKE :search',
        { search: `%${search}%` }
      );
    }

    const [users, total] = await queryBuilder
      .skip((page - 1) * limit)
      .take(limit)
      .getManyAndCount();

    return {
      data: users,
      metadata: {
        total,
        page,
        limit,
        totalPages: Math.ceil(total / limit)
      }
    };
  }
}
```

## Advanced Features

### Custom Repository
```typescript
// repositories/custom-user.repository.ts
import { EntityRepository, Repository } from 'typeorm';
import { User } from '../entities/user.entity';

@EntityRepository(User)
export class CustomUserRepository extends Repository<User> {
  async findByRole(role: string): Promise<User[]> {
    return this.createQueryBuilder('user')
      .where('user.role = :role', { role })
      .getMany();
  }

  async findWithFullProfile(): Promise<User[]> {
    return this.createQueryBuilder('user')
      .leftJoinAndSelect('user.posts', 'posts')
      .leftJoinAndSelect('posts.tags', 'tags')
      .getMany();
  }
}
```

### Subscribers
```typescript
// subscribers/user.subscriber.ts
import {
  EntitySubscriberInterface,
  EventSubscriber,
  InsertEvent
} from 'typeorm';
import { User } from '../entities/user.entity';

@EventSubscriber()
export class UserSubscriber implements EntitySubscriberInterface<User> {
  listenTo() {
    return User;
  }

  beforeInsert(event: InsertEvent<User>) {
    console.log(`Before user inserted: `, event.entity);
  }

  afterInsert(event: InsertEvent<User>) {
    console.log(`After user inserted: `, event.entity);
  }
}
```

### Migrations
```typescript
// migrations/1634567890-CreateUsersTable.ts
import { MigrationInterface, QueryRunner, Table } from 'typeorm';

export class CreateUsersTable1634567890 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.createTable(
      new Table({
        name: 'users',
        columns: [
          {
            name: 'id',
            type: 'uuid',
            isPrimary: true,
            generationStrategy: 'uuid',
            default: 'uuid_generate_v4()'
          },
          {
            name: 'email',
            type: 'varchar',
            isUnique: true
          },
          {
            name: 'password',
            type: 'varchar'
          },
          {
            name: 'role',
            type: 'enum',
            enum: ['user', 'admin', 'moderator'],
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

### 1. Connection Management
```typescript
// utils/database.ts
export class DatabaseManager {
  private static isInitialized = false;

  static async initialize() {
    if (!this.isInitialized) {
      try {
        await AppDataSource.initialize();
        this.isInitialized = true;
        console.log('Database connected');
      } catch (error) {
        console.error('Database connection failed:', error);
        process.exit(1);
      }
    }
  }

  static async destroy() {
    if (this.isInitialized) {
      await AppDataSource.destroy();
      this.isInitialized = false;
    }
  }
}

// Graceful shutdown
process.on('SIGINT', async () => {
  await DatabaseManager.destroy();
  process.exit(0);
});
```

### 2. Error Handling
```typescript
// utils/typeorm-error.ts
export class TypeORMError extends Error {
  constructor(
    public code: string,
    message: string,
    public status: number = 500
  ) {
    super(message);
    this.name = 'TypeORMError';
  }
}

export function handleTypeORMError(error: any): TypeORMError {
  if (error.code === '23505') { // Unique violation
    return new TypeORMError(
      'UNIQUE_VIOLATION',
      'Record already exists',
      409
    );
  }
  // Add more error handlers
  return new TypeORMError(
    'INTERNAL_ERROR',
    'Internal server error',
    500
  );
}
```

Remember to:
1. Use repository pattern
2. Implement proper error handling
3. Use transactions when needed
4. Keep entities normalized
5. Use appropriate indexes
6. Implement proper validation
7. Use migrations in production
8. Monitor query performance
9. Implement proper logging
10. Maintain good documentation