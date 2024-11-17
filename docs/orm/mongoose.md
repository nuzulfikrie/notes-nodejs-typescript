## docs/orm/mongoose.md
```markdown
# Mongoose Integration Guide

A comprehensive guide for integrating and using Mongoose ODM in TypeScript/Node.js applications.

## Table of Contents
- [Setup & Configuration](#setup--configuration)
- [Schema Design](#schema-design)
- [Model Operations](#model-operations)
- [Relationships](#relationships)
- [Framework Integrations](#framework-integrations)
- [Advanced Features](#advanced-features)
- [Best Practices](#best-practices)

## Setup & Configuration

### Installation
```bash
# Install Mongoose and types
npm install mongoose
npm install @types/mongoose --save-dev
```

### Basic Configuration
```typescript
// config/database.config.ts
import mongoose from 'mongoose';

export const databaseConfig = {
  url: process.env.MONGODB_URI || 'mongodb://localhost:27017/your_database',
  options: {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    maxPoolSize: 10,
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 45000,
  }
};

export async function connectDatabase(): Promise<void> {
  try {
    mongoose.set('debug', process.env.NODE_ENV === 'development');
    
    await mongoose.connect(databaseConfig.url, databaseConfig.options);
    console.log('MongoDB connected successfully');

    mongoose.connection.on('error', (error) => {
      console.error('MongoDB connection error:', error);
    });

    mongoose.connection.on('disconnected', () => {
      console.warn('MongoDB disconnected');
    });

    process.on('SIGINT', async () => {
      await mongoose.connection.close();
      process.exit(0);
    });
  } catch (error) {
    console.error('MongoDB connection failed:', error);
    process.exit(1);
  }
}
```

## Schema Design

### Basic Schemas
```typescript
// models/user.model.ts
import mongoose, { Schema, Document } from 'mongoose';
import bcrypt from 'bcrypt';

export interface IUser extends Document {
  email: string;
  password: string;
  name?: string;
  role: 'user' | 'admin' | 'moderator';
  profile?: Record<string, any>;
  posts: mongoose.Types.ObjectId[];
  createdAt: Date;
  updatedAt: Date;
  comparePassword(candidatePassword: string): Promise<boolean>;
}

const userSchema = new Schema<IUser>({
  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
    trim: true,
    lowercase: true,
    validate: {
      validator: (value: string) => {
        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
      },
      message: 'Invalid email format'
    }
  },
  password: {
    type: String,
    required: true,
    minlength: [8, 'Password must be at least 8 characters'],
    select: false
  },
  name: {
    type: String,
    trim: true
  },
  role: {
    type: String,
    enum: ['user', 'admin', 'moderator'],
    default: 'user'
  },
  profile: {
    type: Schema.Types.Mixed,
    default: {}
  },
  posts: [{
    type: Schema.Types.ObjectId,
    ref: 'Post'
  }]
}, {
  timestamps: true,
  toJSON: {
    transform: (doc, ret) => {
      delete ret.password;
      return ret;
    }
  }
});

// Indexes
userSchema.index({ email: 1 });
userSchema.index({ role: 1 });
userSchema.index({ createdAt: -1 });

// Middlewares
userSchema.pre('save', async function(next) {
  if (this.isModified('password')) {
    this.password = await bcrypt.hash(this.password, 10);
  }
  next();
});

// Methods
userSchema.methods.comparePassword = async function(
  candidatePassword: string
): Promise<boolean> {
  const user = await User.findById(this._id).select('+password');
  return bcrypt.compare(candidatePassword, user.password);
};

// Statics
userSchema.statics.findByEmail = async function(email: string) {
  return this.findOne({ email });
};

export const User = mongoose.model<IUser>('User', userSchema);

// models/post.model.ts
export interface IPost extends Document {
  title: string;
  content: string;
  author: mongoose.Types.ObjectId;
  tags: string[];
  status: 'draft' | 'published' | 'archived';
  createdAt: Date;
  updatedAt: Date;
}

const postSchema = new Schema<IPost>({
  title: {
    type: String,
    required: true,
    trim: true
  },
  content: {
    type: String,
    required: true
  },
  author: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  tags: [{
    type: String,
    trim: true
  }],
  status: {
    type: String,
    enum: ['draft', 'published', 'archived'],
    default: 'draft'
  }
}, {
  timestamps: true
});

// Indexes
postSchema.index({ title: 'text', content: 'text' });
postSchema.index({ tags: 1 });
postSchema.index({ status: 1, createdAt: -1 });

export const Post = mongoose.model<IPost>('Post', postSchema);
```

## Model Operations

### Repository Pattern
```typescript
// repositories/base.repository.ts
export class BaseRepository<T extends Document> {
  constructor(private model: Model<T>) {}

  async create(data: Partial<T>): Promise<T> {
    return this.model.create(data);
  }

  async findById(id: string): Promise<T | null> {
    return this.model.findById(id);
  }

  async findOne(filter: FilterQuery<T>): Promise<T | null> {
    return this.model.findOne(filter);
  }

  async find(filter: FilterQuery<T>): Promise<T[]> {
    return this.model.find(filter);
  }

  async update(
    id: string,
    data: UpdateQuery<T>
  ): Promise<T | null> {
    return this.model.findByIdAndUpdate(
      id,
      data,
      { new: true }
    );
  }

  async delete(id: string): Promise<boolean> {
    const result = await this.model.findByIdAndDelete(id);
    return result !== null;
  }

  async paginate(options: {
    filter?: FilterQuery<T>;
    page?: number;
    limit?: number;
    sort?: Record<string, 1 | -1>;
    populate?: string | string[];
  }) {
    const {
      filter = {},
      page = 1,
      limit = 10,
      sort = { createdAt: -1 },
      populate
    } = options;

    const [data, total] = await Promise.all([
      this.model
        .find(filter)
        .sort(sort)
        .skip((page - 1) * limit)
        .limit(limit)
        .populate(populate || []),
      this.model.countDocuments(filter)
    ]);

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
export class UserRepository extends BaseRepository<IUser> {
  async findByEmail(email: string): Promise<IUser | null> {
    return this.findOne({ email });
  }

  async findWithPosts(id: string): Promise<IUser | null> {
    return this.model
      .findById(id)
      .populate({
        path: 'posts',
        select: 'title status createdAt',
        options: { sort: { createdAt: -1 } }
      });
  }
}
```

## Framework Integrations

### Express.js Integration
```typescript
// routes/users.routes.ts
import express from 'express';
import { UserRepository } from '../repositories/user.repository';
import { User } from '../models/user.model';

const router = express.Router();
const userRepository = new UserRepository(User);

router.get('/', async (req, res) => {
  try {
    const page = parseInt(req.query.page as string) || 1;
    const limit = parseInt(req.query.limit as string) || 10;
    const search = req.query.search as string;

    const filter = search ? {
      $or: [
        { email: new RegExp(search, 'i') },
        { name: new RegExp(search, 'i') }
      ]
    } : {};

    const result = await userRepository.paginate({
      filter,
      page,
      limit,
      sort: { createdAt: -1 }
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
import { connectDatabase } from '@/lib/database';
import { User } from '@/models/user.model';

export async function GET(request: Request) {
  try {
    await connectDatabase();

    const { searchParams } = new URL(request.url);
    const page = parseInt(searchParams.get('page') ?? '1');
    const limit = parseInt(searchParams.get('limit') ?? '10');
    const search = searchParams.get('q');

    const filter = search ? {
      $or: [
        { email: new RegExp(search, 'i') },
        { name: new RegExp(search, 'i') }
      ]
    } : {};

    const [users, total] = await Promise.all([
      User
        .find(filter)
        .sort({ createdAt: -1 })
        .skip((page - 1) * limit)
        .limit(limit)
        .select('-password'),
      User.countDocuments(filter)
    ]);

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
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User } from './schemas/user.schema';

@Injectable()
export class UsersService {
  constructor(
    @InjectModel(User.name)
    private readonly userModel: Model<User>
  ) {}

  async findAll(params: {
    page?: number;
    limit?: number;
    search?: string;
  }) {
    const { page = 1, limit = 10, search } = params;

    const filter = search ? {
      $or: [
        { email: new RegExp(search, 'i') },
        { name: new RegExp(search, 'i') }
      ]
    } : {};

    const [users, total] = await Promise.all([
      this.userModel
        .find(filter)
        .sort({ createdAt: -1 })
        .skip((page - 1) * limit)
        .limit(limit)
        .select('-password'),
      this.userModel.countDocuments(filter)
    ]);

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

### Aggregation Pipeline
```typescript
// services/analytics.service.ts
export class AnalyticsService {
  async getUserStats() {
    return User.aggregate([
      {
        $group: {
          _id: '$role',
          count: { $sum: 1 },
          averageAge: { $avg: '$profile.age' }
        }
      },
      {
        $sort: { count: -1 }
      }
    ]);
  }

  async getPostStats() {
    return Post.aggregate([
      {
        $group: {
          _id: {
            year: { $year: '$createdAt' },
            month: { $month: '$createdAt' }
          },
          count: { $sum: 1 }
        }
      },
      {
        $sort: {
          '_id.year': -1,
          '_id.month': -1
        }
      }
    ]);
  }
}
```

### Middleware and Plugins
```typescript
// plugins/pagination.plugin.ts
import { Schema } from 'mongoose';

export function paginationPlugin(schema: Schema) {
  schema.statics.paginate = async function(
    query = {},
    options = {}
  ) {
    const {
      page = 1,
      limit = 10,
      sort = { createdAt: -1 },
      populate
    } = options;

    const skip = (page - 1) * limit;

    const [data, total] = await Promise.all([
      this.find(query)
        .sort(sort)
        .skip(skip)
        .limit(limit)
        .populate(populate || []),
      this.countDocuments(query)
    ]);

    return {
      data,
      metadata: {
        total,
        page,
        limit,
        totalPages: Math.ceil(total / limit)
      }
    };
  };
}

// Apply plugin to schema
userSchema.plugin(paginationPlugin);
```

## Best Practices

### 1. Error Handling
```typescript
// utils/mongoose-error.ts
export class MongooseError extends Error {
  constructor(
    public code: string,
    message: string,
    public status: number = 500
  ) {
    super(message);
    this.name = 'MongooseError';
  }
}

export function handleMongooseError(error: any): MongooseError {
  if (error.code === 11000) {
    return new MongooseError(
      'DUPLICATE_KEY',
      'Record already exists',
      409
    );
  }

  if (error.name === 'ValidationError') {
    return new MongooseError(
      'VALIDATION_ERROR',
      error.message,
      400
    );
  }

  return new MongooseError(
    'INTERNAL_ERROR',
    'Internal server error',
    500
  );
}
```

### 2. Validation
```typescript
// validators/user.validator.ts
import Joi from 'joi';

export const userSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().min(8).required(),
  name: Joi.string().optional(),
  role: Joi.string().valid('user', 'admin', 'moderator')
});

// Middleware
export const validateUser = (req, res, next) => {
  const { error } = userSchema.validate(req.body);
  if (error) {
    return res.status(400).json({
      success: false,
      error: error.details[0].message
    });
  }
  next();
};

```

### 3. Indexing Strategies
```typescript
// models/indexing.example.ts
const userSchema = new Schema({
  // Single field index
  email: {
    type: String,
    index: true
  },

  // Compound index
  name: String,
  role: String,
}, {
  timestamps: true
});

// Compound index declaration
userSchema.index({ name: 1, role: 1 });

// Text index for search
userSchema.index(
  { name: 'text', email: 'text' },
  { weights: { name: 2, email: 1 } }
);

// Partial index
userSchema.index(
  { email: 1 },
  { 
    partialFilterExpression: { 
      status: 'active' 
    } 
  }
);
```

### 4. Transactions
```typescript
// services/transaction.service.ts
import mongoose from 'mongoose';

export class TransactionService {
  async transferPoints(fromUserId: string, toUserId: string, points: number) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      const [fromUser, toUser] = await Promise.all([
        User.findById(fromUserId).session(session),
        User.findById(toUserId).session(session)
      ]);

      if (!fromUser || !toUser) {
        throw new Error('User not found');
      }

      if (fromUser.points < points) {
        throw new Error('Insufficient points');
      }

      await Promise.all([
        User.findByIdAndUpdate(
          fromUserId,
          { $inc: { points: -points } },
          { session }
        ),
        User.findByIdAndUpdate(
          toUserId,
          { $inc: { points: points } },
          { session }
        )
      ]);

      await session.commitTransaction();
      return true;
    } catch (error) {
      await session.abortTransaction();
      throw error;
    } finally {
      session.endSession();
    }
  }
}
```

### 5. Caching Layer
```typescript
// services/cache.service.ts
import { createClient } from 'redis';

export class CacheService {
  private client;

  constructor() {
    this.client = createClient({
      url: process.env.REDIS_URL
    });
    this.client.connect();
  }

  private getKey(key: string): string {
    return `cache:${key}`;
  }

  async get<T>(key: string): Promise<T | null> {
    const cached = await this.client.get(this.getKey(key));
    return cached ? JSON.parse(cached) : null;
  }

  async set(key: string, value: any, ttl: number = 3600): Promise<void> {
    await this.client.set(
      this.getKey(key),
      JSON.stringify(value),
      { EX: ttl }
    );
  }

  async del(key: string): Promise<void> {
    await this.client.del(this.getKey(key));
  }
}

// Cached repository example
export class CachedUserRepository extends UserRepository {
  constructor(
    model: Model<IUser>,
    private cacheService: CacheService
  ) {
    super(model);
  }

  async findById(id: string): Promise<IUser | null> {
    const cacheKey = `user:${id}`;
    const cached = await this.cacheService.get<IUser>(cacheKey);

    if (cached) {
      return cached;
    }

    const user = await super.findById(id);
    if (user) {
      await this.cacheService.set(cacheKey, user);
    }

    return user;
  }
}
```

### 6. Change Streams
```typescript
// services/stream.service.ts
export class StreamService {
  private changeStream: ChangeStream;

  constructor(private model: Model<any>) {
    this.initializeChangeStream();
  }

  private initializeChangeStream() {
    this.changeStream = this.model.watch([], {
      fullDocument: 'updateLookup'
    });

    this.changeStream.on('change', (change) => {
      switch (change.operationType) {
        case 'insert':
          this.handleInsert(change.fullDocument);
          break;
        case 'update':
          this.handleUpdate(change.fullDocument);
          break;
        case 'delete':
          this.handleDelete(change.documentKey._id);
          break;
      }
    });

    this.changeStream.on('error', (error) => {
      console.error('Change stream error:', error);
      // Implement reconnection logic
    });
  }

  private async handleInsert(document: any) {
    // Handle insert event
    console.log('Document inserted:', document);
  }

  private async handleUpdate(document: any) {
    // Handle update event
    console.log('Document updated:', document);
  }

  private async handleDelete(documentId: string) {
    // Handle delete event
    console.log('Document deleted:', documentId);
  }

  public close() {
    if (this.changeStream) {
      this.changeStream.close();
    }
  }
}
```

### 7. Performance Optimization
```typescript
// utils/query-optimization.ts
export class QueryOptimizer {
  static async optimizeQuery(query: any) {
    // Use lean for better performance when you don't need Mongoose documents
    return query.lean();
  }

  static selectFields(fields: string[]): string {
    return fields.join(' ');
  }

  static createProjection(fields: string[]): Record<string, 1 | 0> {
    return fields.reduce((acc, field) => ({
      ...acc,
      [field]: 1
    }), {});
  }
}

// Usage example
const users = await User
  .find({})
  .select(QueryOptimizer.selectFields(['name', 'email']))
  .lean()
  .exec();
```

### 8. Audit Logging
```typescript
// plugins/audit-plugin.ts
export function auditPlugin(schema: Schema) {
  schema.pre('save', function(next) {
    if (this.isNew) {
      this._wasNew = true;
    }
    next();
  });

  schema.post('save', async function() {
    await AuditLog.create({
      action: this._wasNew ? 'create' : 'update',
      collectionName: this.constructor.modelName,
      documentId: this._id,
      changes: this.getChanges(),
      userId: this.__userId // Set by middleware
    });
  });
}

// models/audit-log.model.ts
const auditLogSchema = new Schema({
  action: {
    type: String,
    enum: ['create', 'update', 'delete'],
    required: true
  },
  collectionName: {
    type: String,
    required: true
  },
  documentId: {
    type: Schema.Types.ObjectId,
    required: true
  },
  changes: Schema.Types.Mixed,
  userId: Schema.Types.ObjectId,
  timestamp: {
    type: Date,
    default: Date.now
  }
});

export const AuditLog = model('AuditLog', auditLogSchema);
```

Remember to:
1. Always use schemas for data validation
2. Implement proper error handling
3. Use transactions for data consistency
4. Implement proper indexes
5. Use lean queries when possible
6. Implement proper caching strategy
7. Monitor query performance
8. Use change streams for real-time features
9. Implement proper logging
10. Maintain good documentation
11. Regular database maintenance
12. Use appropriate connection pooling
13. Implement proper security measures
14. Keep schemas normalized when possible
15. Use appropriate middleware and plugins

These practices will help ensure your Mongoose implementation is robust, performant, and maintainable.