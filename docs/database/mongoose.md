## docs/database/mongoose.md
```markdown
# MongoDB/Mongoose Integration Guide

A comprehensive guide for MongoDB integration using Mongoose with Express.js, Next.js, and Nest.js frameworks.

## Table of Contents
- [Basic Setup](#basic-setup)
- [Schema Design](#schema-design)
- [Model Creation](#model-creation)
- [Express.js Implementation](#expressjs-implementation)
- [Next.js Implementation](#nextjs-implementation)
- [Nest.js Implementation](#nestjs-implementation)
- [Advanced Features](#advanced-features)
- [Best Practices](#best-practices)

## Basic Setup

### Installation
```bash
npm install mongoose
```

### Database Configuration
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

export async function connectDatabase() {
  try {
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
  createdAt: Date;
  updatedAt: Date;
  comparePassword(candidatePassword: string): Promise<boolean>;
}

const userSchema = new Schema<IUser>({
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true
  },
  password: {
    type: String,
    required: true,
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
  }
}, {
  timestamps: true,
  toJSON: {
    transform: (doc, ret) => {
      delete ret.password;
      return ret;
    }
  }
});

// Middleware
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
  return bcrypt.compare(candidatePassword, this.password);
};

// Indexes
userSchema.index({ email: 1 });
userSchema.index({ createdAt: -1 });
userSchema.index({ 'profile.name': 'text', email: 'text' });

export const User = mongoose.model<IUser>('User', userSchema);
```

### Relationship Schema Example
```typescript
// models/post.model.ts
import mongoose, { Schema, Document } from 'mongoose';
import { IUser } from './user.model';

export interface IPost extends Document {
  title: string;
  content: string;
  author: IUser['_id'];
  tags: string[];
  status: 'draft' | 'published' | 'archived';
  comments: {
    user: IUser['_id'];
    content: string;
    createdAt: Date;
  }[];
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
  },
  comments: [{
    user: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      required: true
    },
    content: {
      type: String,
      required: true
    },
    createdAt: {
      type: Date,
      default: Date.now
    }
  }]
}, {
  timestamps: true
});

// Indexes
postSchema.index({ title: 'text', content: 'text' });
postSchema.index({ tags: 1 });
postSchema.index({ status: 1, createdAt: -1 });

export const Post = mongoose.model<IPost>('Post', postSchema);
```

## Express.js Implementation

### Repository Pattern
```typescript
// repositories/base.repository.ts
export class BaseRepository<T extends Document> {
  constructor(private model: Model<T>) {}

  async findAll(
    filter = {},
    projection = {},
    options = { sort: { createdAt: -1 } }
  ): Promise<T[]> {
    return this.model.find(filter, projection, options);
  }

  async findById(id: string): Promise<T | null> {
    return this.model.findById(id);
  }

  async create(data: Partial<T>): Promise<T> {
    return this.model.create(data);
  }

  async update(
    id: string,
    data: Partial<T>,
    options = { new: true }
  ): Promise<T | null> {
    return this.model.findByIdAndUpdate(id, data, options);
  }

  async delete(id: string): Promise<boolean> {
    const result = await this.model.findByIdAndDelete(id);
    return result !== null;
  }

  async paginate(
    filter = {},
    page = 1,
    limit = 10,
    sort = { createdAt: -1 }
  ) {
    const [data, total] = await Promise.all([
      this.model
        .find(filter)
        .sort(sort)
        .skip((page - 1) * limit)
        .limit(limit),
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
  constructor() {
    super(User);
  }

  async findByEmail(email: string): Promise<IUser | null> {
    return User.findOne({ email });
  }

  async searchUsers(query: string): Promise<IUser[]> {
    return User.find(
      { $text: { $search: query } },
      { score: { $meta: 'textScore' } }
    ).sort({ score: { $meta: 'textScore' } });
  }
}

// controllers/user.controller.ts
import { Router } from 'express';
import { UserRepository } from '../repositories/user.repository';

const router = Router();
const userRepository = new UserRepository();

router.get('/', async (req, res) => {
  try {
    const page = parseInt(req.query.page as string) || 1;
    const limit = parseInt(req.query.limit as string) || 10;
    
    const result = await userRepository.paginate({}, page, limit);
    
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

## Next.js Implementation

### API Routes with Mongoose
```typescript
// lib/db.ts
import mongoose from 'mongoose';

const MONGODB_URI = process.env.MONGODB_URI!;

let cached = global.mongoose;

if (!cached) {
  cached = global.mongoose = { conn: null, promise: null };
}

export async function connectDB() {
  if (cached.conn) {
    return cached.conn;
  }

  if (!cached.promise) {
    cached.promise = mongoose.connect(MONGODB_URI, databaseConfig.options);
  }

  cached.conn = await cached.promise;
  return cached.conn;
}

// app/api/users/route.ts
import { NextResponse } from 'next/server';
import { connectDB } from '@/lib/db';
import { User } from '@/models/user.model';

export async function GET(request: Request) {
  try {
    await connectDB();

    const { searchParams } = new URL(request.url);
    const page = parseInt(searchParams.get('page') ?? '1');
    const limit = parseInt(searchParams.get('limit') ?? '10');
    const search = searchParams.get('q');

    const query = search
      ? { $text: { $search: search } }
      : {};

    const [users, total] = await Promise.all([
      User
        .find(query)
        .select('-password')
        .sort({ createdAt: -1 })
        .skip((page - 1) * limit)
        .limit(limit),
      User.countDocuments(query)
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

// app/api/users/[id]/route.ts
export async function GET(
  request: Request,
  { params }: { params: { id: string } }
) {
  try {
    await connectDB();

    const user = await User
      .findById(params.id)
      .select('-password');

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

## Nest.js Implementation

### Mongoose Module
```typescript
// database/database.module.ts
import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { databaseConfig } from '../config/database.config';

@Module({
  imports: [
    MongooseModule.forRoot(databaseConfig.url, databaseConfig.options)
  ]
})
export class DatabaseModule {}

// users/schemas/user.schema.ts
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

@Schema({ timestamps: true })
export class User {
  @Prop({
    required: true,
    unique: true,
    trim: true,
    lowercase: true
  })
  email: string;

  @Prop({ required: true })
  password: string;

  @Prop({ trim: true })
  name?: string;

  @Prop({
    type: String,
    enum: ['user', 'admin', 'moderator'],
    default: 'user'
  })
  role: string;

  @Prop({ type: Object, default: {} })
  profile: Record<string, any>;
}

export type UserDocument = User & Document;
export const UserSchema = SchemaFactory.createForClass(User);

// Add methods and middleware
UserSchema.methods.comparePassword = async function(
  candidatePassword: string
): Promise<boolean> {
  return bcrypt.compare(candidatePassword, this.password);
};

UserSchema.pre('save', async function(next) {
  if (this.isModified('password')) {
    this.password = await bcrypt.hash(this.password, 10);
  }
  next();
});

// users/users.service.ts
import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User, UserDocument } from './schemas/user.schema';

@Injectable()
export class UsersService {
  constructor(
    @InjectModel(User.name)
    private userModel: Model<UserDocument>
  ) {}

  async findAll(
    page: number = 1,
    limit: number = 10,
    search?: string
  ) {
    const query = search
      ? { $text: { $search: search } }
      : {};

    const [users, total] = await Promise.all([
      this.userModel
        .find(query)
        .select('-password')
        .sort({ createdAt: -1 })
        .skip((page - 1) * limit)
        .limit(limit),
      this.userModel.countDocuments(query)
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

  async findById(id: string) {
    return this.userModel
      .findById(id)
      .select('-password');
  }

  async create(data: Partial<User>) {
    const user = new this.userModel(data);
    return user.save();
  }

  async update(id: string, data: Partial<User>) {
    return this.userModel
      .findByIdAndUpdate(id, data, { new: true })
      .select('-password');
  }

  async delete(id: string) {
    await this.userModel.findByIdAndDelete(id);
    return true;
  }
}

// users/users.controller.ts
import { Controller, Get, Post, Put, Delete, Query, Body, Param } from '@nestjs/common';
import { UsersService } from './users.service';

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Get()
  async findAll(
    @Query('page') page: number = 1,
    @Query('limit') limit: number = 10,
    @Query('search') search?: string
  ) {
    const result = await this.usersService.findAll(page, limit, search);
    return {
      success: true,
      ...result
    };
  }

  @Get(':id')
  async findOne(@Param('id') id: string) {
    const user = await this.usersService.findById(id);
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
    await this.usersService.delete(id);
    return { 
      success: true, 
      message: 'User deleted successfully' 
    };
  }
}
```

## Advanced Features

### Aggregation Pipeline
```typescript
// services/analytics.service.ts
export class AnalyticsService {
  constructor(
    @InjectModel(User.name)
    private userModel: Model<UserDocument>
  ) {}

  async getUserStats() {
    return this.userModel.aggregate([
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

  async getActiveUsers(days: number) {
    const date = new Date();
    date.setDate(date.getDate() - days);

    return this.userModel.aggregate([
      {
        $match: {
          lastLoginDate: { $gte: date }
        }
      },
      {
        $group: {
          _id: {
            year: { $year: '$lastLoginDate' },
            month: { $month: '$lastLoginDate' },
            day: { $dayOfMonth: '$lastLoginDate' }
          },
          count: { $sum: 1 }
        }
      },
      {
        $sort: {
          '_id.year': 1,
          '_id.month': 1,
          '_id.day': 1
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

interface PaginateOptions {
  page?: number;
  limit?: number;
  sort?: Record<string, 1 | -1>;
}

interface PaginateResult<T> {
  data: T[];
  metadata: {
    total: number;
    page: number;
    limit: number;
    totalPages: number;
  };
}

export function paginationPlugin(schema: Schema) {
  schema.statics.paginate = async function<T>(
    query: any = {},
    options: PaginateOptions = {}
  ): Promise<PaginateResult<T>> {
    const {
      page = 1,
      limit = 10,
      sort = { createdAt: -1 }
    } = options;

    const skip = (page - 1) * limit;

    const [data, total] = await Promise.all([
      this.find(query)
        .sort(sort)
        .skip(skip)
        .limit(limit),
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

// models/user.model.ts
userSchema.plugin(paginationPlugin);
```

### Transactions
```typescript
// services/transaction.service.ts
export class TransactionService {
  async transferPoints(
    fromUserId: string,
    toUserId: string,
    points: number
  ) {
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

### Change Streams
```typescript
// services/stream.service.ts
export class StreamService {
  private changeStream: ChangeStream;

  constructor(private userModel: Model<UserDocument>) {
    this.initializeChangeStream();
  }

  private initializeChangeStream() {
    this.changeStream = this.userModel.watch([], {
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

  private handleInsert(document: any) {
    // Handle insert event
    console.log('New document inserted:', document);
  }

  private handleUpdate(document: any) {
    // Handle update event
    console.log('Document updated:', document);
  }

  private handleDelete(documentId: string) {
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

### Caching Layer
```typescript
// services/cache.service.ts
import { createClient } from 'redis';

export class CacheService {
  private client;
  private readonly ttl = 3600; // 1 hour

  constructor() {
    this.client = createClient({
      url: process.env.REDIS_URL
    });
    this.client.connect();
  }

  private getCacheKey(key: string): string {
    return `cache:${key}`;
  }

  async get<T>(key: string): Promise<T | null> {
    const data = await this.client.get(this.getCacheKey(key));
    return data ? JSON.parse(data) : null;
  }

  async set(key: string, value: any): Promise<void> {
    await this.client.set(
      this.getCacheKey(key),
      JSON.stringify(value),
      { EX: this.ttl }
    );
  }

  async delete(key: string): Promise<void> {
    await this.client.del(this.getCacheKey(key));
  }
}

// repositories/cached-user.repository.ts
export class CachedUserRepository extends UserRepository {
  constructor(
    private cacheService: CacheService
  ) {
    super();
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

## Best Practices

### 1. Schema Design
```typescript
// Best practices for schema design
const bestPracticesSchema = new Schema({
  // Use appropriate types
  stringField: {
    type: String,
    trim: true,
    maxlength: [100, 'Too long']
  },

  // Use enums for fixed values
  status: {
    type: String,
    enum: {
      values: ['active', 'inactive'],
      message: '{VALUE} is not supported'
    }
  },

  // Use nested objects for related data
  address: {
    street: String,
    city: String,
    country: String
  },

  // Use arrays with limitations
  tags: {
    type: [String],
    validate: [
      array => array.length <= 10,
      'Tags exceeds maximum of 10'
    ]
  }
}, {
  // Use timestamps
  timestamps: true,
  
  // Define index options
  autoIndex: process.env.NODE_ENV !== 'production',
  
  // Optimize for JSON transformation
  toJSON: {
    transform: (doc, ret) => {
      delete ret.__v;
      return ret;
    }
  }
});
```

### 2. Performance Optimization
```typescript
// Tips for optimizing performance
// 1. Use lean queries when possible
const users = await User
  .find()
  .lean()
  .exec();

// 2. Select only needed fields
const user = await User
  .findById(id)
  .select('name email')
  .exec();

// 3. Use compound indexes for common queries
userSchema.index({ email: 1, createdAt: -1 });

// 4. Limit results and use pagination
const results = await User
  .find()
  .limit(10)
  .skip(page * 10)
  .exec();

// 5. Use projection in population
await Post
  .findById(id)
  .populate('author', 'name email')
  .exec();
```

### 3. Error Handling
```typescript
// utils/mongoose-error-handler.ts
export class MongooseErrorHandler {
  static handle(error: any) {
    if (error.name === 'ValidationError') {
      const errors = Object.values(error.errors).map(
        (err: any) => err.message
      );
      return {
        status: 400,
        message: 'Validation Error',
        errors
      };
    }

    if (error.code === 11000) {
      return {
        status: 409,
        message: 'Duplicate key error',
        field: Object.keys(error.keyPattern)[0]
      };
    }

    if (error.name === 'CastError') {
      return {
        status: 400,
        message: 'Invalid ID format'
      };
    }

    return {
      status: 500,
      message: 'Internal server error'
    };
  }
}
```

Remember to:
- Use appropriate indexes
- Implement caching for frequently accessed data
- Use transactions for data consistency
- Implement proper error handling
- Monitor database performance
- Use appropriate validation
- Implement proper security measures
- Use connection pooling
- Implement proper logging
- Maintain good documentation

Would you like me to elaborate on any particular aspect or provide additional examples?