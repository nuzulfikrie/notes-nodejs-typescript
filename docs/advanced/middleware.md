# Middleware Guidelines

This document outlines middleware patterns and implementations across Next.js, NestJS, and Express.js frameworks.

## Table of Contents
- [Next.js Middleware](#nextjs-middleware)
- [NestJS Middleware](#nestjs-middleware)
- [Express.js Middleware](#expressjs-middleware)
- [Common Patterns](#common-patterns)

## Next.js Middleware

### Route Middleware
```typescript
// middleware.ts
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

export function middleware(request: NextRequest) {
  // Authentication check
  const token = request.cookies.get('token');
  if (!token && request.nextUrl.pathname.startsWith('/dashboard')) {
    return NextResponse.redirect(new URL('/login', request.url));
  }

  // Add custom headers
  const response = NextResponse.next();
  response.headers.set('x-custom-header', 'custom-value');
  
  return response;
}

export const config = {
  matcher: [
    '/dashboard/:path*',
    '/api/:path*',
  ]
};
```

### API Route Middleware
```typescript
// lib/middleware/withAuth.ts
import { NextApiHandler, NextApiRequest, NextApiResponse } from 'next';

export function withAuth(handler: NextApiHandler) {
  return async (req: NextApiRequest, res: NextApiResponse) => {
    try {
      const token = req.headers.authorization?.split(' ')[1];
      if (!token) {
        return res.status(401).json({ message: 'Unauthorized' });
      }

      // Verify token and attach user to request
      const user = await verifyToken(token);
      (req as any).user = user;

      return handler(req, res);
    } catch (error) {
      return res.status(401).json({ message: 'Invalid token' });
    }
  };
}

// Usage in API route
export default withAuth(async function handler(req, res) {
  const user = (req as any).user;
  res.json({ message: `Hello ${user.name}` });
});
```

## NestJS Middleware

### Global Middleware
```typescript
// middleware/logger.middleware.ts
import { Injectable, NestMiddleware } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';

@Injectable()
export class LoggerMiddleware implements NestMiddleware {
  use(req: Request, res: Response, next: NextFunction) {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
    
    const start = Date.now();
    res.on('finish', () => {
      const duration = Date.now() - start;
      console.log(`[${res.statusCode}] Duration: ${duration}ms`);
    });
    
    next();
  }
}

// app.module.ts
import { Module, NestModule, MiddlewareConsumer } from '@nestjs/common';

@Module({})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer
      .apply(LoggerMiddleware)
      .forRoutes('*');
  }
}
```

### Route-Specific Middleware
```typescript
// middleware/auth.middleware.ts
import { Injectable, NestMiddleware, UnauthorizedException } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthMiddleware implements NestMiddleware {
  constructor(private jwtService: JwtService) {}

  async use(req: Request, res: Response, next: NextFunction) {
    try {
      const token = req.headers.authorization?.split(' ')[1];
      if (!token) {
        throw new UnauthorizedException();
      }

      const payload = await this.jwtService.verifyAsync(token);
      req['user'] = payload;
      
      next();
    } catch {
      throw new UnauthorizedException();
    }
  }
}

// Usage in module
@Module({})
export class UserModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer
      .apply(AuthMiddleware)
      .forRoutes(
        { path: 'users', method: RequestMethod.ALL },
        { path: 'users/:id', method: RequestMethod.ALL }
      );
  }
}
```

## Express.js Middleware

### Application-Level Middleware
```typescript
// middleware/errorHandler.ts
import { Request, Response, NextFunction } from 'express';

export function errorHandler(
  error: Error,
  req: Request,
  res: Response,
  next: NextFunction
) {
  console.error(error.stack);
  
  res.status(500).json({
    error: {
      message: error.message,
      stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
    }
  });
}

// app.ts
import express from 'express';
import { errorHandler } from './middleware/errorHandler';

const app = express();
app.use(express.json());
app.use(errorHandler);
```

### Route-Level Middleware
```typescript
// middleware/validateRequest.ts
import { Request, Response, NextFunction } from 'express';
import { Schema } from 'joi';

export function validateRequest(schema: Schema) {
  return (req: Request, res: Response, next: NextFunction) => {
    const { error } = schema.validate(req.body);
    if (error) {
      return res.status(400).json({
        error: error.details[0].message
      });
    }
    next();
  };
}

// Usage in routes
import { Router } from 'express';
import { validateRequest } from '../middleware/validateRequest';
import { userSchema } from '../schemas/user.schema';

const router = Router();

router.post(
  '/users',
  validateRequest(userSchema),
  async (req, res) => {
    // Handle request
  }
);
```

## Common Patterns

### Request Timing
```typescript
// middleware/requestTimer.ts
export function requestTimer(req: any, res: any, next: any) {
  const start = Date.now();
  
  res.on('finish', () => {
    const duration = Date.now() - start;
    console.log(`${req.method} ${req.url} - ${duration}ms`);
  });
  
  next();
}
```

### Rate Limiting
```typescript
// middleware/rateLimiter.ts
import rateLimit from 'express-rate-limit';

export const rateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later',
  standardHeaders: true,
  legacyHeaders: false,
});
```

### CORS
```typescript
// middleware/cors.ts
import cors from 'cors';

export const corsMiddleware = cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  maxAge: 86400, // 24 hours
});
```

### Request Validation
```typescript
// middleware/validator.ts
import { validate } from 'class-validator';
import { plainToClass } from 'class-transformer';

export function validateDto(dtoClass: any) {
  return async (req: any, res: any, next: any) => {
    const dtoObject = plainToClass(dtoClass, req.body);
    const errors = await validate(dtoObject);
    
    if (errors.length > 0) {
      return res.status(400).json({
        error: 'Validation failed',
        details: errors.map(error => ({
          property: error.property,
          constraints: error.constraints,
        }))
      });
    }
    
    req.validatedData = dtoObject;
    next();
  };
}
```

### Authentication
```typescript
// middleware/auth.ts
import jwt from 'jsonwebtoken';

export function authenticate(req: any, res: any, next: any) {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET!);
    req.user = decoded;
    
    next();
  } catch (error) {
    return res.status(401).json({ message: 'Invalid token' });
  }
}
```

## Best Practices

### 1. Error Handling
- Implement global error handling
- Use appropriate status codes
- Provide meaningful error messages
- Handle async errors properly

### 2. Security
- Implement rate limiting
- Use CORS appropriately
- Validate input data
- Secure sensitive routes

### 3. Performance
- Keep middleware lightweight
- Use caching when appropriate
- Monitor middleware performance
- Chain middleware efficiently

### 4. Maintenance
- Document middleware purpose
- Use TypeScript for type safety
- Write tests for middleware
- Follow consistent naming conventions
