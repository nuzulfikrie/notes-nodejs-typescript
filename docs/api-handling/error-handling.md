## docs/api-handling/error-handling.md
# API Error Handling Guide

A comprehensive guide for handling errors in APIs across **Express.js**, **Next.js**, and **Nest.js** frameworks. This guide includes best practices, code examples, and strategies to ensure robust and consistent error handling.

## Table of Contents
- [Introduction](#introduction)
- [Custom Error Classes](#custom-error-classes)
  - [Base API Error](#base-api-error)
  - [Specific Error Types](#specific-error-types)
- [Error Middleware](#error-middleware)
  - [Global Error Handler](#global-error-handler)
- [Error Response Format](#error-response-format)
  - [Standard Error Response Structure](#standard-error-response-structure)
- [Framework-Specific Implementations](#framework-specific-implementations)
  - [Express.js Implementation](#expressjs-implementation)
  - [Next.js Implementation](#nextjs-implementation)
  - [Nest.js Implementation](#nestjs-implementation)
- [Best Practices](#best-practices)
  - [1. Error Logging](#1-error-logging)
  - [2. Database Error Handling](#2-database-error-handling)
  - [3. Validation Error Handling](#3-validation-error-handling)
  - [4. Rate Limiting Error Handler](#4-rate-limiting-error-handler)
  - [5. Authentication Error Handler](#5-authentication-error-handler)
  - [6. Async Error Handler Wrapper](#6-async-error-handler-wrapper)
  - [7. Business Logic Error Handling](#7-business-logic-error-handling)
- [Conclusion](#conclusion)

## Introduction

Effective error handling is crucial for building robust APIs that provide clear and actionable feedback to clients. This guide explores various aspects of error handling, including custom error classes, middleware, and best practices, using three popular TypeScript frameworks: **Express.js**, **Next.js**, and **Nest.js**.

---

## Custom Error Classes

Custom error classes allow you to define specific error types and encapsulate error-related information.

### Base API Error

The base API error class serves as a foundation for all custom error types.

```typescript
export class APIError extends Error {
  constructor(
    public statusCode: number,
    public message: string,
    public code: string,
    public details?: any
  ) {
    super(message);
    this.name = this.constructor.name;
    Error.captureStackTrace(this, this.constructor);
  }

  toJSON() {
    return {
      error: {
        code: this.code,
        message: this.message,
        details: this.details,
        ...(process.env.NODE_ENV === 'development' && { stack: this.stack })
      }
    };
  }
}
```

**Explanation:**
- **APIError Class**: Extends the native `Error` class to include additional properties like `statusCode`, `code`, and `details`.
- **toJSON Method**: Converts the error object to a JSON representation, including the stack trace in development mode.

### Specific Error Types

Define specific error types for common error scenarios.

```typescript
export class ValidationError extends APIError {
  constructor(details: any) {
    super(400, 'Validation failed', 'VALIDATION_ERROR', details);
  }
}

export class NotFoundError extends APIError {
  constructor(resource: string) {
    super(404, `${resource} not found`, 'NOT_FOUND');
  }
}

export class UnauthorizedError extends APIError {
  constructor(message: string = 'Unauthorized') {
    super(401, message, 'UNAUTHORIZED');
  }
}

export class ForbiddenError extends APIError {
  constructor(message: string = 'Forbidden') {
    super(403, message, 'FORBIDDEN');
  }
}

export class ConflictError extends APIError {
  constructor(message: string) {
    super(409, message, 'CONFLICT');
  }
}

export class DatabaseError extends APIError {
  constructor(message: string) {
    super(500, message, 'DATABASE_ERROR');
  }
}
```

**Explanation:**
- **Specific Error Classes**: Extend `APIError` to represent specific error scenarios, each with a unique status code and message.

**Best Practices:**
- **Use Specific Error Types**: Define specific error types for common scenarios to provide clear and consistent error handling.
- **Include Error Codes**: Use error codes to categorize errors and simplify client-side handling.
- **Avoid Exposing Sensitive Information**: Ensure that error messages do not expose sensitive information.

---

## Error Middleware

Middleware provides a centralized way to handle errors and ensure consistent error responses.

### Global Error Handler

A global error handler catches and processes all errors that occur during request processing.

```typescript
interface ErrorResponse {
  success: false;
  error: {
    code: string;
    message: string;
    details?: any;
    stack?: string;
  };
  timestamp: string;
}

const globalErrorHandler = (
  error: Error,
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  console.error('Error:', error);

  const response: ErrorResponse = {
    success: false,
    error: {
      code: 'INTERNAL_ERROR',
      message: 'Internal server error'
    },
    timestamp: new Date().toISOString()
  };

  if (error instanceof APIError) {
    response.error = {
      code: error.code,
      message: error.message,
      details: error.details
    };
    res.status(error.statusCode).json(response);
    return;
  }

  if (process.env.NODE_ENV === 'development') {
    response.error.stack = error.stack;
  }

  res.status(500).json(response);
};
```

**Explanation:**
- **ErrorResponse Interface**: Defines the structure of error responses.
- **globalErrorHandler Function**: Catches all errors, logs them, and sends a standardized error response.

**Best Practices:**
- **Centralized Error Handling**: Use a global error handler to ensure consistent error responses across the application.
- **Detailed Logging**: Log error details to aid in debugging and monitoring.
- **Environment-Specific Behavior**: Include stack traces in error responses only in development mode.

---

## Error Response Format

A standardized error response format ensures that clients can handle errors consistently.

### Standard Error Response Structure

Define a consistent structure for error responses.

```typescript
interface StandardErrorResponse {
  success: false;
  error: {
    code: string;
    message: string;
    details?: any;
    stack?: string;
  };
  timestamp: string;
  path?: string;
  method?: string;
}

const createErrorResponse = (
  error: APIError,
  req?: Request
): StandardErrorResponse => {
  return {
    success: false,
    error: {
      code: error.code,
      message: error.message,
      details: error.details,
      ...(process.env.NODE_ENV === 'development' && { stack: error.stack })
    },
    timestamp: new Date().toISOString(),
    ...(req && {
      path: req.path,
      method: req.method
    })
  };
};
```

**Explanation:**
- **StandardErrorResponse Interface**: Represents the structure of error responses, including optional request details.
- **createErrorResponse Function**: Generates a standardized error response based on the provided error and request.

**Best Practices:**
- **Consistent Format**: Ensure all error responses follow a consistent structure to simplify client-side handling.
- **Include Request Details**: Optionally include request details (e.g., path, method) to aid in debugging.
- **Avoid Exposing Sensitive Information**: Do not expose sensitive information in error messages or details.

---

## Framework-Specific Implementations

Each framework has its own conventions and best practices for handling errors. Below are detailed implementations for **Express.js**, **Next.js**, and **Nest.js**.

### Express.js Implementation

Express.js provides a flexible and minimalistic framework for handling errors.

```typescript:examples/express/middleware/error.middleware.ts
import { Request, Response, NextFunction } from 'express';
import { APIError } from '../errors';

export const errorHandler = (
  err: Error,
  req: Request,
  res: Response,
  next: NextFunction
) => {
  // Log error
  console.error('Error:', {
    name: err.name,
    message: err.message,
    stack: err.stack,
    path: req.path,
    method: req.method
  });

  if (err instanceof APIError) {
    return res.status(err.statusCode).json(createErrorResponse(err, req));
  }

  // Handle Prisma errors
  if (err.name === 'PrismaClientKnownRequestError') {
    return res.status(400).json(createErrorResponse(
      new APIError(400, 'Database operation failed', 'DATABASE_ERROR'),
      req
    ));
  }

  // Handle validation errors
  if (err.name === 'ValidationError') {
    return res.status(400).json(createErrorResponse(
      new ValidationError(err.message),
      req
    ));
  }

  // Handle unknown errors
  return res.status(500).json(createErrorResponse(
    new APIError(500, 'Internal server error', 'INTERNAL_ERROR'),
    req
  ));
};
```

**Best Practices:**
- **Middleware Usage**: Use middleware to centralize error handling and ensure consistent responses.
- **Specific Error Handling**: Handle specific error types (e.g., Prisma, validation) separately for more precise responses.
- **Logging**: Log error details to aid in debugging and monitoring.

### Next.js Implementation

Next.js offers a powerful API routing system with built-in support for serverless functions.

```typescript:examples/nextjs/app/api/error.ts
import { NextResponse } from 'next/server';
import { APIError } from '@/lib/errors';

export function handleError(error: unknown, req: Request) {
  // Log error
  console.error('Error:', error);

  if (error instanceof APIError) {
    return NextResponse.json(
      createErrorResponse(error),
      { status: error.statusCode }
    );
  }

  // Handle unknown errors
  const internalError = new APIError(
    500,
    'Internal server error',
    'INTERNAL_ERROR'
  );

  return NextResponse.json(
    createErrorResponse(internalError),
    { status: 500 }
  );
}

// Usage in route handlers
export async function GET(request: Request) {
  try {
    // ... handler logic
  } catch (error) {
    return handleError(error, request);
  }
}
```

**Best Practices:**
- **Serverless Optimization**: Keep error handlers lightweight to optimize for serverless environments.
- **Consistent Error Handling**: Use a consistent error handling strategy across all API routes.
- **Efficient Parsing**: Parse and validate query parameters efficiently to minimize response time.

### Nest.js Implementation

Nest.js is a progressive Node.js framework that provides a robust set of features for building scalable server-side applications.

```typescript:nestjs/src/filters/http-exception.filter.ts
import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
} from '@nestjs/common';
import { Response } from 'express';

@Catch(HttpException)
export class HttpExceptionFilter implements ExceptionFilter {
  catch(exception: HttpException, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();
    const status = exception.getStatus();

    const errorResponse = createErrorResponse(
      new APIError(
        status,
        exception.message,
        'HTTP_ERROR',
        exception.getResponse()
      ),
      request
    );

    response.status(status).json(errorResponse);
  }
}

// Custom exception
export class CustomException extends HttpException {
  constructor(message: string, status: number) {
    super(
      {
        success: false,
        error: {
          message,
          code: 'CUSTOM_ERROR',
        },
      },
      status
    );
  }
}
```

**Best Practices:**
- **Interceptors and Filters**: Use interceptors and filters to apply common error handling logic across multiple endpoints.
- **DTOs**: Use Data Transfer Objects (DTOs) to define the structure of response data.
- **Modular Design**: Organize code into modules to promote reusability and maintainability.

---

## Best Practices

### 1. Error Logging

Logging errors is vital for monitoring, debugging, and auditing purposes.

```typescript
const logError = (error: Error, req: Request) => {
  const errorLog = {
    timestamp: new Date().toISOString(),
    name: error.name,
    message: error.message,
    stack: error.stack,
    path: req.path,
    method: req.method,
    query: req.query,
    body: req.body,
    headers: req.headers,
    ip: req.ip
  };

  // Log to your preferred logging service
  console.error('Error:', errorLog);
};
```

**Best Practices:**
- **Avoid Sensitive Data**: Ensure that sensitive information (e.g., passwords) is not logged.
- **Log Levels**: Implement different log levels (info, warning, error) to categorize logs appropriately.
- **Persistent Storage**: Store logs in a persistent and searchable storage solution (e.g., ELK stack, Loggly).

### 2. Database Error Handling

Handle database errors gracefully to provide clear feedback to clients.

```typescript
const handleDatabaseError = (error: any) => {
  if (error.code === 'P2002') {
    throw new ConflictError('Unique constraint violation');
  }
  if (error.code === 'P2025') {
    throw new NotFoundError('Record not found');
  }
  throw new DatabaseError('Database operation failed');
};
```

**Best Practices:**
- **Specific Error Handling**: Handle specific database error codes separately for more precise responses.
- **Clear Messages**: Provide clear and actionable error messages to aid in debugging.
- **Avoid Exposing Internal Details**: Do not expose internal database error details to clients.

### 3. Validation Error Handling

Handle validation errors to ensure that clients receive clear feedback on invalid inputs.

```typescript
const handleValidationError = (errors: any[]) => {
  const details = errors.map(error => ({
    field: error.field,
    message: error.message,
    value: error.value
  }));

  throw new ValidationError(details);
};
```

**Best Practices:**
- **Detailed Feedback**: Provide detailed feedback on validation errors, including field names and error messages.
- **Consistent Format**: Ensure all validation errors follow a consistent format to simplify client-side handling.
- **Avoid Exposing Sensitive Information**: Do not expose sensitive information in validation error messages.

### 4. Rate Limiting Error Handler

Handle rate limiting errors to prevent abuse and ensure fair usage.

```typescript
const handleRateLimitError = (req: Request) => {
  throw new APIError(
    429,
    'Too many requests',
    'RATE_LIMIT_EXCEEDED',
    {
      retryAfter: 60,
      ip: req.ip
    }
  );
};
```

**Best Practices:**
- **Clear Messages**: Provide clear and actionable error messages for rate limiting errors.
- **Include Retry Information**: Include information on when the client can retry the request.
- **Monitor Usage**: Monitor rate limiting errors to identify potential abuse and adjust limits as needed.

### 5. Authentication Error Handler

Handle authentication errors to ensure that clients receive clear feedback on authentication failures.

```typescript
const handleAuthError = (error: Error) => {
  if (error.message === 'jwt expired') {
    throw new UnauthorizedError('Token expired');
  }
  if (error.message === 'invalid signature') {
    throw new UnauthorizedError('Invalid token');
  }
  throw new UnauthorizedError('Authentication failed');
};
```

**Best Practices:**
- **Specific Error Handling**: Handle specific authentication error messages separately for more precise responses.
- **Clear Messages**: Provide clear and actionable error messages for authentication errors.
- **Avoid Exposing Sensitive Information**: Do not expose sensitive information in authentication error messages.

### 6. Async Error Handler Wrapper

Use an async error handler wrapper to simplify error handling in asynchronous route handlers.

```typescript
const asyncHandler = (fn: Function) => {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      await fn(req, res, next);
    } catch (error) {
      next(error);
    }
  };
};

// Usage
app.get('/api/items', asyncHandler(async (req, res) => {
  const items = await ItemService.findAll();
  res.json({ success: true, data: items });
}));
```

**Best Practices:**
- **Simplify Error Handling**: Use an async error handler wrapper to simplify error handling in asynchronous route handlers.
- **Consistent Error Handling**: Ensure all errors are caught and handled consistently.
- **Avoid Code Duplication**: Use a wrapper to avoid duplicating error handling logic in each route handler.

### 7. Business Logic Error Handling

Handle business logic errors to ensure that clients receive clear feedback on business rule violations.

```typescript
class BusinessError extends APIError {
  constructor(message: string, code: string = 'BUSINESS_ERROR') {
    super(400, message, code);
  }
}

const handleBusinessLogicError = (condition: boolean, message: string) => {
  if (!condition) {
    throw new BusinessError(message);
  }
};

// Usage
const transferMoney = (amount: number, balance: number) => {
  handleBusinessLogicError(
    amount <= balance,
    'Insufficient funds'
  );
  // Process transfer...
};
```

**Best Practices:**
- **Specific Error Handling**: Handle specific business logic errors separately for more precise responses.
- **Clear Messages**: Provide clear and actionable error messages for business logic errors.
- **Avoid Exposing Sensitive Information**: Do not expose sensitive information in business logic error messages.

---

## Conclusion

Effective error handling involves a combination of custom error classes, middleware, and best practices. By following the patterns and best practices outlined in this guide, you can build robust APIs that provide clear and consistent error feedback using **Express.js**, **Next.js**, and **Nest.js** frameworks.

---

## Additional Resources

- [Express.js Documentation](https://expressjs.com/)
- [Next.js Documentation](https://nextjs.org/docs)
- [Nest.js Documentation](https://docs.nestjs.com/)
- [Node.js Error Handling](https://nodejs.org/api/errors.html)
- [Logging Best Practices](https://12factor.net/logs)

Feel free to reach out if you need further assistance or have questions regarding API error handling!