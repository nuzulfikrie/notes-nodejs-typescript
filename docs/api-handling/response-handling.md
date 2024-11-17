# API Response Handling Guide

A comprehensive guide for handling API responses across **Express.js**, **Next.js**, and **Nest.js** frameworks. This guide includes best practices, code examples, and strategies to ensure consistent and efficient response handling.

## Table of Contents
- [Introduction](#introduction)
- [Standard Response Format](#standard-response-format)
  - [Success Response Structure](#success-response-structure)
  - [Error Response Structure](#error-response-structure)
- [HTTP Status Codes](#http-status-codes)
  - [Status Code Enums](#status-code-enums)
  - [Status Code Usage Guide](#status-code-usage-guide)
- [Response Headers](#response-headers)
  - [Common Response Headers](#common-response-headers)
  - [Cache Control Headers](#cache-control-headers)
- [Error Responses](#error-responses)
  - [Error Response Builder](#error-response-builder)
- [Response Transformations](#response-transformations)
  - [Response Transformer](#response-transformer)
- [Framework-Specific Implementations](#framework-specific-implementations)
  - [Express.js Implementation](#expressjs-implementation)
  - [Next.js Implementation](#nextjs-implementation)
  - [Nest.js Implementation](#nestjs-implementation)
- [Best Practices](#best-practices)
  - [1. Consistent Response Format](#1-consistent-response-format)
  - [2. Error Handling](#2-error-handling)
  - [3. Response Compression](#3-response-compression)
  - [4. Response Time Tracking](#4-response-time-tracking)
  - [5. Response Sanitization](#5-response-sanitization)
  - [6. Large Response Handling](#6-large-response-handling)
- [Conclusion](#conclusion)

## Introduction

Handling API responses effectively is crucial for providing a seamless user experience and ensuring that clients receive the necessary information in a structured and predictable manner. This guide explores various aspects of API response handling, including standard formats, status codes, headers, and best practices.

---

## Standard Response Format

### Success Response Structure

A consistent success response format helps clients easily parse and understand the data returned by the API.

```typescript
interface SuccessResponse<T> {
  success: true;
  data: T;
  metadata?: {
    page?: number;
    limit?: number;
    total?: number;
    timestamp?: string;
  };
}

interface PaginatedResponse<T> extends SuccessResponse<T[]> {
  metadata: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
    hasNext: boolean;
    hasPrev: boolean;
  };
}
```

**Explanation:**
- **SuccessResponse**: Represents a standard response structure for successful operations, including optional metadata.
- **PaginatedResponse**: Extends `SuccessResponse` to include pagination details, useful for endpoints that return lists of items.

### Error Response Structure

A standardized error response format ensures that clients can handle errors consistently.

```typescript
interface ErrorResponse {
  success: false;
  error: {
    message: string;
    code?: string;
    details?: any;
  };
  timestamp: string;
}
```

**Explanation:**
- **ErrorResponse**: Represents a standard structure for error responses, including an error message, optional code, and additional details.

**Best Practices:**
- **Consistent Structure**: Use a consistent response format across all endpoints to simplify client-side parsing.
- **Include Metadata**: Provide additional metadata (e.g., pagination, timestamps) to enhance the response's usefulness.
- **Clear Error Messages**: Ensure error messages are clear and informative to aid in debugging.

---

## HTTP Status Codes

### Status Code Enums

Using enums for HTTP status codes improves code readability and reduces the likelihood of errors.

```typescript
enum HttpStatus {
  // Success Responses
  OK = 200,
  CREATED = 201,
  ACCEPTED = 202,
  NO_CONTENT = 204,

  // Client Error Responses
  BAD_REQUEST = 400,
  UNAUTHORIZED = 401,
  FORBIDDEN = 403,
  NOT_FOUND = 404,
  CONFLICT = 409,
  UNPROCESSABLE_ENTITY = 422,
  TOO_MANY_REQUESTS = 429,

  // Server Error Responses
  INTERNAL_SERVER_ERROR = 500,
  NOT_IMPLEMENTED = 501,
  SERVICE_UNAVAILABLE = 503
}
```

### Status Code Usage Guide

Mapping status codes to specific request types helps maintain consistency across the API.

```typescript
const StatusCodeMap = {
  // GET requests
  GET: {
    success: HttpStatus.OK,
    notFound: HttpStatus.NOT_FOUND,
  },
  // POST requests
  POST: {
    success: HttpStatus.CREATED,
    invalid: HttpStatus.BAD_REQUEST,
  },
  // PUT/PATCH requests
  PUT: {
    success: HttpStatus.OK,
    invalid: HttpStatus.BAD_REQUEST,
    notFound: HttpStatus.NOT_FOUND,
  },
  // DELETE requests
  DELETE: {
    success: HttpStatus.NO_CONTENT,
    notFound: HttpStatus.NOT_FOUND,
  }
};
```

**Best Practices:**
- **Appropriate Status Codes**: Use the correct status codes to reflect the outcome of the request accurately.
- **Consistency**: Ensure that similar endpoints use the same status codes for similar outcomes.
- **Documentation**: Document the status codes used by each endpoint to aid client developers.

---

## Response Headers

### Common Response Headers

Setting standard response headers ensures that clients receive necessary metadata and control information.

```typescript
interface CommonResponseHeaders {
  'Content-Type': string;
  'Cache-Control': string;
  'ETag': string;
  'Access-Control-Allow-Origin': string;
  'X-Request-ID': string;
  'X-Response-Time': string;
}

const setStandardHeaders = (res: Response) => {
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('X-Response-Time', process.hrtime.bigint().toString());
};
```

### Cache Control Headers

Cache control headers help manage how responses are cached by clients and intermediaries.

```typescript
enum CacheControl {
  NONE = 'no-store, no-cache, must-revalidate',
  SHORT = 'public, max-age=300',  // 5 minutes
  MEDIUM = 'public, max-age=3600', // 1 hour
  LONG = 'public, max-age=86400'   // 1 day
}

const setCacheHeaders = (res: Response, type: keyof typeof CacheControl) => {
  res.setHeader('Cache-Control', CacheControl[type]);
};
```

**Best Practices:**
- **Security Headers**: Include security-related headers (e.g., `Content-Security-Policy`) to protect against common vulnerabilities.
- **CORS Headers**: Set `Access-Control-Allow-Origin` to control which domains can access the API.
- **ETag Headers**: Use ETags to enable efficient caching and reduce bandwidth usage.

---

## Error Responses

### Error Response Builder

Creating a reusable error response builder simplifies error handling and ensures consistency.

```typescript
class APIError extends Error {
  constructor(
    public statusCode: number,
    message: string,
    public code?: string,
    public details?: any
  ) {
    super(message);
    this.name = 'APIError';
  }

  toResponse(): ErrorResponse {
    return {
      success: false,
      error: {
        message: this.message,
        code: this.code,
        details: this.details
      },
      timestamp: new Date().toISOString()
    };
  }
}

// Usage examples
const notFoundError = new APIError(
  HttpStatus.NOT_FOUND,
  'Resource not found',
  'RESOURCE_NOT_FOUND'
);

const validationError = new APIError(
  HttpStatus.BAD_REQUEST,
  'Validation failed',
  'VALIDATION_ERROR',
  { field: 'email', message: 'Invalid email format' }
);
```

**Best Practices:**
- **Detailed Errors**: Provide detailed error information, including codes and additional context, to aid in debugging.
- **Consistent Format**: Ensure all error responses follow a consistent structure to simplify client-side handling.
- **Avoid Sensitive Information**: Do not expose sensitive information in error messages.

---

## Response Transformations

### Response Transformer

A response transformer can be used to modify and format responses before sending them to the client.

```typescript
class ResponseTransformer<T> {
  constructor(private data: T) {}

  paginate(page: number, limit: number, total: number): PaginatedResponse<T> {
    return {
      success: true,
      data: this.data as T[],
      metadata: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit),
        hasNext: page * limit < total,
        hasPrev: page > 1
      }
    };
  }

  serialize(transform?: (data: T) => any): SuccessResponse<T> {
    return {
      success: true,
      data: transform ? transform(this.data) : this.data,
      metadata: {
        timestamp: new Date().toISOString()
      }
    };
  }
}
```

**Best Practices:**
- **Reusability**: Create reusable transformers to handle common response transformations.
- **Customization**: Allow for custom transformations to meet specific client needs.
- **Efficiency**: Ensure transformations are efficient to minimize response time.

---

## Framework-Specific Implementations

### Express.js Implementation

Express.js provides a flexible and minimalistic framework for handling HTTP responses.

```typescript:examples/express/response-handler.ts
// Response helper
class ResponseHandler {
  constructor(private res: Response) {}

  success<T>(data: T, status: number = HttpStatus.OK): void {
    this.res.status(status).json({
      success: true,
      data,
      metadata: {
        timestamp: new Date().toISOString()
      }
    });
  }

  error(error: APIError): void {
    this.res.status(error.statusCode).json(error.toResponse());
  }

  paginated<T>(
    data: T[],
    page: number,
    limit: number,
    total: number
  ): void {
    const response = new ResponseTransformer(data)
      .paginate(page, limit, total);
    this.res.status(HttpStatus.OK).json(response);
  }
}

// Usage in Express
app.get('/api/items', async (req, res) => {
  const handler = new ResponseHandler(res);
  try {
    const { page = 1, limit = 10 } = req.query;
    const [items, total] = await ItemService.findAll(page, limit);
    handler.paginated(items, page, limit, total);
  } catch (error) {
    handler.error(error);
  }
});
```

**Best Practices:**
- **Helper Classes**: Use helper classes to encapsulate response logic and reduce duplication.
- **Error Handling**: Ensure all errors are caught and handled gracefully.
- **Pagination**: Provide paginated responses for endpoints that return lists of items.

### Next.js Implementation

Next.js offers a powerful API routing system with built-in support for serverless functions.

```typescript:examples/nextjs/app/api/items/route.ts
// app/api/items/route.ts
import { NextResponse } from 'next/server';

class NextResponseHandler {
  static success<T>(data: T, status: number = HttpStatus.OK) {
    return NextResponse.json({
      success: true,
      data,
      metadata: {
        timestamp: new Date().toISOString()
      }
    }, { status });
  }

  static error(error: APIError) {
    return NextResponse.json(
      error.toResponse(),
      { status: error.statusCode }
    );
  }

  static paginated<T>(
    data: T[],
    page: number,
    limit: number,
    total: number
  ) {
    const response = new ResponseTransformer(data)
      .paginate(page, limit, total);
    return NextResponse.json(response);
  }
}

// Usage in Next.js
export async function GET(request: Request) {
  try {
    const { searchParams } = new URL(request.url);
    const page = parseInt(searchParams.get('page') ?? '1');
    const limit = parseInt(searchParams.get('limit') ?? '10');
    
    const [items, total] = await ItemService.findAll(page, limit);
    return NextResponseHandler.paginated(items, page, limit, total);
  } catch (error) {
    return NextResponseHandler.error(error);
  }
}
```

**Best Practices:**
- **Serverless Optimization**: Keep response handlers lightweight to optimize for serverless environments.
- **Consistent Error Handling**: Use a consistent error handling strategy across all API routes.
- **Efficient Parsing**: Parse and validate query parameters efficiently to minimize response time.

### Nest.js Implementation

Nest.js is a progressive Node.js framework that provides a robust set of features for building scalable server-side applications.

```typescript:nestjs/src/interceptors/response.interceptor.ts
// response.interceptor.ts
import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';

@Injectable()
export class ResponseInterceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    return next.handle().pipe(
      map(data => ({
        success: true,
        data,
        metadata: {
          timestamp: new Date().toISOString()
        }
      }))
    );
  }
}

// Usage in Nest.js controller
@Controller('items')
@UseInterceptors(ResponseInterceptor)
export class ItemsController {
  @Get()
  async findAll(
    @Query('page') page: number = 1,
    @Query('limit') limit: number = 10
  ) {
    const [items, total] = await this.itemsService.findAll(page, limit);
    return new ResponseTransformer(items)
      .paginate(page, limit, total);
  }
}
```

**Best Practices:**
- **Interceptors**: Use interceptors to apply common response transformations across multiple endpoints.
- **DTOs**: Use Data Transfer Objects (DTOs) to define the structure of response data.
- **Modular Design**: Organize code into modules to promote reusability and maintainability.

---

## Best Practices

### 1. Consistent Response Format

- **Maintain Consistency**: Ensure all responses follow a consistent format to simplify client-side parsing.
- **Include Metadata**: Provide additional metadata (e.g., timestamps, pagination) to enhance the response's usefulness.
- **Use Proper Status Codes**: Reflect the outcome of the request accurately with appropriate HTTP status codes.

### 2. Error Handling

```typescript
const handleErrorResponse = (error: unknown) => {
  if (error instanceof APIError) {
    return error.toResponse();
  }

  // Handle unexpected errors
  const unexpectedError = new APIError(
    HttpStatus.INTERNAL_SERVER_ERROR,
    'An unexpected error occurred',
    'INTERNAL_ERROR'
  );
  return unexpectedError.toResponse();
};
```

**Best Practices:**
- **Consistent Error Format**: Ensure all error responses follow a consistent structure.
- **Meaningful Messages**: Provide clear and actionable error messages.
- **Avoid Exposing Sensitive Information**: Do not expose stack traces or internal error details to clients.

### 3. Response Compression

```typescript
import compression from 'compression';

app.use(compression({
  filter: (req, res) => {
    if (req.headers['x-no-compression']) {
      return false;
    }
    return compression.filter(req, res);
  },
  level: 6 // Compression level (0-9)
}));
```

**Best Practices:**
- **Enable Compression**: Compress responses to reduce bandwidth usage and improve load times.
- **Custom Filters**: Use custom filters to control which responses are compressed.
- **Monitor Performance**: Monitor the impact of compression on server performance and adjust settings as needed.

### 4. Response Time Tracking

```typescript
const trackResponseTime = (req: Request, res: Response, next: NextFunction) => {
  const start = process.hrtime();
  
  res.on('finish', () => {
    const [seconds, nanoseconds] = process.hrtime(start);
    const duration = seconds * 1000 + nanoseconds / 1e6;
    console.log(`${req.method} ${req.url} - ${duration.toFixed(2)}ms`);
  });
  
  next();
};
```

**Best Practices:**
- **Track Response Times**: Log response times to identify performance bottlenecks.
- **Analyze Trends**: Use response time data to analyze trends and optimize performance.
- **Set Alerts**: Set alerts for unusually long response times to proactively address issues.

### 5. Response Sanitization

```typescript
const sanitizeResponse = <T>(data: T): T => {
  if (Array.isArray(data)) {
    return data.map(item => sanitizeResponse(item)) as any;
  }
  
  if (data && typeof data === 'object') {
    const sanitized = { ...data };
    delete sanitized.password;
    delete sanitized.secretKey;
    delete sanitized.__v;
    return sanitized;
  }
  
  return data;
};
```

**Best Practices:**
- **Remove Sensitive Data**: Ensure sensitive information (e.g., passwords, secret keys) is not included in responses.
- **Automate Sanitization**: Use automated sanitization functions to consistently clean response data.
- **Review Regularly**: Regularly review sanitization logic to ensure it covers all sensitive fields.

### 6. Large Response Handling

```typescript
const streamLargeResponse = async (
  req: Request,
  res: Response,
  data: any[]
) => {
  res.setHeader('Content-Type', 'application/json');
  res.write('{"success":true,"data":[');
  
  for (let i = 0; i < data.length; i++) {
    const chunk = JSON.stringify(data[i]);
    res.write(i === 0 ? chunk : `,${chunk}`);
    
    // Allow other events to process
    await new Promise(resolve => setImmediate(resolve));
  }
  
  res.write(']}');
  res.end();
};
```

**Best Practices:**
- **Stream Large Responses**: Stream large responses to avoid blocking the event loop and improve performance.
- **Chunk Data**: Send data in manageable chunks to reduce memory usage.
- **Monitor Impact**: Monitor the impact of large responses on server performance and adjust strategies as needed.

---

## Conclusion

Handling API responses effectively involves a combination of consistent formatting, efficient transformations, and robust error handling. By following the patterns and best practices outlined in this guide, you can build APIs that provide clear, reliable, and efficient responses using **Express.js**, **Next.js**, and **Nest.js** frameworks.

---

## Additional Resources

- [Express.js Documentation](https://expressjs.com/)
- [Next.js Documentation](https://nextjs.org/docs)
- [Nest.js Documentation](https://docs.nestjs.com/)
- [Compression Middleware](https://github.com/expressjs/compression)
- [HTTP Status Codes](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status)

Feel free to reach out if you need further assistance or have questions regarding API response handling!