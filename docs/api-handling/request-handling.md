## docs/api-handling/request-handling.md

# API Request Handling Guide

This guide covers best practices and patterns for handling API requests across **Express.js**, **Next.js**, and **Nest.js** frameworks. It includes detailed explanations, complete code examples, and recommended practices to ensure robust and secure API implementations.

## Table of Contents
- [Introduction](#introduction)
- [Common Request Types](#common-request-types)
  - [Basic Request Structure](#basic-request-structure)
  - [Standard Request Headers](#standard-request-headers)
- [Request Validation](#request-validation)
  - [Using Zod](#using-zod)
  - [Using Class Validator](#using-class-validator)
- [Query Parameters](#query-parameters)
  - [Parsing and Validation](#parsing-and-validation)
- [Route Parameters](#route-parameters)
  - [Parameter Validation](#parameter-validation)
- [File Uploads](#file-uploads)
  - [Multipart Form Data Handling](#multipart-form-data-handling)
- [Request Body Parsing](#request-body-parsing)
  - [JSON Body Parsing](#json-body-parsing)
  - [Form Data Parsing](#form-data-parsing)
- [Framework-Specific Implementations](#framework-specific-implementations)
  - [Express.js Implementation](#expressjs-implementation)
  - [Next.js Implementation (App Router)](#nextjs-implementation-app-router)
  - [Nest.js Implementation](#nestjs-implementation)
- [Best Practices](#best-practices)
  - [1. Request Validation](#1-request-validation)
  - [2. Security Considerations](#2-security-considerations)
  - [3. Request Logging](#3-request-logging)
  - [4. Rate Limiting](#4-rate-limiting)
  - [5. Request Timeout Handling](#5-request-timeout-handling)
- [Error Handling](#error-handling)
  - [Request Error Handler](#request-error-handler)
- [Conclusion](#conclusion)

## Introduction

Handling API requests efficiently and securely is crucial for building scalable and maintainable applications. This guide explores various aspects of API request handling, including validation, parsing, and best practices, using three popular TypeScript frameworks: **Express.js**, **Next.js**, and **Nest.js**.

---

## Common Request Types

### Basic Request Structure

Understanding the structure of a typical HTTP request is essential for effective API handling. Here's a basic TypeScript interface that outlines the common components of a request:

```typescript
interface BaseRequest {
  body: any;
  params: Record<string, string>;
  query: Record<string, string>;
  headers: Record<string, string>;
  cookies?: Record<string, string>;
}
```

- **body**: Contains the payload of the request, often used with POST, PUT, PATCH methods.
- **params**: URL parameters extracted from the route (e.g., `/users/:id`).
- **query**: Query string parameters (e.g., `/users?page=2`).
- **headers**: HTTP headers sent with the request.
- **cookies**: Cookies sent with the request, if any.

### Standard Request Headers

HTTP headers provide essential metadata about the request. Below is an interface representing common headers:

```typescript
interface CommonHeaders {
  'content-type': string;
  'authorization': string;
  'accept': string;
  'user-agent': string;
  'accept-language': string;
  'x-request-id': string;
  'x-correlation-id': string;
}
```

- **Content-Type**: Indicates the media type of the request body.
- **Authorization**: Contains credentials for authenticating the client.
- **Accept**: Specifies the media types the client can process.
- **User-Agent**: Provides information about the client software.
- **Accept-Language**: Indicates the preferred languages for the response.
- **X-Request-ID** & **X-Correlation-ID**: Custom headers for tracking requests across services.

---

## Request Validation

Validating incoming requests ensures that your API handles only well-formed and expected data, enhancing security and reliability.

### Using Zod

[Zod](https://github.com/colinhacks/zod) is a TypeScript-first schema declaration and validation library.

```typescript
import { z } from 'zod';

// Define a schema for creating a user
const CreateUserSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
  name: z.string().min(2),
  age: z.number().min(18).optional(),
});

type CreateUserDto = z.infer<typeof CreateUserSchema>;

// Validation function
const validateRequest = <T>(schema: z.Schema<T>, data: unknown): T => {
  const result = schema.safeParse(data);
  if (!result.success) {
    // Extract detailed validation errors
    const errors = result.error.errors.map(err => ({
      path: err.path.join('.'),
      message: err.message,
    }));
    throw new Error(`Validation error: ${JSON.stringify(errors)}`);
  }
  return result.data;
};
```

**Explanation:**
- **CreateUserSchema**: Defines the expected structure for a user creation request.
- **validateRequest**: Generic function that validates incoming data against the provided schema. Throws a detailed error if validation fails.

### Using Class Validator

[Class-validator](https://github.com/typestack/class-validator) integrates well with Nest.js for validating request DTOs.

```typescript
import { IsEmail, IsString, MinLength, IsOptional, IsNumber, Min } from 'class-validator';

export class CreateUserDto {
  @IsEmail()
  email: string;

  @IsString()
  @MinLength(8)
  password: string;

  @IsString()
  @MinLength(2)
  name: string;

  @IsOptional()
  @IsNumber()
  @Min(18)
  age?: number;
}
```

**Explanation:**
- **Decorators**: Used to enforce validation rules on each property.
- **CreateUserDto**: Data Transfer Object that represents the structure and validation rules for user creation.

---

## Query Parameters

### Parsing and Validation

Handling query parameters effectively allows for flexible and dynamic API endpoints.

```typescript
interface PaginationQuery {
  page?: number;
  limit?: number;
  sort?: string;
  order?: 'asc' | 'desc';
}

const parsePaginationQuery = (query: Record<string, string>): PaginationQuery => {
  return {
    page: query.page ? parseInt(query.page, 10) : 1,
    limit: query.limit ? parseInt(query.limit, 10) : 10,
    sort: query.sort || 'createdAt',
    order: query.order === 'desc' ? 'desc' : 'asc'
  };
};

const validatePaginationQuery = (query: PaginationQuery): void => {
  if (query.page && query.page < 1) throw new Error('Page must be greater than 0');
  if (query.limit && (query.limit < 1 || query.limit > 100)) {
    throw new Error('Limit must be between 1 and 100');
  }
};
```

**Explanation:**
- **PaginationQuery**: Defines the structure for pagination-related query parameters.
- **parsePaginationQuery**: Converts string query parameters to appropriate types with default values.
- **validatePaginationQuery**: Ensures that pagination parameters fall within acceptable ranges.

**Best Practices:**
- **Default Values**: Always provide sensible defaults to handle missing query parameters.
- **Type Conversion**: Convert query parameters from strings to their intended types.
- **Range Validation**: Ensure numerical parameters fall within acceptable limits to prevent abuse.

---

## Route Parameters

### Parameter Validation

Validating route parameters ensures that endpoints receive valid and expected identifiers.

```typescript
interface RouteParams {
  id: string;
}

const validateRouteParams = (params: RouteParams): void => {
  if (!params.id) throw new Error('ID is required');
  // Example: Validate MongoDB ObjectId format
  if (!/^[0-9a-fA-F]{24}$/.test(params.id)) throw new Error('Invalid ID format');
};
```

**Explanation:**
- **RouteParams**: Represents the expected route parameters.
- **validateRouteParams**: Checks for the presence and correct format of the `id` parameter.

**Best Practices:**
- **Presence Checks**: Ensure required parameters are present.
- **Format Validation**: Validate the format of parameters (e.g., UUIDs, ObjectIds).
- **Descriptive Errors**: Provide clear error messages to aid in debugging.

---

## File Uploads

### Multipart Form Data Handling

Handling file uploads securely and efficiently is essential for APIs that accept user files.

```typescript
import multer, { FileFilterCallback } from 'multer';
import { Request } from 'express';

interface FileUploadOptions {
  maxSize: number;
  allowedMimeTypes: string[];
  destination: string;
}

const defaultFileUploadOptions: FileUploadOptions = {
  maxSize: 5 * 1024 * 1024, // 5MB
  allowedMimeTypes: ['image/jpeg', 'image/png', 'image/gif'],
  destination: 'uploads/'
};

// Multer storage configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, defaultFileUploadOptions.destination);
  },
  filename: (req, file, cb) => {
    // Generate a unique filename
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = file.originalname.split('.').pop();
    cb(null, `${file.fieldname}-${uniqueSuffix}.${ext}`);
  }
});

// File filter to validate mime types and file size
const fileFilter = (req: Request, file: Express.Multer.File, cb: FileFilterCallback) => {
  if (!defaultFileUploadOptions.allowedMimeTypes.includes(file.mimetype)) {
    return cb(new Error('Invalid file type'), false);
  }
  cb(null, true);
};

// Initialize multer
const upload = multer({
  storage,
  limits: { fileSize: defaultFileUploadOptions.maxSize },
  fileFilter
});

// Express.js route using multer middleware
app.post('/upload', upload.single('avatar'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'File upload failed' });
  }
  res.status(201).json({ message: 'File uploaded successfully', file: req.file });
});
```

**Explanation:**
- **Multer**: Middleware for handling `multipart/form-data`, primarily used for file uploads.
- **Storage Configuration**: Specifies where and how to store uploaded files.
- **File Filter**: Validates file types and sizes before accepting the upload.
- **Express Route**: Demonstrates how to use the multer middleware in an Express route.

**Best Practices:**
- **Limit File Size**: Prevent excessively large files from being uploaded.
- **Validate File Types**: Restrict to allowed MIME types to enhance security.
- **Unique Filenames**: Generate unique filenames to avoid collisions and potential overwrites.
- **Secure Storage**: Store uploads in directories with appropriate permissions and consider using cloud storage solutions for scalability.

---

## Request Body Parsing

### JSON Body Parsing

Parsing JSON bodies is fundamental for APIs that accept structured data.

```typescript
interface RequestBodyParser<T> {
  parse(body: unknown): T;
  validate(parsed: T): void;
}

import { z } from 'zod';

class JsonBodyParser<T> implements RequestBodyParser<T> {
  constructor(private schema: z.Schema<T>) {}

  parse(body: unknown): T {
    if (typeof body !== 'object' || body === null) {
      throw new Error('Invalid JSON body');
    }
    return this.schema.parse(body);
  }

  validate(parsed: T): void {
    const result = this.schema.safeParse(parsed);
    if (!result.success) {
      // Extract detailed validation errors
      const errors = result.error.errors.map(err => ({
        path: err.path.join('.'),
        message: err.message,
      }));
      throw new Error(`Validation error: ${JSON.stringify(errors)}`);
    }
  }
}

// Usage Example with Zod
const userSchema = z.object({
  name: z.string().min(2),
  email: z.string().email(),
  age: z.number().min(18).optional(),
});

const parser = new JsonBodyParser(userSchema);

app.post('/users', (req, res) => {
  try {
    const parsedBody = parser.parse(req.body);
    parser.validate(parsedBody);
    // Proceed with processing the validated data
    res.status(201).json({ success: true, data: parsedBody });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});
```

**Explanation:**
- **JsonBodyParser Class**: A generic class that handles parsing and validation of JSON request bodies.
- **Zod Schema**: Defines the structure and validation rules for the expected JSON data.
- **Usage Example**: Demonstrates how to utilize the `JsonBodyParser` in an Express route.

**Best Practices:**
- **Schema Definitions**: Clearly define schemas for expected request bodies to enforce structure and data types.
- **Error Handling**: Provide detailed error messages to help clients understand validation failures.
- **Middleware Integration**: Consider integrating body parsing and validation into middleware for cleaner route handlers.

### Form Data Parsing

Handling form data, especially for file uploads, requires different parsing strategies.

```typescript
import formidable from 'formidable';
import { NextApiRequest, NextApiResponse } from 'next';

// Disable Next.js default body parser for handling multipart/form-data
export const config = {
  api: {
    bodyParser: false
  }
};

const handler = async (req: NextApiRequest, res: NextApiResponse) => {
  if (req.method !== 'POST') {
    res.setHeader('Allow', ['POST']);
    return res.status(405).end(`Method ${req.method} Not Allowed`);
  }

  const form = new formidable.IncomingForm({
    maxFileSize: 5 * 1024 * 1024, // 5MB
    uploadDir: './uploads',
    keepExtensions: true,
  });

  form.parse(req, (err, fields, files) => {
    if (err) {
      return res.status(400).json({ error: 'File upload failed', details: err.message });
    }

    // Access parsed fields and files
    const { name, email } = fields;
    const avatar = files.avatar as formidable.File;

    // Perform additional validation and processing
    if (!name || !email || !avatar) {
      return res.status(400).json({ error: 'Missing required fields or files' });
    }

    res.status(201).json({
      message: 'User uploaded successfully',
      data: { name, email, avatar: avatar.newFilename }
    });
  });
};

export default handler;
```

**Explanation:**
- **Formidable**: A Node.js module for parsing form data, especially file uploads.
- **Configuration**: Disables Next.js's default body parser to handle multipart data.
- **Form Parsing**: Extracts fields and files from the request, performing additional validation before processing.

**Best Practices:**
- **Disable Default Body Parsers**: When handling multipart data, disable default parsers to avoid conflicts.
- **Limit File Sizes**: Protect your server from large uploads by setting maximum file sizes.
- **Secure Upload Directories**: Store uploaded files in secure directories and sanitize filenames to prevent security vulnerabilities.
- **Error Handling**: Gracefully handle parsing errors and provide meaningful feedback to clients.

---

## Framework-Specific Implementations

Each framework has its own conventions and best practices for handling API requests. Below are detailed implementations for **Express.js**, **Next.js**, and **Nest.js**.

### Express.js Implementation

Express.js is a minimalistic and flexible Node.js web application framework that provides a robust set of features for web and mobile applications.

```typescript:examples/express/routes/users.ts
import express, { Request, Response, NextFunction } from 'express';
import { validateRequest } from '../validators';
import { CreateUserSchema } from '../schemas';

const router = express.Router();

// Middleware for authentication (example)
const authenticate = (req: Request, res: Response, next: NextFunction) => {
  const token = req.headers.authorization;
  if (!token) {
    return res.status(401).json({ success: false, error: 'Unauthorized' });
  }
  // Verify token logic here
  next();
};

router.post('/users', authenticate, async (req: Request, res: Response) => {
  try {
    const validatedBody = validateRequest(CreateUserSchema, req.body);
    // Process validated request (e.g., save to database)
    res.status(201).json({ success: true, data: validatedBody });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

export default router;
```

**Explanation:**
- **Router Setup**: Defines routes related to user operations.
- **Authentication Middleware**: Ensures that only authenticated requests can access certain endpoints.
- **Request Validation**: Validates incoming request bodies against predefined schemas.
- **Error Handling**: Catches and responds to validation errors appropriately.

**Best Practices:**
- **Modular Routes**: Organize routes into separate modules for maintainability.
- **Middleware Usage**: Utilize middleware for cross-cutting concerns like authentication and logging.
- **Asynchronous Handling**: Use asynchronous handlers to manage non-blocking operations effectively.

### Next.js Implementation (App Router)

Next.js provides a powerful routing system with built-in support for API routes, enabling developers to create serverless functions easily.

```typescript:examples/nextjs/app/api/users/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { validateRequest } from '@/lib/validators';
import { CreateUserSchema } from '@/lib/schemas';

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const validatedBody = validateRequest(CreateUserSchema, body);
    
    // Process validated request (e.g., save to database)
    
    return NextResponse.json({ success: true, data: validatedBody }, { status: 201 });
  } catch (error) {
    return NextResponse.json(
      { success: false, error: error.message },
      { status: 400 }
    );
  }
}
```

**Explanation:**
- **API Route Handler**: Defines a POST handler for user creation.
- **Request Parsing**: Uses `request.json()` to parse the incoming JSON body.
- **Validation**: Validates the parsed body against the `CreateUserSchema`.
- **Response**: Returns appropriate JSON responses based on the outcome.

**Best Practices:**
- **Serverless Optimization**: Keep API route handlers lightweight to optimize for serverless environments.
- **Error Handling**: Use consistent error formats to simplify client-side error handling.
- **Reusability**: Extract common logic (like validation) into reusable utilities or libraries.

### Nest.js Implementation

Nest.js is a progressive Node.js framework for building efficient and scalable server-side applications. It leverages TypeScript and incorporates elements from Object-Oriented Programming (OOP), Functional Programming (FP), and Functional Reactive Programming (FRP).

```typescript:nestjs/src/users/users.controller.ts
import { Controller, Post, Body, UsePipes, ValidationPipe, HttpException, HttpStatus } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UsersService } from './users.service';

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Post()
  @UsePipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }))
  async create(@Body() createUserDto: CreateUserDto) {
    try {
      const user = await this.usersService.create(createUserDto);
      return { success: true, data: user };
    } catch (error) {
      throw new HttpException({
        success: false,
        error: error.message,
      }, error.status || HttpStatus.BAD_REQUEST);
    }
  }
}
```

```typescript:nestjs/src/users/users.service.ts
import { Injectable } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
// Import your User entity or model here

@Injectable()
export class UsersService {
  // Inject repositories or models if using ORM like TypeORM or Prisma

  async create(createUserDto: CreateUserDto) {
    // Implement user creation logic (e.g., save to database)
    // Example with pseudo-code:
    // const user = await this.userRepository.save(createUserDto);
    // return user;

    // For demonstration, return the DTO
    return createUserDto;
  }
}
```

**Explanation:**
- **Controller**: Defines endpoints and handles incoming requests.
- **DTO (Data Transfer Object)**: Ensures that incoming data adheres to expected validation rules.
- **Service**: Encapsulates business logic, promoting separation of concerns.
- **ValidationPipe**: Automatically validates incoming requests based on DTO rules, rejecting invalid data.

**Best Practices:**
- **Separation of Concerns**: Keep controllers thin by delegating business logic to services.
- **DTO Usage**: Use DTOs to define and validate the shape of incoming data.
- **Global Validation Pipes**: Consider applying validation pipes globally to reduce redundancy.

---

## Best Practices

### 1. Request Validation

- **Always Validate Inputs**: Ensure that all incoming data conforms to expected formats and types.
- **Use Strong Typing**: Leverage TypeScript to enforce type safety.
- **Comprehensive Validation**: Validate both the structure and business rules of the data.
- **Centralized Validation Logic**: Maintain validation schemas in centralized locations for consistency.

### 2. Security Considerations

Enhancing the security of your API helps protect against common vulnerabilities.

```typescript
const securityHeaders = {
  'Content-Security-Policy': "default-src 'self'",
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'X-XSS-Protection': '1; mode=block',
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'
};

// Middleware to apply security headers
const applySecurityHeaders = (req: Request, res: Response, next: NextFunction) => {
  Object.entries(securityHeaders).forEach(([header, value]) => {
    res.setHeader(header, value);
  });
  next();
};

// Usage in Express.js
app.use(applySecurityHeaders);
```

**Explanation:**
- **Content-Security-Policy**: Mitigates Cross-Site Scripting (XSS) and other content injection attacks.
- **X-Content-Type-Options**: Prevents MIME type sniffing.
- **X-Frame-Options**: Protects against Clickjacking by controlling whether the browser should be allowed to render a page in a `<frame>`, `<iframe>`, etc.
- **X-XSS-Protection**: Enables the browser's built-in XSS filtering.
- **Strict-Transport-Security**: Enforces secure (HTTPS) connections to the server.

### 3. Request Logging

Logging requests is vital for monitoring, debugging, and auditing purposes.

```typescript
const logRequest = (req: Request, res: Response, next: NextFunction) => {
  console.log({
    timestamp: new Date().toISOString(),
    method: req.method,
    path: req.path,
    query: req.query,
    body: req.body,
    ip: req.ip,
    userAgent: req.headers['user-agent']
  });
  next();
};

// Usage in Express.js
app.use(logRequest);
```

**Explanation:**
- **Comprehensive Logging**: Logs key details about each request, including method, path, query parameters, body, IP address, and user agent.
- **Structured Logging**: Logs data in a structured format (e.g., JSON) to facilitate easy parsing and analysis.

**Best Practices:**
- **Avoid Sensitive Data**: Ensure that sensitive information (e.g., passwords) is not logged.
- **Log Levels**: Implement different log levels (info, warning, error) to categorize logs appropriately.
- **Persistent Storage**: Store logs in a persistent and searchable storage solution (e.g., ELK stack, Loggly).

### 4. Rate Limiting

Rate limiting helps protect your API from abuse and ensures fair usage.

```typescript
interface RateLimitConfig {
  windowMs: number;
  maxRequests: number;
}

class RateLimiter {
  private requests: Map<string, number[]> = new Map();

  constructor(private config: RateLimitConfig) {}

  isAllowed(ip: string): boolean {
    const now = Date.now();
    const windowStart = now - this.config.windowMs;
    
    const requests = this.requests.get(ip) || [];
    const recentRequests = requests.filter(time => time > windowStart);
    
    if (recentRequests.length >= this.config.maxRequests) {
      return false;
    }
    
    recentRequests.push(now);
    this.requests.set(ip, recentRequests);
    return true;
  }
}

// Middleware usage in Express.js
const rateLimitConfig: RateLimitConfig = { windowMs: 15 * 60 * 1000, maxRequests: 100 };
const rateLimiter = new RateLimiter(rateLimitConfig);

const rateLimitMiddleware = (req: Request, res: Response, next: NextFunction) => {
  const ip = req.ip;
  if (!rateLimiter.isAllowed(ip)) {
    return res.status(429).json({ success: false, error: 'Too Many Requests' });
  }
  next();
};

app.use(rateLimitMiddleware);
```

**Explanation:**
- **RateLimiter Class**: Tracks incoming requests per IP within a specified time window.
- **Middleware**: Checks if an IP has exceeded the allowed number of requests and responds accordingly.

**Best Practices:**
- **Distributed Rate Limiting**: For scalable applications, implement rate limiting in a distributed manner using shared storage (e.g., Redis).
- **Dynamic Limits**: Adjust rate limits based on user roles or subscription plans.
- **Exponential Backoff**: Implement strategies like exponential backoff to discourage persistent abuse.

### 5. Request Timeout Handling

Handling timeouts ensures that clients receive timely responses and that server resources are not indefinitely tied up.

```typescript
const timeoutMiddleware = (timeout: number) => {
  return (req: Request, res: Response, next: NextFunction) => {
    const timer = setTimeout(() => {
      res.status(408).json({ success: false, error: 'Request timeout' });
    }, timeout);

    res.on('finish', () => {
      clearTimeout(timer);
    });

    next();
  };
};

// Usage in Express.js (e.g., 10 seconds timeout)
app.use(timeoutMiddleware(10000));
```

**Explanation:**
- **Middleware Function**: Sets a timer for each request. If the request takes longer than the specified timeout, it responds with a 408 status code.
- **Cleanup**: Clears the timer once the response has been sent to prevent unnecessary executions.

**Best Practices:**
- **Appropriate Timeouts**: Set timeouts based on the expected processing time of your endpoints.
- **Graceful Degradation**: Ensure that ongoing processes are handled appropriately when a timeout occurs.
- **Monitoring and Alerts**: Track timeout occurrences to identify and address performance bottlenecks.

---

## Error Handling

Effective error handling provides clarity and consistency in API responses, aiding both developers and users in understanding issues.

### Request Error Handler

Creating a standardized error handling mechanism ensures that all errors are processed and returned in a consistent format.

```typescript
class RequestError extends Error {
  constructor(
    public statusCode: number,
    message: string,
    public details?: any
  ) {
    super(message);
    this.name = 'RequestError';
  }
}

const handleRequestError = (error: unknown) => {
  if (error instanceof RequestError) {
    return {
      success: false,
      error: error.message,
      details: error.details,
      statusCode: error.statusCode
    };
  }

  return {
    success: false,
    error: 'Internal server error',
    statusCode: 500
  };
};
```

**Explanation:**
- **RequestError Class**: Custom error class that includes a status code and optional details.
- **handleRequestError Function**: Processes different error types and returns a standardized error response.

**Usage Example in Express.js:**

```typescript
app.post('/users', (req: Request, res: Response) => {
  try {
    // Simulate an operation that may throw a RequestError
    if (!req.body.email) {
      throw new RequestError(400, 'Email is required');
    }
    // Proceed with operation
    res.status(201).json({ success: true, data: req.body });
  } catch (error) {
    const formattedError = handleRequestError(error);
    res.status(formattedError.statusCode).json(formattedError);
  }
});
```

**Best Practices:**
- **Consistent Format**: Ensure all error responses follow a consistent structure.
- **Meaningful Messages**: Provide clear and actionable error messages.
- **Avoid Exposing Sensitive Information**: Do not expose stack traces or internal error details to clients.
- **HTTP Status Codes**: Use appropriate HTTP status codes to signify the nature of the error.

---

## Conclusion

Handling API requests effectively involves a combination of proper validation, secure practices, and consistent error handling. By following the patterns and best practices outlined in this guide, you can build robust and maintainable APIs using **Express.js**, **Next.js**, and **Nest.js** frameworks.

---

## Additional Resources

- [Express.js Documentation](https://expressjs.com/)
- [Next.js Documentation](https://nextjs.org/docs)
- [Nest.js Documentation](https://docs.nestjs.com/)
- [Zod Documentation](https://github.com/colinhacks/zod)
- [Class-validator Documentation](https://github.com/typestack/class-validator)
- [Formidable Documentation](https://github.com/node-formidable/formidable)
- [Multer Documentation](https://github.com/expressjs/multer)