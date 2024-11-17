# Environment Setup Guide

## Development Environment Setup

### 1. Project Structure
Create the following directory structure:
```bash
mkdir -p src/{config,controllers,services,models,middleware,utils}
```

### 2. Environment Variables
Create a `.env` file in your project root:

```env
# Server Configuration
PORT=3000
NODE_ENV=development

# Database Configuration
DATABASE_URL="postgresql://user:password@localhost:5432/dbname"
MONGODB_URI="mongodb://localhost:27017/dbname"

# Authentication
JWT_SECRET="your-secret-key"
JWT_EXPIRES_IN="1h"

# API Configuration
API_PREFIX="/api/v1"
RATE_LIMIT_WINDOW=15
RATE_LIMIT_MAX=100
```

### 3. Environment Variable Validation

Install required packages:
```bash
npm install dotenv envalid
```

Create an environment validation file:

```typescript
// src/config/env.config.ts
import { cleanEnv, str, num, port } from 'envalid';

export const env = cleanEnv(process.env, {
  NODE_ENV: str({ choices: ['development', 'test', 'production'] }),
  PORT: port({ default: 3000 }),
  DATABASE_URL: str(),
  JWT_SECRET: str(),
  API_PREFIX: str({ default: '/api/v1' }),
  RATE_LIMIT_WINDOW: num({ default: 15 }),
  RATE_LIMIT_MAX: num({ default: 100 })
});
```

### 4. Development Tools Setup

#### ESLint Configuration
```bash
npm install -D eslint @typescript-eslint/parser @typescript-eslint/eslint-plugin
```

Create `.eslintrc.js`:
```javascript
module.exports = {
  parser: '@typescript-eslint/parser',
  plugins: ['@typescript-eslint'],
  extends: [
    'eslint:recommended',
    'plugin:@typescript-eslint/recommended'
  ],
  rules: {
    '@typescript-eslint/explicit-function-return-type': 'warn',
    '@typescript-eslint/no-explicit-any': 'warn'
  }
};
```

#### Prettier Configuration
```bash
npm install -D prettier
```

Create `.prettierrc`:
```json
{
  "singleQuote": true,
  "trailingComma": "es5",
  "printWidth": 100,
  "tabWidth": 2,
  "semi": true
}
```

### 5. Git Configuration

Create `.gitignore`:
```gitignore
# Dependencies
node_modules/

# Build output
dist/
build/

# Environment variables
.env
.env.local
.env.*.local

# Logs
logs/
*.log
npm-debug.log*

# IDE files
.idea/
.vscode/
*.swp
*.swo

# Testing
coverage/

# Temporary files
.DS_Store
Thumbs.db
```

### 6. Scripts Setup

Update `package.json` scripts:
```json
{
  "scripts": {
    "start": "node dist/index.js",
    "dev": "nodemon src/index.ts",
    "build": "tsc",
    "lint": "eslint . --ext .ts",
    "format": "prettier --write \"src/**/*.ts\"",
    "test": "jest",
    "test:watch": "jest --watch",
    "test:coverage": "jest --coverage"
  }
}
```
```

## docs/http-handling/common-patterns.md
```markdown
# Common HTTP Handling Patterns

## Request Handling Patterns

### 1. Basic Request Structure
```typescript
interface BaseRequest {
  body?: any;
  query?: Record<string, string>;
  params?: Record<string, string>;
  headers: Record<string, string>;
}
```

### 2. Common Status Codes
```typescript
enum HTTPStatus {
  OK = 200,
  CREATED = 201,
  NO_CONTENT = 204,
  BAD_REQUEST = 400,
  UNAUTHORIZED = 401,
  FORBIDDEN = 403,
  NOT_FOUND = 404,
  INTERNAL_SERVER_ERROR = 500
}
```

### 3. Standard Response Format
```typescript
interface APIResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
  message?: string;
  metadata?: {
    page?: number;
    limit?: number;
    total?: number;
  };
}
```

## Error Handling Patterns

### 1. Custom Error Classes
```typescript
class APIError extends Error {
  constructor(
    public statusCode: number,
    message: string,
    public isOperational = true
  ) {
    super(message);
    Object.setPrototypeOf(this, APIError.prototype);
  }
}

class ValidationError extends APIError {
  constructor(message: string) {
    super(400, message);
  }
}

class NotFoundError extends APIError {
  constructor(resource: string) {
    super(404, `${resource} not found`);
  }
}
```

### 2. Error Handler Middleware
```typescript
const errorHandler = (
  err: Error,
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  if (err instanceof APIError) {
    res.status(err.statusCode).json({
      success: false,
      error: err.message
    });
    return;
  }

  // Default error
  res.status(500).json({
    success: false,
    error: 'Internal server error'
  });
};
```

## Middleware Patterns

### 1. Request Validation
```typescript
const validateRequest = (schema: any) => {
  return (req: Request, res: Response, next: NextFunction) => {
    const { error } = schema.validate(req.body);
    if (error) {
      throw new ValidationError(error.details[0].message);
    }
    next();
  };
};
```

### 2. Authentication Middleware
```typescript
const authenticate = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    throw new APIError(401, 'Authentication required');
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET!);
    req.user = decoded;
    next();
  } catch (error) {
    throw new APIError(401, 'Invalid token');
  }
};
```

### 3. Request Logger
```typescript
const requestLogger = (
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  console.log(`${req.method} ${req.path}`);
  console.log('Body:', req.body);
  console.log('Query:', req.query);
  console.log('Params:', req.params);
  
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    console.log(
      `${req.method} ${req.path} ${res.statusCode} - ${duration}ms`
    );
  });
  
  next();
};
```

## Rate Limiting Pattern
```typescript
import rateLimit from 'express-rate-limit';

const createRateLimiter = (
  windowMs: number = 15 * 60 * 1000,
  max: number = 100
) => {
  return rateLimit({
    windowMs,
    max,
    message: {
      success: false,
      error: 'Too many requests, please try again later'
    }
  });
};
```

## CORS Configuration
```typescript
import cors from 'cors';

const corsOptions = {
  origin: process.env.NODE_ENV === 'production'
    ? ['https://yourapp.com']
    : ['http://localhost:3000'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  maxAge: 86400 // 24 hours
};

app.use(cors(corsOptions));
```

## Body Parser Configuration
```typescript
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
```

## File Upload Pattern
```typescript
import multer from 'multer';

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = `${Date.now()}-${Math.round(Math.random() * 1E9)}`;
    cb(null, `${file.fieldname}-${uniqueSuffix}`);
  }
});

const upload = multer({
  storage,
  limits: {
    fileSize: 5 * 1024 * 1024 // 5MB
  },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Not an image file'));
    }
  }
});
```