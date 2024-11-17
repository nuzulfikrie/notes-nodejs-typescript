## docs/http-handling/express.md
# Express.js HTTP Handling Guide

## Basic Setup

### Installation
```bash
npm install express @types/express cors helmet
```

### Basic Express Application
```typescript
// src/app.ts
import express, { Application } from 'express';
import cors from 'cors';
import helmet from 'helmet';

const app: Application = express();

// Middleware
app.use(cors());
app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

export default app;
```

## Request Methods

### GET Requests
```typescript
// Basic GET
app.get('/api/items', async (req, res) => {
  try {
    const items = await ItemService.findAll();
    res.json({ success: true, data: items });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Failed to fetch items' });
  }
});

// GET with URL Parameters
app.get('/api/items/:id', async (req, res) => {
  try {
    const item = await ItemService.findById(req.params.id);
    if (!item) {
      return res.status(404).json({ 
        success: false, 
        error: 'Item not found' 
      });
    }
    res.json({ success: true, data: item });
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      error: 'Failed to fetch item' 
    });
  }
});

// GET with Query Parameters
app.get('/api/search', async (req, res) => {
  const { query, page = '1', limit = '10' } = req.query;
  try {
    const results = await ItemService.search({
      query: query as string,
      page: parseInt(page as string),
      limit: parseInt(limit as string)
    });
    res.json({ success: true, data: results });
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      error: 'Search failed' 
    });
  }
});
```

### POST Requests
```typescript
// Basic POST with Body
app.post('/api/items', async (req, res) => {
  try {
    const newItem = await ItemService.create(req.body);
    res.status(201).json({ 
      success: true, 
      data: newItem 
    });
  } catch (error) {
    res.status(400).json({ 
      success: false, 
      error: 'Failed to create item' 
    });
  }
});

// POST with File Upload
import multer from 'multer';

const upload = multer({ 
  dest: 'uploads/',
  limits: { fileSize: 5 * 1024 * 1024 } // 5MB
});

app.post('/api/upload', upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ 
      success: false, 
      error: 'No file uploaded' 
    });
  }
  res.json({ 
    success: true, 
    data: { filename: req.file.filename } 
  });
});
```

### PUT Requests
```typescript
app.put('/api/items/:id', async (req, res) => {
  try {
    const updatedItem = await ItemService.update(
      req.params.id, 
      req.body
    );
    if (!updatedItem) {
      return res.status(404).json({ 
        success: false, 
        error: 'Item not found' 
      });
    }
    res.json({ success: true, data: updatedItem });
  } catch (error) {
    res.status(400).json({ 
      success: false, 
      error: 'Failed to update item' 
    });
  }
});
```

### PATCH Requests
```typescript
app.patch('/api/items/:id', async (req, res) => {
  try {
    const patchedItem = await ItemService.patch(
      req.params.id, 
      req.body
    );
    if (!patchedItem) {
      return res.status(404).json({ 
        success: false, 
        error: 'Item not found' 
      });
    }
    res.json({ success: true, data: patchedItem });
  } catch (error) {
    res.status(400).json({ 
      success: false, 
      error: 'Failed to patch item' 
    });
  }
});
```

### DELETE Requests
```typescript
app.delete('/api/items/:id', async (req, res) => {
  try {
    await ItemService.delete(req.params.id);
    res.status(204).send();
  } catch (error) {
    res.status(400).json({ 
      success: false, 
      error: 'Failed to delete item' 
    });
  }
});
```

## Middleware Implementation

### Error Handling Middleware
```typescript
interface ErrorResponse {
  success: false;
  error: string;
  stack?: string;
}

const errorHandler = (
  err: Error,
  req: express.Request,
  res: express.Response,
  next: express.NextFunction
) => {
  const response: ErrorResponse = {
    success: false,
    error: err.message || 'Internal Server Error'
  };

  if (process.env.NODE_ENV === 'development') {
    response.stack = err.stack;
  }

  res.status(500).json(response);
};

app.use(errorHandler);
```

### Authentication Middleware
```typescript
import jwt from 'jsonwebtoken';

const authenticateToken = (
  req: express.Request,
  res: express.Response,
  next: express.NextFunction
) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ 
      success: false, 
      error: 'Authentication required' 
    });
  }

  try {
    const user = jwt.verify(token, process.env.JWT_SECRET!);
    req.user = user;
    next();
  } catch (error) {
    res.status(403).json({ 
      success: false, 
      error: 'Invalid token' 
    });
  }
};
```

### Request Validation Middleware
```typescript
import { validate } from 'class-validator';

const validateRequest = (type: any) => {
  return async (
    req: express.Request,
    res: express.Response,
    next: express.NextFunction
  ) => {
    const input = Object.assign(new type(), req.body);
    const errors = await validate(input);

    if (errors.length > 0) {
      return res.status(400).json({
        success: false,
        error: 'Validation failed',
        details: errors.map(error => ({
          property: error.property,
          constraints: error.constraints
        }))
      });
    }

    req.validatedBody = input;
    next();
  };
};
```

## Route Organization

### Router Implementation
```typescript
// src/routes/item.routes.ts
import { Router } from 'express';
import { ItemController } from '../controllers/item.controller';

const router = Router();
const itemController = new ItemController();

router.get('/', itemController.getAll);
router.get('/:id', itemController.getOne);
router.post('/', itemController.create);
router.put('/:id', itemController.update);
router.delete('/:id', itemController.delete);

export default router;

// src/app.ts
import itemRoutes from './routes/item.routes';
app.use('/api/items', itemRoutes);
```

## Advanced Features

### Request Rate Limiting
```typescript
import rateLimit from 'express-rate-limit';

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: {
    success: false,
    error: 'Too many requests, please try again later'
  }
});

app.use('/api/', limiter);
```

### Request Logging
```typescript
import morgan from 'morgan';

if (process.env.NODE_ENV === 'development') {
  app.use(morgan('dev'));
} else {
  app.use(morgan('combined'));
}
```

### Compression
```typescript
import compression from 'compression';

app.use(compression());
```

### Security Headers
```typescript
import helmet from 'helmet';

app.use(helmet());
```

### CORS Configuration
```typescript
import cors from 'cors';

const corsOptions = {
  origin: process.env.NODE_ENV === 'production' 
    ? 'https://yourapp.com' 
    : 'http://localhost:3000',
  optionsSuccessStatus: 200,
  credentials: true
};

app.use(cors(corsOptions));
```