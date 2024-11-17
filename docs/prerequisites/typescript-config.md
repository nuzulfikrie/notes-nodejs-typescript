
# TypeScript Configuration Guide

## Overview

TypeScript configuration is crucial for modern Node.js development. This guide covers essential configurations for different frameworks and common use cases.

## Basic Configuration

### tsconfig.json Explanation

The `tsconfig.json` file is the heart of TypeScript project configuration. Here's a detailed breakdown:

```json
{
  "compilerOptions": {
    // JavaScript Environment Configuration
    "target": "ES2022",        // Specifies ECMAScript target version
    "module": "NodeNext",      // Specifies module code generation method
    "lib": ["ES2022"],        // Specifies library files to include
    
    // Module Resolution
    "moduleResolution": "NodeNext", // Determines how modules are resolved
    "baseUrl": "./",          // Base directory for resolving non-relative module names
    "paths": {               // Path mapping for module aliases
      "@/*": ["src/*"]
    },
    
    // Output Configuration
    "outDir": "./dist",       // Output directory for compiled files
    "rootDir": "./src",       // Root directory of input files
    "sourceMap": true,        // Generate source maps for debugging
    
    // Type Checking
    "strict": true,           // Enables all strict type checking options
    "noImplicitAny": true,    // Raise error on expressions with implied 'any' type
    "strictNullChecks": true, // Enable strict null checks
    
    // Interoperability
    "esModuleInterop": true,  // Enables interoperability between CommonJS and ES Modules
    "allowJs": true,          // Allow JavaScript files to be compiled
    
    // Advanced Options
    "skipLibCheck": true,     // Skip type checking of declaration files
    "forceConsistentCasingInFileNames": true, // Ensure consistent casing in file names
    "experimentalDecorators": true,    // Enable experimental decorators
    "emitDecoratorMetadata": true     // Emit decorator metadata
  },
  "include": ["src/**/*"],    // Files to include in compilation
  "exclude": ["node_modules", "**/*.spec.ts"] // Files to exclude
}
```

## Framework-Specific Configurations

### Express.js Configuration
```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "CommonJS",      // Express works best with CommonJS
    "outDir": "./dist",
    "rootDir": "./src",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "typeRoots": [            // Custom type definition locations
      "./node_modules/@types",
      "./src/types"
    ],
    "paths": {
      "@middleware/*": ["src/middleware/*"],
      "@controllers/*": ["src/controllers/*"],
      "@models/*": ["src/models/*"]
    }
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "**/*.spec.ts"]
}
```

### Next.js Configuration
```json
{
  "compilerOptions": {
    "target": "ES2022",
    "lib": ["dom", "dom.iterable", "esnext"],
    "allowJs": true,
    "skipLibCheck": true,
    "strict": true,
    "forceConsistentCasingInFileNames": true,
    "noEmit": true,           // Next.js handles compilation
    "esModuleInterop": true,
    "module": "esnext",
    "moduleResolution": "node",
    "resolveJsonModule": true,
    "isolatedModules": true,
    "jsx": "preserve",        // Preserve JSX for Next.js
    "incremental": true,
    "plugins": [
      {
        "name": "next"
      }
    ],
    "paths": {
      "@/*": ["./src/*"],
      "@components/*": ["src/components/*"],
      "@lib/*": ["src/lib/*"],
      "@styles/*": ["src/styles/*"]
    }
  },
  "include": [
    "next-env.d.ts",
    "**/*.ts",
    "**/*.tsx",
    ".next/types/**/*.ts"
  ],
  "exclude": ["node_modules"]
}
```

### Nest.js Configuration
```json
{
  "compilerOptions": {
    "module": "commonjs",
    "declaration": true,      // Generate .d.ts files
    "removeComments": true,
    "emitDecoratorMetadata": true,
    "experimentalDecorators": true,
    "allowSyntheticDefaultImports": true,
    "target": "ES2022",
    "sourceMap": true,
    "outDir": "./dist",
    "baseUrl": "./",
    "incremental": true,
    "skipLibCheck": true,
    "strictNullChecks": true,
    "noImplicitAny": true,
    "strictBindCallApply": true,
    "forceConsistentCasingInFileNames": true,
    "noFallthroughCasesInSwitch": true,
    "paths": {
      "@modules/*": ["src/modules/*"],
      "@services/*": ["src/services/*"],
      "@interfaces/*": ["src/interfaces/*"]
    }
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "dist"]
}
```

## Type Declarations

### Custom Type Declarations
Create a `types` directory in your project for custom type definitions:

```typescript
// types/express/index.d.ts
declare namespace Express {
  export interface Request {
    user?: {
      id: string;
      email: string;
      roles: string[];
    };
    session?: {
      token: string;
      expires: Date;
    };
  }
}
```

### Environment Variables
```typescript
// types/environment.d.ts
declare namespace NodeJS {
  interface ProcessEnv {
    // Server Configuration
    NODE_ENV: 'development' | 'production' | 'test';
    PORT: string;
    HOST: string;
    
    // Database Configuration
    DATABASE_URL: string;
    DATABASE_USER: string;
    DATABASE_PASSWORD: string;
    
    // Authentication
    JWT_SECRET: string;
    JWT_EXPIRES_IN: string;
    
    // External Services
    AWS_ACCESS_KEY: string;
    AWS_SECRET_KEY: string;
    REDIS_URL: string;
  }
}
```

## Best Practices

1. **Strict Type Checking**
Enable comprehensive type checking:
```json
{
  "compilerOptions": {
    "strict": true,
    "noImplicitAny": true,
    "strictNullChecks": true,
    "strictFunctionTypes": true,
    "strictBindCallApply": true
  }
}
```

2. **Path Aliases**
Use path aliases for cleaner imports:
```json
{
  "compilerOptions": {
    "baseUrl": ".",
    "paths": {
      "@/*": ["src/*"],
      "@config/*": ["src/config/*"],
      "@utils/*": ["src/utils/*"]
    }
  }
}
```

3. **Source Maps and Debugging**
Enable proper debugging support:
```json
{
  "compilerOptions": {
    "sourceMap": true,
    "inlineSourceMap": false,
    "inlineSources": false
  }
}
```

4. **Module Resolution**
Configure modern module resolution:
```json
{
  "compilerOptions": {
    "moduleResolution": "NodeNext",
    "allowSyntheticDefaultImports": true,
    "esModuleInterop": true
  }
}
```

## Common Issues and Solutions

### Path Aliases in Jest
When using path aliases, configure Jest accordingly:
```javascript
// jest.config.js
module.exports = {
  moduleNameMapper: {
    '^@/(.*)$': '<rootDir>/src/$1',
    '^@utils/(.*)$': '<rootDir>/src/utils/$1'
  }
}
```

### Working with Decorators
Enable and configure decorator support:
```json
{
  "compilerOptions": {
    "experimentalDecorators": true,
    "emitDecoratorMetadata": true
  }
}
```