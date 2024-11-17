
# Installation Guide

This guide covers the installation and setup process for all required software and tools.

## Required Software

### 1. Node.js
```bash
# Using nvm (recommended)
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash
nvm install 18
nvm use 18

# Or download directly from nodejs.org
https://nodejs.org/en/download/
```

### 2. TypeScript
```bash
npm install -g typescript
tsc --version # Should show 5.0.0 or higher
```

### 3. Package Manager
Choose one of the following:

#### npm (comes with Node.js)
```bash
npm --version
```

#### yarn
```bash
npm install -g yarn
yarn --version
```

#### pnpm
```bash
npm install -g pnpm
pnpm --version
```

## Framework-Specific Installation

### Express.js
```bash
npm install express @types/express
```

### Next.js
```bash
npx create-next-app@latest --typescript
```

### Nest.js
```bash
npm install -g @nestjs/cli
nest new project-name
```

## Development Tools

### 1. VS Code Extensions
- ESLint
- Prettier
- TypeScript Language Support
- Jest Runner
- Thunder Client (for API testing)

### 2. Git Setup
```bash
git init
git config user.name "Your Name"
git config user.email "your.email@example.com"
```

### 3. Environment Setup
```bash
cp config/.env.example .env
```

## Verification Steps

1. Verify TypeScript:
```bash
tsc --version
```

2. Verify Node.js:
```bash
node --version
```

3. Test TypeScript compilation:
```bash
echo "console.log('Hello, TypeScript!')" > test.ts
tsc test.ts
node test.js
```

## Common Issues and Solutions

### Node.js Version Conflicts
Use nvm to manage multiple Node.js versions:
```bash
nvm install 18
nvm use 18
```

### TypeScript Compilation Errors
Ensure tsconfig.json is properly configured:
```bash
tsc --init
```

### Package Manager Conflicts
Clean npm cache if experiencing issues:
```bash
npm cache clean --force
```
