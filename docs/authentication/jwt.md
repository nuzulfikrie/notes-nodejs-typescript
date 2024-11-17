## docs/authentication/jwt.md
```markdown
# JWT Authentication Guide

A comprehensive guide for implementing JWT (JSON Web Token) authentication in **Express.js**, **Next.js**, and **Nest.js**. This guide includes best practices, code examples, and strategies to ensure secure and efficient authentication.

## Table of Contents
- [Introduction](#introduction)
- [Common JWT Utilities](#common-jwt-utilities)
  - [JWT Helper Functions](#jwt-helper-functions)
- [Express.js Implementation](#expressjs-implementation)
  - [Authentication Middleware](#authentication-middleware)
  - [Authentication Routes](#authentication-routes)
- [Next.js Implementation](#nextjs-implementation)
  - [Authentication Hooks](#authentication-hooks)
  - [Authentication API Routes](#authentication-api-routes)
  - [Protected Route Component](#protected-route-component)
- [Nest.js Implementation](#nestjs-implementation)
  - [Auth Module](#auth-module)
- [Security Best Practices](#security-best-practices)
  - [1. Token Storage](#1-token-storage)
  - [2. Token Refresh Strategy](#2-token-refresh-strategy)
  - [3. Request Interceptor](#3-request-interceptor)
  - [4. CSRF Protection](#4-csrf-protection)
  - [5. Rate Limiting](#5-rate-limiting)
  - [6. Password Hashing](#6-password-hashing)
  - [7. User Session Management](#7-user-session-management)
  - [8. Security Headers](#8-security-headers)
  - [9. Audit Logging](#9-audit-logging)
  - [10. Token Blacklisting](#10-token-blacklisting)
- [Conclusion](#conclusion)

## Introduction

JWT (JSON Web Token) is a compact, URL-safe means of representing claims to be transferred between two parties. It is commonly used for authentication and information exchange in web applications. This guide explores various aspects of JWT authentication, including token generation, verification, and best practices, using three popular TypeScript frameworks: **Express.js**, **Next.js**, and **Nest.js**.

---

## Common JWT Utilities

### JWT Helper Functions

Helper functions simplify the process of generating and verifying JWTs.

```typescript
// utils/jwt.utils.ts
import jwt from 'jsonwebtoken';

interface JWTPayload {
  userId: string;
  email: string;
  role: string;
}

export class JWTUtil {
  private static SECRET = process.env.JWT_SECRET!;
  private static REFRESH_SECRET = process.env.JWT_REFRESH_SECRET!;

  static generateTokens(payload: JWTPayload) {
    const accessToken = jwt.sign(payload, this.SECRET, { expiresIn: '15m' });
    const refreshToken = jwt.sign(payload, this.REFRESH_SECRET, { expiresIn: '7d' });
    return { accessToken, refreshToken };
  }

  static verifyToken(token: string): JWTPayload {
    return jwt.verify(token, this.SECRET) as JWTPayload;
  }

  static verifyRefreshToken(token: string): JWTPayload {
    return jwt.verify(token, this.REFRESH_SECRET) as JWTPayload;
  }
}
```

**Explanation:**
- **JWTPayload Interface**: Defines the structure of the payload included in the JWT.
- **JWTUtil Class**: Provides utility methods for generating and verifying access and refresh tokens.
- **generateTokens Method**: Creates access and refresh tokens with specified expiration times.
- **verifyToken Method**: Verifies the validity of an access token.
- **verifyRefreshToken Method**: Verifies the validity of a refresh token.

**Best Practices:**
- **Environment Variables**: Store secrets in environment variables to enhance security.
- **Short Expiration Times**: Use short expiration times for access tokens to limit exposure in case of compromise.
- **Separate Secrets**: Use separate secrets for access and refresh tokens to enhance security.

---

## Express.js Implementation

Express.js provides a flexible and minimalistic framework for implementing JWT authentication.

### Authentication Middleware

Middleware is used to protect routes by verifying JWTs.

```typescript
// middleware/auth.middleware.ts
import { Request, Response, NextFunction } from 'express';
import { JWTUtil } from '../utils/jwt.utils';

declare global {
  namespace Express {
    interface Request {
      user?: JWTPayload;
    }
  }
}

export const authMiddleware = (req: Request, res: Response, next: NextFunction) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      throw new Error('No token provided');
    }

    const decoded = JWTUtil.verifyToken(token);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({
      success: false,
      error: 'Unauthorized'
    });
  }
};
```

**Explanation:**
- **authMiddleware Function**: Verifies the JWT from the `Authorization` header and attaches the decoded payload to the request object.
- **Error Handling**: Responds with a 401 status code if the token is missing or invalid.

### Authentication Routes

Define routes for login, logout, and token refresh operations.

```typescript
// routes/auth.routes.ts
import express from 'express';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcrypt';
import { JWTUtil } from '../utils/jwt.utils';

const router = express.Router();
const prisma = new PrismaClient();

// Login
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      return res.status(401).json({
        success: false,
        error: 'Invalid credentials'
      });
    }

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({
        success: false,
        error: 'Invalid credentials'
      });
    }

    const { accessToken, refreshToken } = JWTUtil.generateTokens({
      userId: user.id,
      email: user.email,
      role: user.role
    });

    // Set refresh token in HTTP-only cookie
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });

    res.json({
      success: true,
      data: {
        accessToken,
        user: {
          id: user.id,
          email: user.email,
          role: user.role
        }
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Login failed'
    });
  }
});

// Logout
router.post('/logout', (req, res) => {
  res.clearCookie('refreshToken');
  res.json({
    success: true,
    message: 'Logged out successfully'
  });
});

// Get current user
router.get('/me', authMiddleware, async (req, res) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.user!.userId },
      select: {
        id: true,
        email: true,
        role: true,
        profile: true
      }
    });

    res.json({
      success: true,
      data: user
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to fetch user'
    });
  }
});

// Refresh token
router.post('/refresh', async (req, res) => {
  try {
    const refreshToken = req.cookies.refreshToken;
    if (!refreshToken) {
      throw new Error('No refresh token');
    }

    const decoded = JWTUtil.verifyRefreshToken(refreshToken);
    const { accessToken, refreshToken: newRefreshToken } = JWTUtil.generateTokens({
      userId: decoded.userId,
      email: decoded.email,
      role: decoded.role
    });

    res.cookie('refreshToken', newRefreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    res.json({
      success: true,
      data: { accessToken }
    });
  } catch (error) {
    res.status(401).json({
      success: false,
      error: 'Invalid refresh token'
    });
  }
});

export default router;
```

**Explanation:**
- **Login Route**: Authenticates the user, generates tokens, and sets the refresh token in an HTTP-only cookie.
- **Logout Route**: Clears the refresh token cookie to log the user out.
- **Get Current User Route**: Retrieves the authenticated user's information.
- **Refresh Token Route**: Verifies the refresh token and issues a new access token.

**Best Practices:**
- **HTTP-Only Cookies**: Store refresh tokens in HTTP-only cookies to prevent access from JavaScript.
- **Secure Cookies**: Use secure cookies in production to ensure they are only sent over HTTPS.
- **Error Handling**: Provide clear error messages for authentication failures.

---

## Next.js Implementation

Next.js offers a powerful API routing system with built-in support for serverless functions.

### Authentication Hooks

Hooks provide a convenient way to manage authentication state in Next.js applications.

```typescript
// hooks/useAuth.ts
import { create } from 'zustand';
import { persist } from 'zustand/middleware';

interface AuthState {
  user: any | null;
  accessToken: string | null;
  setAuth: (user: any, accessToken: string) => void;
  clearAuth: () => void;
}

const useAuth = create<AuthState>()(
  persist(
    (set) => ({
      user: null,
      accessToken: null,
      setAuth: (user, accessToken) => set({ user, accessToken }),
      clearAuth: () => set({ user: null, accessToken: null })
    }),
    {
      name: 'auth-storage'
    }
  )
);

export const useAuthCheck = () => {
  const { user, accessToken } = useAuth();
  return { isAuthenticated: !!user && !!accessToken, user, accessToken };
};

export const useLogin = () => {
  const setAuth = useAuth((state) => state.setAuth);

  const login = async (email: string, password: string) => {
    const response = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });

    if (!response.ok) {
      throw new Error('Login failed');
    }

    const { data } = await response.json();
    setAuth(data.user, data.accessToken);
    return data;
  };

  return login;
};

export const useLogout = () => {
  const clearAuth = useAuth((state) => state.clearAuth);

  const logout = async () => {
    await fetch('/api/auth/logout', { method: 'POST' });
    clearAuth();
  };

  return logout;
};
```

**Explanation:**
- **useAuth Hook**: Manages authentication state using Zustand with persistence.
- **useAuthCheck Hook**: Provides a convenient way to check if the user is authenticated.
- **useLogin Hook**: Handles the login process and updates the authentication state.
- **useLogout Hook**: Handles the logout process and clears the authentication state.

### Authentication API Routes

Define API routes for login, logout, and token refresh operations.

```typescript
// app/api/auth/login/route.ts
import { NextResponse } from 'next/server';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcrypt';
import { JWTUtil } from '@/utils/jwt.utils';

const prisma = new PrismaClient();

export async function POST(request: Request) {
  try {
    const { email, password } = await request.json();

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      return NextResponse.json(
        { success: false, error: 'Invalid credentials' },
        { status: 401 }
      );
    }

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return NextResponse.json(
        { success: false, error: 'Invalid credentials' },
        { status: 401 }
      );
    }

    const { accessToken, refreshToken } = JWTUtil.generateTokens({
      userId: user.id,
      email: user.email,
      role: user.role
    });

    const response = NextResponse.json({
      success: true,
      data: {
        accessToken,
        user: {
          id: user.id,
          email: user.email,
          role: user.role
        }
      }
    });

    response.cookies.set('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 // 7 days
    });

    return response;
  } catch (error) {
    return NextResponse.json(
      { success: false, error: 'Login failed' },
      { status: 500 }
    );
  }
}

// app/api/auth/me/route.ts
export async function GET(request: Request) {
  try {
    const token = request.headers.get('authorization')?.split(' ')[1];
    if (!token) {
      return NextResponse.json(
        { success: false, error: 'Unauthorized' },
        { status: 401 }
      );
    }

    const decoded = JWTUtil.verifyToken(token);
    const user = await prisma.user.findUnique({
      where: { id: decoded.userId },
      select: {
        id: true,
        email: true,
        role: true,
        profile: true
      }
    });

    return NextResponse.json({ success: true, data: user });
  } catch (error) {
    return NextResponse.json(
      { success: false, error: 'Failed to fetch user' },
      { status: 401 }
    );
  }
}
```

**Explanation:**
- **Login Route**: Authenticates the user, generates tokens, and sets the refresh token in an HTTP-only cookie.
- **Get Current User Route**: Retrieves the authenticated user's information.

### Protected Route Component

A component to protect routes and redirect unauthenticated users.

```typescript
// components/ProtectedRoute.tsx
'use client';

import { useRouter } from 'next/navigation';
import { useAuthCheck } from '@/hooks/useAuth';

export function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const { isAuthenticated } = useAuthCheck();

  if (!isAuthenticated) {
    router.push('/login');
    return null;
  }

  return <>{children}</>;
}
```

**Explanation:**
- **ProtectedRoute Component**: Checks if the user is authenticated and redirects to the login page if not.

**Best Practices:**
- **Client-Side Protection**: Use client-side protection to prevent unauthorized access to protected routes.
- **Redirect Unauthenticated Users**: Redirect unauthenticated users to the login page.

---

## Nest.js Implementation

Nest.js is a progressive Node.js framework that provides a robust set of features for building scalable server-side applications.

### Auth Module

The auth module encapsulates authentication logic, including JWT strategy and guards.

```typescript
// auth/auth.module.ts
import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtStrategy } from './jwt.strategy';

@Module({
  imports: [
    PassportModule,
    JwtModule.register({
      secret: process.env.JWT_SECRET,
      signOptions: { expiresIn: '15m' },
    }),
  ],
  controllers: [AuthController],
  providers: [AuthService, JwtStrategy],
})
export class AuthModule {}

// auth/auth.service.ts
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../prisma/prisma.service';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
  constructor(
    private jwtService: JwtService,
    private prisma: PrismaService,
  ) {}

  async validateUser(email: string, password: string) {
    const user = await this.prisma.user.findUnique({ where: { email } });
    if (user && (await bcrypt.compare(password, user.password))) {
      const { password, ...result } = user;
      return result;
    }
    return null;
  }

  async login(user: any) {
    const payload = { userId: user.id, email: user.email, role: user.role };
    return {
      accessToken: this.jwtService.sign(payload),
      refreshToken: this.jwtService.sign(payload, { expiresIn: '7d' }),
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
      },
    };
  }

  async refreshToken(refreshToken: string) {
    try {
      const decoded = this.jwtService.verify(refreshToken);
      const { accessToken, refreshToken: newRefreshToken } = await this.login(decoded);
      return { accessToken, refreshToken: newRefreshToken };
    } catch {
      throw new UnauthorizedException('Invalid refresh token');
    }
  }
}

// auth/auth.controller.ts
import {
  Controller,
  Post,
  Get,
  Body,
  UseGuards,
  Req,
  Res,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { JwtAuthGuard } from './jwt-auth.guard';
import { Response } from 'express';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('login')
  async login(
    @Body() loginDto: { email: string; password: string },
    @Res({ passthrough: true }) response: Response,
  ) {
    const user = await this.authService.validateUser(
      loginDto.email,
      loginDto.password,
    );
    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const { accessToken, refreshToken, user: userData } = await this.authService.login(user);

    response.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return {
      success: true,
      data: {
        accessToken,
        user: userData,
      },
    };
  }

  @UseGuards(JwtAuthGuard)
  @Get('me')
  async getProfile(@Req() req) {
    const user = await this.prisma.user.findUnique({
      where: { id: req.user.userId },
      select: {
        id: true,
        email: true,
        role: true,
        profile: true,
      },
    });
    return { success: true, data: user };
  }

  @Post('logout')
  logout(@Res({ passthrough: true }) response: Response) {
    response.clearCookie('refreshToken');
    return { success: true, message: 'Logged out successfully' };
  }

    @Post('refresh')
    async refresh(
      @Req() req,
      @Res({ passthrough: true }) response: Response,
    ) {
      const refreshToken = req.cookies.refreshToken;
      if (!refreshToken) {
        throw new UnauthorizedException('No refresh token');
      }

      const { accessToken, refreshToken: newRefreshToken } = 
        await this.authService.refreshToken(refreshToken);

      response.cookie('refreshToken', newRefreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000,
      });

      return {
        success: true,
        data: { accessToken },
      };
    }
}

// auth/jwt.strategy.ts
import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor() {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: process.env.JWT_SECRET,
    });
  }

  async validate(payload: any) {
    return {
      userId: payload.userId,
      email: payload.email,
      role: payload.role,
    };
  }
}

// auth/jwt-auth.guard.ts
import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {}
```

**Explanation:**
- **Auth Module**: Encapsulates authentication logic, including JWT strategy and guards.
- **AuthService**: Provides methods for validating users, generating tokens, and refreshing tokens.
- **AuthController**: Defines routes for login, logout, and token refresh operations.
- **JwtStrategy**: Configures the JWT strategy for Passport.js.
- **JwtAuthGuard**: Protects routes by verifying JWTs.

**Best Practices:**
- **Modular Design**: Organize authentication logic into a dedicated module for maintainability.
- **Use Guards**: Use guards to protect routes and ensure only authenticated users can access them.
- **Error Handling**: Provide clear error messages for authentication failures.

---

## Security Best Practices

### 1. Token Storage

Store tokens securely to prevent unauthorized access.

```typescript
// Safe token storage in browser
const safeTokenStorage = {
  setToken: (token: string) => {
    // Store in memory
    if (typeof window !== 'undefined') {
      (window as any).authToken = token;
    }
  },
  
  getToken: (): string | null => {
    // Retrieve from memory
    if (typeof window !== 'undefined') {
      return (window as any).authToken || null;
    }
    return null;
  },
  
  clearToken: () => {
    // Clear from memory
    if (typeof window !== 'undefined') {
      delete (window as any).authToken;
    }
  }
};
```

**Best Practices:**
- **Avoid Local Storage**: Avoid storing tokens in local storage to prevent XSS attacks.
- **Use HTTP-Only Cookies**: Store refresh tokens in HTTP-only cookies to prevent access from JavaScript.

### 2. Token Refresh Strategy

Implement a token refresh strategy to maintain session validity.

```typescript
// utils/token-refresh.ts
class TokenRefreshManager {
  private refreshPromise: Promise<string> | null = null;
  private readonly minValidityDuration = 30; // seconds

  async getValidToken(): Promise<string> {
    const currentToken = safeTokenStorage.getToken();
    if (!currentToken) {
      throw new Error('No token available');
    }

    try {
      const decoded = JWTUtil.decode(currentToken);
      const expiresIn = decoded.exp - (Date.now() / 1000);

      if (expiresIn > this.minValidityDuration) {
        return currentToken;
      }

      return this.refreshToken();
    } catch {
      return this.refreshToken();
    }
  }

  private async refreshToken(): Promise<string> {
    if (!this.refreshPromise) {
      this.refreshPromise = (async () => {
        try {
          const response = await fetch('/api/auth/refresh', {
            method: 'POST',
            credentials: 'include'
          });

          if (!response.ok) {
            throw new Error('Token refresh failed');
          }

          const { data } = await response.json();
          safeTokenStorage.setToken(data.accessToken);
          return data.accessToken;
        } finally {
          this.refreshPromise = null;
        }
      })();
    }

    return this.refreshPromise;
  }
}
```

**Best Practices:**
- **Short Expiration Times**: Use short expiration times for access tokens to limit exposure in case of compromise.
- **Automatic Refresh**: Implement automatic token refresh to maintain session validity.

### 3. Request Interceptor

Use a request interceptor to attach tokens to outgoing requests.

```typescript
// utils/api-client.ts
class APIClient {
  private tokenManager = new TokenRefreshManager();

  async request(url: string, options: RequestInit = {}) {
    try {
      const token = await this.tokenManager.getValidToken();
      
      const response = await fetch(url, {
        ...options,
        headers: {
          ...options.headers,
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (!response.ok) {
        throw new Error('Request failed');
      }

      return response.json();
    } catch (error) {
      if (error.message === 'No token available') {
        // Redirect to login
        window.location.href = '/login';
      }
      throw error;
    }
  }
}
```

**Best Practices:**
- **Attach Tokens**: Automatically attach tokens to outgoing requests to ensure authenticated access.
- **Handle Expired Tokens**: Handle expired tokens by redirecting to the login page.

### 4. CSRF Protection

Implement CSRF protection to prevent cross-site request forgery attacks.

```typescript
// middleware/csrf.middleware.ts
import { Request, Response, NextFunction } from 'express';
import csrf from 'csurf';

export const csrfProtection = csrf({
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict'
  }
});

export const csrfErrorHandler = (
  err: any,
  req: Request,
  res: Response,
  next: NextFunction
) => {
  if (err.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({
      success: false,
      error: 'Invalid CSRF token'
    });
  }
  next(err);
};
```

**Best Practices:**
- **Use CSRF Tokens**: Use CSRF tokens to protect against cross-site request forgery attacks.
- **Secure Cookies**: Use secure cookies to store CSRF tokens in production.

### 5. Rate Limiting

Implement rate limiting to prevent abuse and ensure fair usage.

```typescript
// middleware/rate-limit.middleware.ts
import rateLimit from 'express-rate-limit';

export const authRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts
  message: {
    success: false,
    error: 'Too many login attempts, please try again later'
  }
});
```

**Best Practices:**
- **Limit Login Attempts**: Limit the number of login attempts to prevent brute force attacks.
- **Monitor Usage**: Monitor rate limiting to identify potential abuse and adjust limits as needed.

### 6. Password Hashing

Use secure password hashing to protect user passwords.

```typescript
// utils/password.utils.ts
import * as bcrypt from 'bcrypt';

export class PasswordUtil {
  private static SALT_ROUNDS = 12;

  static async hash(password: string): Promise<string> {
    return bcrypt.hash(password, this.SALT_ROUNDS);
  }

  static async verify(
    password: string,
    hash: string
  ): Promise<boolean> {
    return bcrypt.compare(password, hash);
  }
}
```

**Best Practices:**
- **Use Strong Hashing Algorithms**: Use strong hashing algorithms like bcrypt to hash passwords.
- **Use Salt**: Use a salt to enhance the security of hashed passwords.

### 7. User Session Management

Manage user sessions to ensure secure and efficient session handling.

```typescript
// utils/session.utils.ts
class SessionManager {
  private static readonly SESSION_DURATION = 30 * 60 * 1000; // 30 minutes
  private static sessions = new Map<string, number>();

  static startSession(userId: string): void {
    this.sessions.set(userId, Date.now());
  }

  static validateSession(userId: string): boolean {
    const sessionStart = this.sessions.get(userId);
    if (!sessionStart) return false;

    const isValid = Date.now() - sessionStart < this.SESSION_DURATION;
    if (!isValid) {
      this.sessions.delete(userId);
    }
    return isValid;
  }

  static endSession(userId: string): void {
    this.sessions.delete(userId);
  }
}
```

**Best Practices:**
- **Session Expiration**: Implement session expiration to limit session duration.
- **Session Validation**: Validate sessions to ensure they are still valid.

### 8. Security Headers

Use security headers to protect against common vulnerabilities.

```typescript
// middleware/security-headers.middleware.ts
export const securityHeaders = {
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
  'X-Frame-Options': 'DENY',
  'X-Content-Type-Options': 'nosniff',
  'X-XSS-Protection': '1; mode=block',
  'Content-Security-Policy': "default-src 'self'",
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()'
};

export const applySecurityHeaders = (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  Object.entries(securityHeaders).forEach(([header, value]) => {
    res.setHeader(header, value);
  });
  next();
};
```

**Best Practices:**
- **Use Security Headers**: Use security headers to protect against common vulnerabilities like XSS and clickjacking.
- **Monitor Security**: Monitor security headers to ensure they are correctly configured.

### 9. Audit Logging

Implement audit logging to track authentication events and monitor for suspicious activities.

```typescript
// utils/audit-logger.ts
interface AuditLog {
  userId: string;
  action: string;
  timestamp: Date;
  ip: string;
  userAgent: string;
  success: boolean;
  details?: any;
}

class AuditLogger {
  static async log(log: AuditLog): Promise<void> {
    // Save to database or logging service
    await prisma.auditLog.create({
      data: {
        userId: log.userId,
        action: log.action,
        timestamp: log.timestamp,
        ip: log.ip,
        userAgent: log.userAgent,
        success: log.success,
        details: log.details
      }
    });
  }

  static async getAuthenticationLogs(
    userId: string
  ): Promise<AuditLog[]> {
    return prisma.auditLog.findMany({
      where: {
        userId,
        action: {
          in: ['LOGIN', 'LOGOUT', 'TOKEN_REFRESH']
        }
      },
      orderBy: {
        timestamp: 'desc'
      }
    });
  }
}
```

**Best Practices:**
- **Track Authentication Events**: Track authentication events to monitor for suspicious activities.
- **Use Audit Logs**: Use audit logs to track changes and monitor for suspicious activities.

### 10. Token Blacklisting

Implement token blacklisting to invalidate tokens and prevent unauthorized access.

```typescript
// utils/token-blacklist.ts
class TokenBlacklist {
  private static readonly redis = new Redis();
  private static readonly PREFIX = 'blacklist:';

  static async blacklist(
    token: string,
    expiresIn: number
  ): Promise<void> {
    const key = `${this.PREFIX}${token}`;
    await this.redis.set(key, '1', 'EX', expiresIn);
  }

  static async isBlacklisted(token: string): Promise<boolean> {
    const key = `${this.PREFIX}${token}`;
    return (await this.redis.exists(key)) === 1;
  }
}
```

**Best Practices:**
- **Blacklist Tokens**: Blacklist tokens to invalidate them and prevent unauthorized access.
- **Monitor Blacklist**: Monitor the blacklist to ensure it is correctly configured.

---

## Conclusion

Implementing JWT authentication involves a combination of token generation, verification, and best practices. By following the patterns and best practices outlined in this guide, you can build secure and efficient authentication systems using **Express.js**, **Next.js**, and **Nest.js** frameworks.

---

## Additional Resources

- [Express.js Documentation](https://expressjs.com/)
- [Next.js Documentation](https://nextjs.org/docs)
- [Nest.js Documentation](https://docs.nestjs.com/)
- [JWT.io](https://jwt.io/)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

Feel free to reach out if you need further assistance or have questions regarding JWT authentication!