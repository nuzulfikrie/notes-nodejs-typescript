## docs/authentication/passport.md
# Passport.js Authentication Guide

A comprehensive guide for implementing Passport.js authentication strategies across **Express.js**, **Next.js**, and **Nest.js** frameworks. This guide includes best practices, code examples, and strategies to ensure secure and efficient authentication.

## Table of Contents
- [Introduction](#introduction)
- [Basic Setup](#basic-setup)
  - [Installation](#installation)
  - [Passport Configuration](#passport-configuration)
- [Local Strategy](#local-strategy)
  - [Basic Local Strategy Setup](#basic-local-strategy-setup)
  - [Extended Local Strategy with Rate Limiting](#extended-local-strategy-with-rate-limiting)
- [JWT Strategy](#jwt-strategy)
  - [JWT Strategy Implementation](#jwt-strategy-implementation)
- [Express.js Implementation](#expressjs-implementation)
  - [Authentication Routes](#authentication-routes)
  - [Authentication Middleware](#authentication-middleware)
- [Next.js Implementation](#nextjs-implementation)
  - [Passport Middleware](#passport-middleware)
- [Nest.js Implementation](#nestjs-implementation)
  - [Passport Module](#passport-module)
- [Custom Strategies](#custom-strategies)
  - [API Key Strategy](#api-key-strategy)
  - [Two-Factor Authentication Strategy](#two-factor-authentication-strategy)
- [Security Best Practices](#security-best-practices)
  - [Session Security](#session-security)
  - [Authentication Logging](#authentication-logging)
- [Conclusion](#conclusion)

## Introduction

Passport.js is a popular authentication middleware for Node.js, providing a simple and flexible way to implement various authentication strategies. This guide explores different Passport.js strategies, including local, JWT, and custom strategies, and demonstrates their implementation in **Express.js**, **Next.js**, and **Nest.js**.

---

## Basic Setup

### Installation

Install Passport.js and related packages for authentication.

```bash
npm install passport passport-local passport-jwt passport-google-oauth20 passport-github2 bcrypt
```

**Explanation:**
- **passport**: Core Passport.js library for authentication.
- **passport-local**: Strategy for authenticating with a username and password.
- **passport-jwt**: Strategy for authenticating with JSON Web Tokens.
- **passport-google-oauth20**: Strategy for authenticating with Google OAuth 2.0.
- **passport-github2**: Strategy for authenticating with GitHub OAuth 2.0.
- **bcrypt**: Library for hashing passwords securely.

### Passport Configuration

Configure Passport.js with serialization and deserialization logic.

```typescript
// config/passport.config.ts
import passport from 'passport';
import { PrismaClient } from '@prisma/client';
import { Strategy as LocalStrategy } from 'passport-local';
import { Strategy as JwtStrategy, ExtractJwt } from 'passport-jwt';
import * as bcrypt from 'bcrypt';

const prisma = new PrismaClient();

// Passport serialization
passport.serializeUser((user: any, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id: string, done) => {
  try {
    const user = await prisma.user.findUnique({ where: { id } });
    done(null, user);
  } catch (error) {
    done(error);
  }
});
```

**Explanation:**
- **serializeUser**: Defines how user information is stored in the session.
- **deserializeUser**: Defines how user information is retrieved from the session.

**Best Practices:**
- **Secure Password Storage**: Use bcrypt to hash passwords securely.
- **Error Handling**: Implement error handling for serialization and deserialization processes.

---

## Local Strategy

### Basic Local Strategy Setup

Implement a basic local strategy for authenticating with a username and password.

```typescript
// strategies/local.strategy.ts
const localStrategy = new LocalStrategy(
  {
    usernameField: 'email',
    passwordField: 'password',
  },
  async (email: string, password: string, done) => {
    try {
      const user = await prisma.user.findUnique({ 
        where: { email }
      });

      if (!user) {
        return done(null, false, { 
          message: 'Invalid credentials' 
        });
      }

      const isValidPassword = await bcrypt.compare(
        password, 
        user.password
      );

      if (!isValidPassword) {
        return done(null, false, { 
          message: 'Invalid credentials' 
        });
      }

      return done(null, user);
    } catch (error) {
      return done(error);
    }
  }
);

passport.use(localStrategy);
```

**Explanation:**
- **LocalStrategy**: Configures the local strategy for authenticating with a username and password.
- **Password Verification**: Uses bcrypt to verify the provided password against the stored hash.

**Best Practices:**
- **Error Handling**: Provide clear error messages for authentication failures.
- **Secure Password Storage**: Use bcrypt to hash passwords securely.

### Extended Local Strategy with Rate Limiting

Enhance the local strategy with rate limiting to prevent brute force attacks.

```typescript
// strategies/local-extended.strategy.ts
import { RateLimiter } from '../utils/rate-limiter';

interface LoginAttempt {
  email: string;
  timestamp: number;
  success: boolean;
}

class LoginRateLimiter {
  private attempts = new Map<string, LoginAttempt[]>();
  private readonly maxAttempts = 5;
  private readonly windowMs = 15 * 60 * 1000; // 15 minutes

  isAllowed(email: string): boolean {
    const now = Date.now();
    const attempts = this.attempts.get(email) || [];
    const recentAttempts = attempts.filter(
      attempt => now - attempt.timestamp < this.windowMs
    );

    this.attempts.set(email, recentAttempts);
    return recentAttempts.length < this.maxAttempts;
  }

  recordAttempt(email: string, success: boolean): void {
    const attempts = this.attempts.get(email) || [];
    attempts.push({ email, timestamp: Date.now(), success });
    this.attempts.set(email, attempts);
  }
}

const loginRateLimiter = new LoginRateLimiter();

const localStrategyExtended = new LocalStrategy(
  {
    usernameField: 'email',
    passwordField: 'password',
    passReqToCallback: true,
  },
  async (req, email, password, done) => {
    try {
      if (!loginRateLimiter.isAllowed(email)) {
        return done(null, false, { 
          message: 'Too many login attempts' 
        });
      }

      const user = await prisma.user.findUnique({ 
        where: { email } 
      });

      if (!user) {
        loginRateLimiter.recordAttempt(email, false);
        return done(null, false, { 
          message: 'Invalid credentials' 
        });
      }

      const isValidPassword = await bcrypt.compare(
        password, 
        user.password
      );

      if (!isValidPassword) {
        loginRateLimiter.recordAttempt(email, false);
        return done(null, false, { 
          message: 'Invalid credentials' 
        });
      }

      loginRateLimiter.recordAttempt(email, true);
      return done(null, user);
    } catch (error) {
      return done(error);
    }
  }
);
```

**Explanation:**
- **LoginRateLimiter**: Implements rate limiting to prevent brute force attacks by tracking login attempts.
- **localStrategyExtended**: Enhances the local strategy with rate limiting logic.

**Best Practices:**
- **Rate Limiting**: Implement rate limiting to prevent brute force attacks.
- **Clear Error Messages**: Provide clear error messages for rate limiting violations.

---

## JWT Strategy

### JWT Strategy Implementation

Implement a JWT strategy for authenticating with JSON Web Tokens.

```typescript
// strategies/jwt.strategy.ts
const jwtStrategy = new JwtStrategy(
  {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: process.env.JWT_SECRET,
    ignoreExpiration: false,
  },
  async (payload: any, done) => {
    try {
      const user = await prisma.user.findUnique({
        where: { id: payload.userId }
      });

      if (!user) {
        return done(null, false);
      }

      return done(null, user);
    } catch (error) {
      return done(error);
    }
  }
);

passport.use('jwt', jwtStrategy);
```

**Explanation:**
- **JwtStrategy**: Configures the JWT strategy for authenticating with JSON Web Tokens.
- **Token Verification**: Verifies the JWT and retrieves the associated user.

**Best Practices:**
- **Secure Token Storage**: Store JWTs securely to prevent unauthorized access.
- **Error Handling**: Provide clear error messages for token verification failures.

---

## Express.js Implementation

### Authentication Routes

Define routes for login and protected resources using Passport.js.

```typescript
// routes/auth.routes.ts
import express from 'express';
import passport from 'passport';
import { generateTokens } from '../utils/jwt';

const router = express.Router();

router.post('/login', (req, res, next) => {
  passport.authenticate('local', { session: false }, 
    (err, user, info) => {
      if (err) {
        return next(err);
      }

      if (!user) {
        return res.status(401).json({ 
          success: false, 
          message: info.message 
        });
      }

      const { accessToken, refreshToken } = generateTokens(user);

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
            name: user.name
          }
        }
      });
    }
  )(req, res, next);
});

router.get(
  '/protected',
  passport.authenticate('jwt', { session: false }),
  (req, res) => {
    res.json({
      success: true,
      data: {
        user: req.user
      }
    });
  }
);
```

**Explanation:**
- **Login Route**: Authenticates the user using the local strategy and issues JWT tokens.
- **Protected Route**: Protects resources using the JWT strategy.

**Best Practices:**
- **Secure Cookies**: Use secure cookies in production to ensure they are only sent over HTTPS.
- **Error Handling**: Provide clear error messages for authentication failures.

### Authentication Middleware

Implement middleware for authenticating requests using Passport.js.

```typescript
// middleware/auth.middleware.ts
import passport from 'passport';

export const authenticateJWT = (req, res, next) => {
  passport.authenticate('jwt', { session: false }, (err, user) => {
    if (err) {
      return next(err);
    }

    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Unauthorized'
      });
    }

    req.user = user;
    next();
  })(req, res, next);
};

export const requireRoles = (...roles: string[]) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: 'Unauthorized'
      });
    }

    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        message: 'Forbidden'
      });
    }

    next();
  };
};
```

**Explanation:**
- **authenticateJWT**: Middleware for authenticating requests using the JWT strategy.
- **requireRoles**: Middleware for enforcing role-based access control.

**Best Practices:**
- **Role-Based Access Control**: Implement role-based access control to restrict access to resources.
- **Error Handling**: Provide clear error messages for unauthorized access.

---

## Next.js Implementation

### Passport Middleware

Implement middleware for using Passport.js in Next.js API routes.

```typescript
// middleware/passport.ts
import { NextApiRequest, NextApiResponse } from 'next';
import passport from 'passport';
import { promisify } from 'util';

export const authenticatePassport = async (
  req: NextApiRequest,
  res: NextApiResponse,
  strategy: string
) => {
  const authenticate = promisify(
    passport.authenticate(strategy, { session: false })
  );
  
  try {
    const user = await authenticate(req, res);
    return user;
  } catch (error) {
    throw error;
  }
};

// pages/api/auth/[...nextauth].ts
import { NextApiHandler } from 'next';
import NextAuth from 'next-auth';
import CredentialsProvider from 'next-auth/providers/credentials';
import { authenticatePassport } from '../../../middleware/passport';

const authHandler: NextApiHandler = (req, res) => 
  NextAuth(req, res, {
    providers: [
      CredentialsProvider({
        name: 'Credentials',
        credentials: {
          email: { label: 'Email', type: 'email' },
          password: { label: 'Password', type: 'password' }
        },
        async authorize(credentials) {
          try {
            const user = await authenticatePassport(
              req,
              res,
              'local'
            );
            return user;
          } catch (error) {
            return null;
          }
        }
      })
    ],
    callbacks: {
      async jwt({ token, user }) {
        if (user) {
          token.userId = user.id;
          token.role = user.role;
        }
        return token;
      },
      async session({ session, token }) {
        if (token) {
          session.user.id = token.userId;
          session.user.role = token.role;
        }
        return session;
      }
    }
  });

export default authHandler;
```

**Explanation:**
- **authenticatePassport**: Middleware for authenticating requests using Passport.js in Next.js API routes.
- **NextAuth**: Integrates Passport.js with NextAuth.js for handling authentication in Next.js.

**Best Practices:**
- **Secure Token Storage**: Store tokens securely to prevent unauthorized access.
- **Error Handling**: Provide clear error messages for authentication failures.

---

## Nest.js Implementation

### Passport Module

Implement a Passport module for handling authentication in Nest.js.

```typescript
// auth/passport/passport.module.ts
import { Module } from '@nestjs/common';
import { PassportModule as NestPassportModule } from '@nestjs/passport';
import { LocalStrategy } from './local.strategy';
import { JwtStrategy } from './jwt.strategy';
import { AuthService } from '../auth.service';

@Module({
  imports: [
    NestPassportModule.register({ defaultStrategy: 'jwt' })
  ],
  providers: [LocalStrategy, JwtStrategy, AuthService],
  exports: [NestPassportModule]
})
export class PassportModule {}

// auth/passport/local.strategy.ts
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-local';
import { AuthService } from '../auth.service';

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy) {
  constructor(private authService: AuthService) {
    super({
      usernameField: 'email',
      passwordField: 'password',
    });
  }

  async validate(email: string, password: string) {
    const user = await this.authService.validateUser(email, password);
    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }
    return user;
  }
}

// auth/auth.controller.ts
import { Controller, Post, UseGuards, Req } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { AuthService } from './auth.service';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('login')
  @UseGuards(AuthGuard('local'))
  async login(@Req() req) {
    return this.authService.login(req.user);
  }

  @UseGuards(AuthGuard('jwt'))
  @Get('profile')
  async getProfile(@Req() req) {
    return req.user;
  }
}
```

**Explanation:**
- **PassportModule**: Encapsulates authentication logic, including strategies and controllers.
- **LocalStrategy**: Configures the local strategy for authenticating with a username and password.
- **AuthController**: Defines routes for login and protected resources.

**Best Practices:**
- **Modular Design**: Organize authentication logic into a dedicated module for maintainability.
- **Use Guards**: Use guards to protect routes and ensure only authenticated users can access them.
- **Error Handling**: Provide clear error messages for authentication failures.

---

## Custom Strategies

### API Key Strategy

Implement a custom strategy for authenticating with API keys.

```typescript
// strategies/apikey.strategy.ts
import { Strategy } from 'passport-custom';

const apiKeyStrategy = new Strategy(
  async (req, done) => {
    try {
      const apiKey = req.headers['x-api-key'];
      
      if (!apiKey) {
        return done(null, false);
      }

      const apiKeyRecord = await prisma.apiKey.findUnique({
        where: { key: apiKey },
        include: { user: true }
      });

      if (!apiKeyRecord || !apiKeyRecord.isActive) {
        return done(null, false);
      }

      return done(null, apiKeyRecord.user);
    } catch (error) {
      return done(error);
    }
  }
);

passport.use('apikey', apiKeyStrategy);
```

**Explanation:**
- **apiKeyStrategy**: Custom strategy for authenticating with API keys.
- **API Key Verification**: Verifies the API key and retrieves the associated user.

**Best Practices:**
- **Secure API Keys**: Store API keys securely to prevent unauthorized access.
- **Error Handling**: Provide clear error messages for API key verification failures.

### Two-Factor Authentication Strategy

Implement a custom strategy for two-factor authentication.

```typescript
// strategies/2fa.strategy.ts
import { Strategy } from 'passport-custom';
import { verifyTOTP } from '../utils/totp';

const twoFactorStrategy = new Strategy(
  async (req, done) => {
    try {
      const { userId, code } = req.body;

      const user = await prisma.user.findUnique({
        where: { id: userId },
        include: { twoFactorSecret: true }
      });

      if (!user || !user.twoFactorSecret) {
        return done(null, false);
      }

      const isValidCode = verifyTOTP(
        code, 
        user.twoFactorSecret.secret
      );

      if (!isValidCode) {
        return done(null, false);
      }

      return done(null, user);
    } catch (error) {
      return done(error);
    }
  }
);

passport.use('2fa', twoFactorStrategy);
```

**Explanation:**
- **twoFactorStrategy**: Custom strategy for two-factor authentication using TOTP.
- **TOTP Verification**: Verifies the TOTP code and retrieves the associated user.

**Best Practices:**
- **Two-Factor Authentication**: Implement two-factor authentication to enhance security.
- **Error Handling**: Provide clear error messages for TOTP verification failures.

---

## Security Best Practices

### Session Security

Configure secure session settings to protect user sessions.

```typescript
const sessionConfig = {
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    sameSite: 'strict'
  },
  store: new RedisStore({
    client: redisClient,
    prefix: 'session:'
  })
};
```

**Best Practices:**
- **Secure Cookies**: Use secure cookies in production to ensure they are only sent over HTTPS.
- **Session Expiration**: Implement session expiration to limit session duration.

### Authentication Logging

Log authentication attempts to monitor for suspicious activities.

```typescript
const logAuthenticationAttempt = async (
  userId: string,
  success: boolean,
  strategy: string,
  metadata: any
) => {
  await prisma.authenticationLog.create({
    data: {
      userId,
      success,
      strategy,
      metadata,
      timestamp: new Date(),
      ipAddress: metadata.ip,
      userAgent: metadata.userAgent
    }
  });
};
```

**Best Practices:**
- **Track Authentication Events**: Track authentication events to monitor for suspicious activities.
- **Use Audit Logs**: Use audit logs to track changes and monitor for suspicious activities.

---

## Conclusion

Implementing Passport.js authentication involves a combination of strategy configuration, secure session management, and best practices. By following the patterns and best practices outlined in this guide, you can build secure and efficient authentication systems using **Express.js**, **Next.js**, and **Nest.js** frameworks.

---

## Additional Resources

- [Passport.js Documentation](http://www.passportjs.org/docs/)
- [Express.js Documentation](https://expressjs.com/)
- [Next.js Documentation](https://nextjs.org/docs)
- [Nest.js Documentation](https://docs.nestjs.com/)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

Feel free to reach out if you need further assistance or have questions regarding Passport.js authentication!