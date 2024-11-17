## docs/authentication/oauth.md
# OAuth Authentication Guide

A comprehensive guide for implementing OAuth authentication with popular providers in **Express.js**, **Next.js**, and **Nest.js**. This guide includes best practices, code examples, and strategies to ensure secure and efficient OAuth authentication.

## Table of Contents
- [Introduction](#introduction)
- [OAuth Providers Setup](#oauth-providers-setup)
  - [Google OAuth Configuration](#google-oauth-configuration)
  - [GitHub OAuth Configuration](#github-oauth-configuration)
- [Express.js Implementation](#expressjs-implementation)
  - [OAuth Middleware and Routes](#oauth-middleware-and-routes)
- [Next.js Implementation](#nextjs-implementation)
  - [OAuth Routes and Handlers](#oauth-routes-and-handlers)
  - [OAuth Hook](#oauth-hook)
- [Nest.js Implementation](#nestjs-implementation)
  - [OAuth Module](#oauth-module)
- [Social Login Buttons Component](#social-login-buttons-component)
- [Error Handling](#error-handling)
  - [OAuth Error Handler](#oauth-error-handler)
- [Best Practices](#best-practices)
  - [1. State Parameter](#1-state-parameter)
  - [2. PKCE Implementation](#2-pkce-implementation)
  - [3. Token Security](#3-token-security)
  - [4. Refresh Token Rotation](#4-refresh-token-rotation)
- [Conclusion](#conclusion)

## Introduction

OAuth (Open Authorization) is an open standard for access delegation, commonly used as a way to grant websites or applications limited access to user information without exposing passwords. This guide explores various aspects of OAuth authentication, including provider setup, implementation, and best practices, using three popular TypeScript frameworks: **Express.js**, **Next.js**, and **Nest.js**.

---

## OAuth Providers Setup

### Google OAuth Configuration

Configure Google OAuth by setting up the necessary credentials and scopes.

```typescript
// config/oauth.config.ts
interface OAuthConfig {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  scopes: string[];
}

export const googleOAuthConfig: OAuthConfig = {
  clientId: process.env.GOOGLE_CLIENT_ID!,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
  redirectUri: `${process.env.APP_URL}/api/auth/google/callback`,
  scopes: [
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/userinfo.profile'
  ]
};
```

**Explanation:**
- **OAuthConfig Interface**: Defines the structure for OAuth configuration, including client ID, client secret, redirect URI, and scopes.
- **googleOAuthConfig**: Contains the configuration for Google OAuth, using environment variables for sensitive information.

### GitHub OAuth Configuration

Configure GitHub OAuth similarly to Google OAuth.

```typescript
export const githubOAuthConfig: OAuthConfig = {
  clientId: process.env.GITHUB_CLIENT_ID!,
  clientSecret: process.env.GITHUB_CLIENT_SECRET!,
  redirectUri: `${process.env.APP_URL}/api/auth/github/callback`,
  scopes: ['user:email']
};
```

**Explanation:**
- **githubOAuthConfig**: Contains the configuration for GitHub OAuth, specifying the necessary scopes for accessing user email information.

**Best Practices:**
- **Environment Variables**: Store sensitive information like client IDs and secrets in environment variables.
- **Secure Redirect URIs**: Ensure redirect URIs are secure and correctly configured to prevent unauthorized access.

---

## Express.js Implementation

Express.js provides a flexible and minimalistic framework for implementing OAuth authentication.

### OAuth Middleware and Routes

Use middleware and routes to handle OAuth authentication with providers.

```typescript
// middleware/oauth.middleware.ts
import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { Strategy as GitHubStrategy } from 'passport-github2';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

passport.use(
  new GoogleStrategy(
    {
      clientID: googleOAuthConfig.clientId,
      clientSecret: googleOAuthConfig.clientSecret,
      callbackURL: googleOAuthConfig.redirectUri,
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        let user = await prisma.user.findUnique({
          where: {
            email: profile.emails![0].value
          }
        });

        if (!user) {
          user = await prisma.user.create({
            data: {
              email: profile.emails![0].value,
              name: profile.displayName,
              provider: 'google',
              providerId: profile.id,
              avatar: profile.photos?.[0].value
            }
          });
        }

        return done(null, user);
      } catch (error) {
        return done(error as Error);
      }
    }
  )
);

// routes/oauth.routes.ts
import express from 'express';
import passport from 'passport';
import { JWTUtil } from '../utils/jwt.utils';

const router = express.Router();

// Google OAuth routes
router.get('/google',
  passport.authenticate('google', {
    scope: googleOAuthConfig.scopes
  })
);

router.get('/google/callback',
  passport.authenticate('google', { session: false }),
  async (req, res) => {
    try {
      const user = req.user as any;
      const { accessToken, refreshToken } = JWTUtil.generateTokens({
        userId: user.id,
        email: user.email,
        role: user.role
      });

      res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
      });

      // Redirect to frontend with token
      res.redirect(
        `${process.env.FRONTEND_URL}/auth/callback?token=${accessToken}`
      );
    } catch (error) {
      res.redirect(`${process.env.FRONTEND_URL}/auth/error`);
    }
  }
);
```

**Explanation:**
- **GoogleStrategy**: Configures the Google OAuth strategy using Passport.js.
- **OAuth Routes**: Define routes for initiating OAuth authentication and handling callbacks.
- **Token Generation**: Generate JWT tokens upon successful authentication and set refresh tokens in HTTP-only cookies.

**Best Practices:**
- **Use Passport.js**: Leverage Passport.js for handling OAuth strategies and simplifying authentication logic.
- **Secure Cookies**: Use secure cookies in production to ensure they are only sent over HTTPS.
- **Error Handling**: Provide clear error handling and redirection for failed authentication attempts.

---

## Next.js Implementation

Next.js offers a powerful API routing system with built-in support for serverless functions.

### OAuth Routes and Handlers

Define API routes and handlers for OAuth authentication.

```typescript
// app/api/auth/[provider]/route.ts
import { NextResponse } from 'next/server';
import { OAuth2Client } from 'google-auth-library';
import { PrismaClient } from '@prisma/client';
import { JWTUtil } from '@/utils/jwt.utils';

const prisma = new PrismaClient();
const googleClient = new OAuth2Client(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET
);

export async function GET(
  request: Request,
  { params }: { params: { provider: string } }
) {
  const { provider } = params;
  const { searchParams } = new URL(request.url);
  const code = searchParams.get('code');

  if (!code) {
    // Generate OAuth URL and redirect to provider
    const url = generateOAuthUrl(provider);
    return NextResponse.redirect(url);
  }

  try {
    const userData = await getOAuthUserData(provider, code);
    const user = await handleOAuthUser(userData);
    const { accessToken, refreshToken } = JWTUtil.generateTokens({
      userId: user.id,
      email: user.email,
      role: user.role
    });

    const response = NextResponse.redirect(
      `${process.env.FRONTEND_URL}/auth/callback?token=${accessToken}`
    );

    response.cookies.set('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 // 7 days
    });

    return response;
  } catch (error) {
    return NextResponse.redirect(
      `${process.env.FRONTEND_URL}/auth/error`
    );
  }
}

// OAuth utility functions
function generateOAuthUrl(provider: string): string {
  switch (provider) {
    case 'google':
      return googleClient.generateAuthUrl({
        access_type: 'offline',
        scope: googleOAuthConfig.scopes
      });
    case 'github':
      const githubParams = new URLSearchParams({
        client_id: githubOAuthConfig.clientId,
        redirect_uri: githubOAuthConfig.redirectUri,
        scope: githubOAuthConfig.scopes.join(' ')
      });
      return `https://github.com/login/oauth/authorize?${githubParams}`;
    default:
      throw new Error('Unknown provider');
  }
}

async function getOAuthUserData(provider: string, code: string) {
  switch (provider) {
    case 'google':
      const { tokens } = await googleClient.getToken(code);
      const ticket = await googleClient.verifyIdToken({
        idToken: tokens.id_token!,
        audience: process.env.GOOGLE_CLIENT_ID
      });
      return ticket.getPayload();
    case 'github':
      // Implement GitHub token exchange and user data fetch
      break;
    default:
      throw new Error('Unknown provider');
  }
}

async function handleOAuthUser(userData: any) {
  let user = await prisma.user.findUnique({
    where: { email: userData.email }
  });

  if (!user) {
    user = await prisma.user.create({
      data: {
        email: userData.email,
        name: userData.name,
        provider: userData.provider,
        providerId: userData.sub,
        avatar: userData.picture
      }
    });
  }

  return user;
}
```

**Explanation:**
- **OAuth Routes**: Define routes for handling OAuth authentication and callbacks.
- **Token Generation**: Generate JWT tokens upon successful authentication and set refresh tokens in HTTP-only cookies.
- **Utility Functions**: Provide utility functions for generating OAuth URLs and handling user data.

### OAuth Hook

A hook to manage OAuth authentication state and actions.

```typescript
// hooks/useOAuth.ts
import { useState } from 'react';

export const useOAuth = () => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const signInWithProvider = async (provider: string) => {
    setLoading(true);
    setError(null);
    
    try {
      window.location.href = `/api/auth/${provider}`;
    } catch (err) {
      setError('Authentication failed');
    } finally {
      setLoading(false);
    }
  };

  return {
    signInWithProvider,
    loading,
    error
  };
};
```

**Explanation:**
- **useOAuth Hook**: Manages OAuth authentication state and provides a method to initiate authentication with a provider.

**Best Practices:**
- **Client-Side Redirection**: Use client-side redirection to initiate OAuth authentication.
- **Error Handling**: Provide clear error messages for failed authentication attempts.

---

## Nest.js Implementation

Nest.js is a progressive Node.js framework that provides a robust set of features for building scalable server-side applications.

### OAuth Module

The OAuth module encapsulates authentication logic, including strategies and controllers.

```typescript
// auth/oauth/oauth.module.ts
import { Module } from '@nestjs/common';
import { PassportModule } from '@nestjs/passport';
import { GoogleStrategy } from './google.strategy';
import { GitHubStrategy } from './github.strategy';
import { OAuthController } from './oauth.controller';
import { OAuthService } from './oauth.service';

@Module({
  imports: [PassportModule],
  controllers: [OAuthController],
  providers: [OAuthService, GoogleStrategy, GitHubStrategy]
})
export class OAuthModule {}

// auth/oauth/google.strategy.ts
import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-google-oauth20';
import { OAuthService } from './oauth.service';

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  constructor(private oauthService: OAuthService) {
    super({
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: googleOAuthConfig.redirectUri,
      scope: googleOAuthConfig.scopes
    });
  }

  async validate(
    accessToken: string,
    refreshToken: string,
    profile: any
  ) {
    const user = await this.oauthService.handleOAuthUser({
      email: profile.emails[0].value,
      name: profile.displayName,
      provider: 'google',
      providerId: profile.id,
      avatar: profile.photos?.[0].value
    });
    return user;
  }
}

// auth/oauth/oauth.controller.ts
import { Controller, Get, Req, Res, UseGuards } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { OAuthService } from './oauth.service';
import { JWTUtil } from '../../utils/jwt.utils';

@Controller('auth')
export class OAuthController {
  constructor(private oauthService: OAuthService) {}

  @Get('google')
  @UseGuards(AuthGuard('google'))
  async googleAuth() {
    // Guard redirects to Google
  }

  @Get('google/callback')
  @UseGuards(AuthGuard('google'))
  async googleAuthCallback(@Req() req, @Res() res) {
    try {
      const { accessToken, refreshToken } = JWTUtil.generateTokens({
        userId: req.user.id,
        email: req.user.email,
        role: req.user.role
      });

      res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: 7 * 24 * 60 * 60 * 1000
      });

      res.redirect(
        `${process.env.FRONTEND_URL}/auth/callback?token=${accessToken}`
      );
    } catch (error) {
      res.redirect(`${process.env.FRONTEND_URL}/auth/error`);
    }
  }
}
```

**Explanation:**
- **OAuth Module**: Encapsulates authentication logic, including strategies and controllers.
- **GoogleStrategy**: Configures the Google OAuth strategy using Passport.js.
- **OAuthController**: Defines routes for initiating OAuth authentication and handling callbacks.

**Best Practices:**
- **Modular Design**: Organize authentication logic into a dedicated module for maintainability.
- **Use Guards**: Use guards to protect routes and ensure only authenticated users can access them.
- **Error Handling**: Provide clear error handling and redirection for failed authentication attempts.

---

## Social Login Buttons Component

A component to render social login buttons for initiating OAuth authentication.

```typescript
// components/SocialLogin.tsx
import React from 'react';
import { useOAuth } from '@/hooks/useOAuth';

export const SocialLogin: React.FC = () => {
  const { signInWithProvider, loading, error } = useOAuth();

  return (
    <div className="space-y-4">
      <button
        onClick={() => signInWithProvider('google')}
        disabled={loading}
        className="w-full flex items-center justify-center gap-2 bg-white text-gray-800 border border-gray-300 rounded-lg px-4 py-2 hover:bg-gray-50"
      >
        <GoogleIcon className="w-5 h-5" />
        Continue with Google
      </button>

      <button
        onClick={() => signInWithProvider('github')}
        disabled={loading}
        className="w-full flex items-center justify-center gap-2 bg-gray-800 text-white rounded-lg px-4 py-2 hover:bg-gray-700"
      >
        <GitHubIcon className="w-5 h-5" />
        Continue with GitHub
      </button>

      {error && (
        <div className="text-red-500 text-sm text-center">
          {error}
        </div>
      )}
    </div>
  );
};
```

**Explanation:**
- **SocialLogin Component**: Renders buttons for initiating OAuth authentication with Google and GitHub.
- **useOAuth Hook**: Manages OAuth authentication state and provides a method to initiate authentication with a provider.

**Best Practices:**
- **User Experience**: Provide clear and accessible buttons for initiating OAuth authentication.
- **Error Feedback**: Display error messages to inform users of authentication failures.

---

## Error Handling

### OAuth Error Handler

Handle OAuth-specific errors to provide clear feedback to users.

```typescript
class OAuthError extends Error {
  constructor(
    public provider: string,
    public code: string,
    message: string
  ) {
    super(message);
    this.name = 'OAuthError';
  }
}

const handleOAuthError = (error: any, provider: string) => {
  if (error.code === 'access_denied') {
    return new OAuthError(
      provider,
      'ACCESS_DENIED',
      'User denied access'
    );
  }

  if (error.code === 'invalid_request') {
    return new OAuthError(
      provider,
      'INVALID_REQUEST',
      'Invalid OAuth request'
    );
  }

  return new OAuthError(
    provider,
    'UNKNOWN_ERROR',
    'Authentication failed'
  );
};
```

**Explanation:**
- **OAuthError Class**: Represents OAuth-specific errors, including provider and error code.
- **handleOAuthError Function**: Handles common OAuth errors and provides clear error messages.

**Best Practices:**
- **Consistent Error Handling**: Use a consistent error handling strategy for OAuth-specific errors.
- **Clear Error Messages**: Provide clear and actionable error messages to aid in debugging and user feedback.

---

## Best Practices

### 1. State Parameter

Use a state parameter to prevent CSRF attacks during OAuth authentication.

```typescript
const generateOAuthState = () => {
  const state = crypto.randomBytes(32).toString('hex');
  // Store state in Redis with expiration
  return state;
};

const validateOAuthState = async (state: string) => {
  // Validate state from Redis
  return true;
};
```

**Best Practices:**
- **State Parameter**: Use a state parameter to prevent CSRF attacks and ensure the integrity of OAuth requests.
- **Secure Storage**: Store state parameters securely and validate them upon callback.

### 2. PKCE Implementation

Implement PKCE (Proof Key for Code Exchange) for additional security.

```typescript
const generatePKCE = () => {
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto
    .createHash('sha256')
    .update(verifier)
    .digest('base64url');
  return { verifier, challenge };
};
```

**Best Practices:**
- **PKCE**: Use PKCE to enhance the security of OAuth authentication flows, especially for public clients.
- **Secure Code Exchange**: Ensure the code exchange process is secure and resistant to interception.

### 3. Token Security

Securely store and manage OAuth tokens to prevent unauthorized access.

```typescript
const secureTokenStorage = {
  store: async (userId: string, tokens: any) => {
    const encrypted = encrypt(JSON.stringify(tokens));
    await redis.set(`oauth:${userId}`, encrypted, 'EX', 3600 * 24 * 7);
  },
  
  retrieve: async (userId: string) => {
    const encrypted = await redis.get(`oauth:${userId}`);
    if (!encrypted) return null;
    return JSON.parse(decrypt(encrypted));
  }
};
```

**Best Practices:**
- **Secure Storage**: Store tokens securely using encryption and secure storage solutions.
- **Token Management**: Implement proper token management to ensure tokens are valid and secure.

### 4. Refresh Token Rotation

Implement refresh token rotation to enhance security and prevent token reuse.

```typescript
const rotateRefreshToken = async (userId: string) => {
  const tokens = await secureTokenStorage.retrieve(userId);
  if (!tokens) throw new Error('No tokens found');

  // Get new tokens using refresh token
  const newTokens = await refreshOAuthTokens(tokens.refreshToken);
  
  // Store new tokens
  await secureTokenStorage.store(userId, newTokens);
  
  return newTokens;
};
```

**Best Practices:**
- **Refresh Token Rotation**: Rotate refresh tokens to enhance security and prevent token reuse.
- **Secure Token Exchange**: Ensure the token exchange process is secure and resistant to interception.

---

## Conclusion

Implementing OAuth authentication involves a combination of provider setup, secure token management, and best practices. By following the patterns and best practices outlined in this guide, you can build secure and efficient OAuth authentication systems using **Express.js**, **Next.js**, and **Nest.js** frameworks.

---

## Additional Resources

- [Express.js Documentation](https://expressjs.com/)
- [Next.js Documentation](https://nextjs.org/docs)
- [Nest.js Documentation](https://docs.nestjs.com/)
- [OAuth 2.0](https://oauth.net/2/)
- [OWASP OAuth 2.0 Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Security_Cheat_Sheet.html)