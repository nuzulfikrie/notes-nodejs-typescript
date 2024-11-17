# Next.js Event Handling

This document outlines event handling patterns and implementations specific to Next.js applications.

## Table of Contents
- [Client-Side Events](#client-side-events)
- [Server-Side Events](#server-side-events)
- [WebSocket Events](#websocket-events)
- [Best Practices](#best-practices)

## Client-Side Events

### Event Bus Implementation
```typescript
// lib/events/eventBus.ts
type EventHandler = (payload: any) => void;

class ClientEventBus {
  private handlers: Map<string, EventHandler[]> = new Map();

  subscribe(eventType: string, handler: EventHandler): () => void {
    if (!this.handlers.has(eventType)) {
      this.handlers.set(eventType, []);
    }
    this.handlers.get(eventType)!.push(handler);

    return () => {
      const handlers = this.handlers.get(eventType)!;
      const index = handlers.indexOf(handler);
      if (index > -1) {
        handlers.splice(index, 1);
      }
    };
  }

  publish(eventType: string, payload: any): void {
    const handlers = this.handlers.get(eventType) || [];
    handlers.forEach(handler => handler(payload));
  }
}

export const eventBus = new ClientEventBus();
```

### React Component Integration
```typescript
// components/EventAwareComponent.tsx
import { useEffect } from 'react';
import { eventBus } from '@/lib/events/eventBus';

export function EventAwareComponent() {
  useEffect(() => {
    // Subscribe to events
    const unsubscribe = eventBus.subscribe('dataUpdated', (data) => {
      console.log('Data updated:', data);
    });

    // Cleanup subscription
    return () => unsubscribe();
  }, []);

  const handleAction = () => {
    eventBus.publish('dataUpdated', { timestamp: new Date() });
  };

  return <button onClick={handleAction}>Trigger Event</button>;
}
```

### Custom Event Hook
```typescript
// hooks/useEvent.ts
import { useEffect } from 'react';
import { eventBus } from '@/lib/events/eventBus';

export function useEvent(eventType: string, handler: (payload: any) => void) {
  useEffect(() => {
    const unsubscribe = eventBus.subscribe(eventType, handler);
    return () => unsubscribe();
  }, [eventType, handler]);
}

// Usage in component
function MyComponent() {
  useEvent('userUpdated', (user) => {
    console.log('User updated:', user);
  });
}
```

## Server-Side Events

### API Route Handler
```typescript
// pages/api/events/[type].ts
import { NextApiRequest, NextApiResponse } from 'next';
import { Server as SocketServer } from 'socket.io';

export default function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'POST') {
    return res.status(405).json({ message: 'Method not allowed' });
  }

  const { type } = req.query;
  const payload = req.body;

  // Get Socket.io instance
  const io = (res.socket as any).server.io;

  // Emit event to all connected clients
  io.emit(type as string, payload);

  res.status(200).json({ message: 'Event published' });
}
```

### Server Event Middleware
```typescript
// middleware/events.ts
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

export function middleware(request: NextRequest) {
  // Add event tracking headers
  const response = NextResponse.next();
  response.headers.set('X-Event-Timestamp', new Date().toISOString());
  return response;
}

export const config = {
  matcher: '/api/events/:path*',
};
```

## WebSocket Events

### Socket.io Setup
```typescript
// lib/socket.ts
import { Server as HTTPServer } from 'http';
import { Server as SocketIOServer } from 'socket.io';
import { eventBus } from './eventBus';

export function setupWebSocketServer(server: HTTPServer) {
  const io = new SocketIOServer(server, {
    path: '/api/socketio',
  });

  io.on('connection', (socket) => {
    console.log('Client connected');

    // Handle client events
    socket.on('client:event', (data) => {
      eventBus.publish('client:event', data);
    });

    // Forward events to connected clients
    eventBus.subscribe('server:event', (data) => {
      socket.emit('server:event', data);
    });

    socket.on('disconnect', () => {
      console.log('Client disconnected');
    });
  });

  return io;
}
```

### WebSocket Client Hook
```typescript
// hooks/useSocket.ts
import { useEffect, useRef } from 'react';
import io, { Socket } from 'socket.io-client';

export function useSocket(url: string) {
  const socketRef = useRef<Socket>();

  useEffect(() => {
    socketRef.current = io(url, {
      path: '/api/socketio',
    });

    return () => {
      socketRef.current?.disconnect();
    };
  }, [url]);

  return socketRef.current;
}

// Usage in component
function RealTimeComponent() {
  const socket = useSocket(process.env.NEXT_PUBLIC_SOCKET_URL!);

  useEffect(() => {
    if (!socket) return;

    socket.on('server:event', (data) => {
      console.log('Received event:', data);
    });

    return () => {
      socket.off('server:event');
    };
  }, [socket]);
}
```

## Best Practices

### 1. Event Naming
- Use namespaced event names (e.g., 'user:created', 'data:updated')
- Keep event names consistent across the application
- Document all event types and their payloads

### 2. Performance
```typescript
// Example of debounced event publishing
import debounce from 'lodash/debounce';

const debouncedPublish = debounce((type: string, payload: any) => {
  eventBus.publish(type, payload);
}, 300);
```

### 3. Error Handling
```typescript
// Enhanced event bus with error handling
class SafeEventBus extends ClientEventBus {
  publish(eventType: string, payload: any): void {
    try {
      super.publish(eventType, payload);
    } catch (error) {
      console.error(`Error publishing event ${eventType}:`, error);
      // Optional: Report to error tracking service
    }
  }
}
```

### 4. Testing
```typescript
// Example event test
import { eventBus } from '@/lib/events/eventBus';

describe('EventBus', () => {
  test('subscribers should receive published events', (done) => {
    const payload = { test: true };
    
    eventBus.subscribe('test:event', (data) => {
      expect(data).toEqual(payload);
      done();
    });

    eventBus.publish('test:event', payload);
  });
});
```

### 5. Type Safety
```typescript
// Typed event bus
type EventMap = {
  'user:created': { id: string; name: string };
  'user:updated': { id: string; changes: Partial<User> };
  'data:refreshed': void;
};

class TypedEventBus {
  publish<K extends keyof EventMap>(
    event: K,
    payload: EventMap[K]
  ): void {
    // Implementation
  }

  subscribe<K extends keyof EventMap>(
    event: K,
    handler: (payload: EventMap[K]) => void
  ): () => void {
    // Implementation
  }
}


### NestJS Event Handling 
// Enhanced NestJS Event Handling Example

// publisher.service.ts
import { Injectable } from '@nestjs/common';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { CreateUserDto } from './dto/create-user.dto';
import { User } from './entities/user.entity';

@Injectable()
export class PublisherService {
  constructor(private readonly eventEmitter: EventEmitter2) {}

  /**
   * Creates a new user and emits a 'user.created' event.
   * @param userDto - Data transfer object containing user details.
   * @returns The created user entity.
   */
  async createUser(userDto: CreateUserDto): Promise<User> {
    // Logic to create a user
    const user = await this.saveUserToDatabase(userDto);

    // Emit the 'user.created' event with the created user data
    this.eventEmitter.emit('user.created', user);

    return user;
  }

  /**
   * Saves the user to the database.
   * @param userDto - Data transfer object containing user details.
   * @returns The saved user entity.
   */
  private async saveUserToDatabase(userDto: CreateUserDto): Promise<User> {
    // Implement the logic to save the user to the database
    // Example:
    // return this.userRepository.create(userDto);
    // For demonstration purposes, returning a mock user
    return {
      id: '12345',
      name: userDto.name,
      email: userDto.email,
      // ...other properties
    };
  }
}

// listener.service.ts
import { Injectable, Logger } from '@nestjs/common';
import { OnEvent } from '@nestjs/event-emitter';
import { User } from './entities/user.entity';
import { EmailService } from './email.service';

@Injectable()
export class ListenerService {
  private readonly logger = new Logger(ListenerService.name);

  constructor(private readonly emailService: EmailService) {}

  /**
   * Handles the 'user.created' event.
   * @param user - The user entity that was created.
   */
  @OnEvent('user.created')
  async handleUserCreatedEvent(user: User): Promise<void> {
    this.logger.log(`User created: ${user.id} - ${user.name}`);

    try {
      // Additional logic, e.g., sending a welcome email
      await this.emailService.sendWelcomeEmail(user.email);
      this.logger.log(`Welcome email sent to ${user.email}`);
    } catch (error) {
      this.logger.error(`Failed to send welcome email to ${user.email}`, error.stack);
      // Handle the error appropriately, such as retrying or notifying administrators
    }
  }
}
```