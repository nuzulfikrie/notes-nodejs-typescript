## docs/microservices/communication.md
# Microservices Communication Guide

## Table of Contents
- [Communication Patterns](#communication-patterns)
- [REST Communication](#rest-communication)
- [gRPC Implementation](#grpc-implementation)
- [Message Queues](#message-queues)
- [Event-Driven Architecture](#event-driven-architecture)
- [Circuit Breakers](#circuit-breakers)
- [API Gateway](#api-gateway)
- [Best Practices](#best-practices)

## Communication Patterns

### 1. Synchronous Communication
- REST APIs
- gRPC
- GraphQL
- Direct HTTP calls

### 2. Asynchronous Communication
- Message Queues (RabbitMQ, Apache Kafka)
- Event Bus
- Pub/Sub Systems

## REST Communication

### Service-to-Service REST Client
```typescript
// utils/http-client.ts
import axios, { AxiosInstance, AxiosError } from 'axios';

export class ServiceHttpClient {
  private client: AxiosInstance;

  constructor(baseURL: string, private serviceName: string) {
    this.client = axios.create({
      baseURL,
      timeout: 5000,
      headers: {
        'Content-Type': 'application/json',
        'X-Service-Name': serviceName
      }
    });

    this.setupInterceptors();
  }

  private setupInterceptors() {
    this.client.interceptors.request.use(
      (config) => {
        // Add correlation ID for request tracing
        config.headers['X-Correlation-ID'] = this.generateCorrelationId();
        return config;
      },
      (error) => {
        return Promise.reject(error);
      }
    );

    this.client.interceptors.response.use(
      (response) => response,
      (error: AxiosError) => {
        this.handleError(error);
        return Promise.reject(error);
      }
    );
  }

  private generateCorrelationId(): string {
    return `${this.serviceName}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  private handleError(error: AxiosError) {
    // Log error with context
    console.error('Service communication error:', {
      service: this.serviceName,
      status: error.response?.status,
      message: error.message,
      url: error.config?.url
    });
  }

  async get<T>(url: string) {
    const response = await this.client.get<T>(url);
    return response.data;
  }

  async post<T>(url: string, data: any) {
    const response = await this.client.post<T>(url, data);
    return response.data;
  }

  async put<T>(url: string, data: any) {
    const response = await this.client.put<T>(url, data);
    return response.data;
  }

  async delete<T>(url: string) {
    const response = await this.client.delete<T>(url);
    return response.data;
  }
}

// Usage example
const userServiceClient = new ServiceHttpClient(
  'http://user-service:3001',
  'order-service'
);
```

## gRPC Implementation

### Proto Definition
```protobuf
// proto/user.proto
syntax = "proto3";

package user;

service UserService {
  rpc GetUser (GetUserRequest) returns (User) {}
  rpc CreateUser (CreateUserRequest) returns (User) {}
}

message GetUserRequest {
  string id = 1;
}

message CreateUserRequest {
  string email = 1;
  string name = 2;
}

message User {
  string id = 1;
  string email = 2;
  string name = 3;
  string role = 4;
}
```

### gRPC Server Implementation
```typescript
// services/grpc-user.service.ts
import * as grpc from '@grpc/grpc-js';
import * as protoLoader from '@grpc/proto-loader';
import { ProtoGrpcType } from './generated/user';

const packageDefinition = protoLoader.loadSync('./proto/user.proto');
const proto = grpc.loadPackageDefinition(
  packageDefinition
) as unknown as ProtoGrpcType;

class UserService {
  async getUser(
    call: grpc.ServerUnaryCall<GetUserRequest, User>,
    callback: grpc.sendUnaryData<User>
  ) {
    try {
      const user = await UserModel.findById(call.request.id);
      if (!user) {
        return callback({
          code: grpc.status.NOT_FOUND,
          message: 'User not found'
        });
      }
      callback(null, user);
    } catch (error) {
      callback({
        code: grpc.status.INTERNAL,
        message: 'Internal error'
      });
    }
  }

  async createUser(
    call: grpc.ServerUnaryCall<CreateUserRequest, User>,
    callback: grpc.sendUnaryData<User>
  ) {
    try {
      const user = await UserModel.create(call.request);
      callback(null, user);
    } catch (error) {
      callback({
        code: grpc.status.INTERNAL,
        message: 'Internal error'
      });
    }
  }
}

const server = new grpc.Server();
server.addService(
  proto.user.UserService.service,
  new UserService() as any
);
```

### gRPC Client Implementation
```typescript
// clients/user-grpc.client.ts
import * as grpc from '@grpc/grpc-js';
import { promisify } from 'util';
import { UserServiceClient } from './generated/user';

export class UserGrpcClient {
  private client: UserServiceClient;

  constructor(address: string) {
    this.client = new proto.user.UserService(
      address,
      grpc.credentials.createInsecure()
    );
  }

  async getUser(id: string): Promise<User> {
    const getUser = promisify(this.client.getUser.bind(this.client));
    return getUser({ id });
  }

  async createUser(data: CreateUserRequest): Promise<User> {
    const createUser = promisify(this.client.createUser.bind(this.client));
    return createUser(data);
  }
}
```

## Message Queues

### RabbitMQ Implementation
```typescript
// services/message-queue.service.ts
import amqp, { Channel, Connection } from 'amqplib';

export class MessageQueueService {
  private connection?: Connection;
  private channel?: Channel;

  async connect(url: string) {
    this.connection = await amqp.connect(url);
    this.channel = await this.connection.createChannel();
  }

  async publishMessage(
    exchange: string,
    routingKey: string,
    message: any
  ) {
    if (!this.channel) {
      throw new Error('Channel not initialized');
    }

    await this.channel.assertExchange(exchange, 'topic', { durable: true });
    
    this.channel.publish(
      exchange,
      routingKey,
      Buffer.from(JSON.stringify(message)),
      {
        persistent: true,
        headers: {
          'timestamp': new Date().toISOString(),
          'service': process.env.SERVICE_NAME
        }
      }
    );
  }

  async subscribe(
    exchange: string,
    queue: string,
    routingKey: string,
    handler: (message: any) => Promise<void>
  ) {
    if (!this.channel) {
      throw new Error('Channel not initialized');
    }

    await this.channel.assertExchange(exchange, 'topic', { durable: true });
    
    const q = await this.channel.assertQueue(queue, { durable: true });
    
    await this.channel.bindQueue(q.queue, exchange, routingKey);

    this.channel.consume(q.queue, async (msg) => {
      if (msg) {
        try {
          const content = JSON.parse(msg.content.toString());
          await handler(content);
          this.channel?.ack(msg);
        } catch (error) {
          // Handle failed processing
          this.channel?.nack(msg, false, true);
        }
      }
    });
  }

  async close() {
    await this.channel?.close();
    await this.connection?.close();
  }
}

// Usage example
const messageQueue = new MessageQueueService();

// Publisher
await messageQueue.connect(process.env.RABBITMQ_URL);
await messageQueue.publishMessage(
  'user-events',
  'user.created',
  { id: 'user123', email: 'user@example.com' }
);

// Subscriber
await messageQueue.subscribe(
  'user-events',
  'order-service-user-events',
  'user.*',
  async (message) => {
    console.log('Received message:', message);
    // Process message
  }
);
```

## Event-Driven Architecture

### Event Bus Implementation
```typescript
// services/event-bus.service.ts
type EventHandler = (data: any) => Promise<void>;

export class EventBus {
  private handlers: Map<string, EventHandler[]> = new Map();
  private messageQueue: MessageQueueService;

  constructor(messageQueue: MessageQueueService) {
    this.messageQueue = messageQueue;
  }

  async publish(eventName: string, data: any) {
    await this.messageQueue.publishMessage(
      'events',
      eventName,
      {
        eventName,
        data,
        timestamp: new Date().toISOString()
      }
    );
  }

  subscribe(eventName: string, handler: EventHandler) {
    const handlers = this.handlers.get(eventName) || [];
    handlers.push(handler);
    this.handlers.set(eventName, handlers);
  }

  async init() {
    await this.messageQueue.subscribe(
      'events',
      `${process.env.SERVICE_NAME}-events`,
      '#',
      async (message) => {
        const handlers = this.handlers.get(message.eventName) || [];
        await Promise.all(
          handlers.map(handler => handler(message.data))
        );
      }
    );
  }
}
```

## Circuit Breakers

### Circuit Breaker Implementation
```typescript
// utils/circuit-breaker.ts
interface CircuitBreakerOptions {
  failureThreshold: number;
  resetTimeout: number;
}

enum CircuitState {
  CLOSED,
  OPEN,
  HALF_OPEN
}

export class CircuitBreaker {
  private state: CircuitState = CircuitState.CLOSED;
  private failureCount: number = 0;
  private lastFailureTime?: number;

  constructor(private options: CircuitBreakerOptions) {}

  async execute<T>(
    operation: () => Promise<T>
  ): Promise<T> {
    if (this.state === CircuitState.OPEN) {
      if (this.shouldReset()) {
        this.state = CircuitState.HALF_OPEN;
      } else {
        throw new Error('Circuit breaker is OPEN');
      }
    }

    try {
      const result = await operation();
      this.onSuccess();
      return result;
    } catch (error) {
      this.onFailure();
      throw error;
    }
  }

  private onSuccess() {
    this.failureCount = 0;
    this.state = CircuitState.CLOSED;
  }

  private onFailure() {
    this.failureCount++;
    this.lastFailureTime = Date.now();

    if (this.failureCount >= this.options.failureThreshold) {
      this.state = CircuitState.OPEN;
    }
  }

  private shouldReset(): boolean {
    if (!this.lastFailureTime) return false;
    return Date.now() - this.lastFailureTime >= this.options.resetTimeout;
  }
}

// Usage example
const circuitBreaker = new CircuitBreaker({
  failureThreshold: 3,
  resetTimeout: 30000 // 30 seconds
});

try {
  const result = await circuitBreaker.execute(async () => {
    return await userServiceClient.get('/users/123');
  });
} catch (error) {
  // Handle error or circuit breaker open
}
```

## Best Practices

### 1. Error Handling
- Implement proper retry mechanisms
- Use circuit breakers
- Handle timeouts appropriately
- Log failed communications

### 2. Message Design
- Use versioned messages
- Include correlation IDs
- Keep messages lightweight
- Use appropriate serialization

### 3. Security
- Implement service-to-service authentication
- Use TLS for all communications
- Validate all incoming messages
- Implement rate limiting

### 4. Monitoring
- Track communication metrics
- Monitor message queue health
- Implement distributed tracing
- Log all service interactions

### 5. Performance
- Use connection pooling
- Implement caching where appropriate
- Choose appropriate serialization formats
- Consider message compression

Remember to:
1. Choose the right communication pattern for each use case
2. Implement proper error handling and retries
3. Monitor and log all communications
4. Secure all service-to-service communication
5. Handle partial failures gracefully
6. Implement proper message validation
7. Use correlation IDs for request tracing
8. Maintain API versioning
9. Document all communication interfaces
10. Test communication failures and recovery