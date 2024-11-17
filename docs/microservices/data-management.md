# Data Management Guidelines

This document provides detailed guidance on data management patterns and practices within our microservices architecture.

## Table of Contents
- [Database Patterns](#database-patterns)
- [Data Consistency](#data-consistency)
- [Event Sourcing](#event-sourcing)
- [CQRS Implementation](#cqrs-implementation)
- [Distributed Transactions](#distributed-transactions)

## Database Patterns

### Database per Service
- Each service owns its data exclusively
- No direct database access from other services
- Independent schema evolution
- Technology choice flexibility

```typescript
// Example service data boundary
interface UserService {
  // Own user-specific data
  users: {
    id: string;
    email: string;
    profile: UserProfile;
  };
  
  // Reference only IDs from other services
  orders: {
    userId: string;
    orderIds: string[]; // References to Order Service
  };
}
```

### Data Access Patterns
```typescript
// Repository Pattern Example
interface UserRepository {
  findById(id: string): Promise<User>;
  findByEmail(email: string): Promise<User>;
  save(user: User): Promise<User>;
  update(id: string, data: Partial<User>): Promise<User>;
  delete(id: string): Promise<void>;
}

// Implementation with MongoDB
class MongoUserRepository implements UserRepository {
  constructor(private readonly collection: Collection<User>) {}

  async findById(id: string): Promise<User> {
    const user = await this.collection.findOne({ _id: new ObjectId(id) });
    if (!user) throw new NotFoundException('User not found');
    return user;
  }
  
  // ... other implementations
}
```

## Data Consistency

### Eventual Consistency
```typescript
// Event-based consistency example
interface OrderCreatedEvent {
  orderId: string;
  userId: string;
  products: Array<{
    productId: string;
    quantity: number;
  }>;
}

class InventoryService {
  @EventHandler('ORDER_CREATED')
  async handleOrderCreated(event: OrderCreatedEvent): Promise<void> {
    // Update inventory counts asynchronously
    for (const product of event.products) {
      await this.reserveInventory(product.productId, product.quantity);
    }
  }
}
```

### Saga Pattern
```typescript
// Distributed transaction saga
class OrderSaga {
  async execute(orderData: CreateOrderDto): Promise<void> {
    try {
      // Step 1: Create Order
      const order = await this.orderService.create(orderData);
      
      // Step 2: Reserve Inventory
      await this.inventoryService.reserve(order.items);
      
      // Step 3: Process Payment
      await this.paymentService.process(order.payment);
      
      // Step 4: Confirm Order
      await this.orderService.confirm(order.id);
    } catch (error) {
      // Compensating transactions
      await this.rollback(error);
    }
  }

  private async rollback(error: Error): Promise<void> {
    // Implement compensating transactions
  }
}
```

## Event Sourcing

### Event Store
```typescript
interface Event {
  id: string;
  type: string;
  aggregateId: string;
  data: any;
  timestamp: Date;
  version: number;
}

class EventStore {
  async saveEvents(aggregateId: string, events: Event[]): Promise<void> {
    await this.eventCollection.insertMany(events);
  }

  async getEvents(aggregateId: string): Promise<Event[]> {
    return this.eventCollection
      .find({ aggregateId })
      .sort({ version: 1 })
      .toArray();
  }
}
```

### Event Sourced Aggregate
```typescript
class OrderAggregate {
  private state: Order;
  private version: number = 0;

  applyEvents(events: Event[]): void {
    for (const event of events) {
      this.apply(event);
      this.version = event.version;
    }
  }

  private apply(event: Event): void {
    switch (event.type) {
      case 'ORDER_CREATED':
        this.state = { ...event.data, status: 'CREATED' };
        break;
      case 'ORDER_CONFIRMED':
        this.state.status = 'CONFIRMED';
        break;
      // ... other event handlers
    }
  }
}
```

## CQRS Implementation

### Command Side
```typescript
interface CreateOrderCommand {
  userId: string;
  items: OrderItem[];
}

class OrderCommandHandler {
  async handle(command: CreateOrderCommand): Promise<string> {
    // Validate command
    // Generate events
    // Save to event store
    const events = this.generateEvents(command);
    await this.eventStore.saveEvents(events);
    
    // Return aggregate ID
    return events[0].aggregateId;
  }
}
```

### Query Side
```typescript
interface OrderReadModel {
  id: string;
  userId: string;
  items: OrderItem[];
  status: OrderStatus;
  total: number;
  createdAt: Date;
}

class OrderQueryService {
  async getOrder(id: string): Promise<OrderReadModel> {
    return this.readDatabase.orders.findOne({ id });
  }

  async getUserOrders(userId: string): Promise<OrderReadModel[]> {
    return this.readDatabase.orders.find({ userId });
  }
}
```

## Distributed Transactions

### Two-Phase Commit
```typescript
class TwoPhaseCommit {
  async execute(transaction: Transaction): Promise<void> {
    // Phase 1: Prepare
    const participants = await this.prepare(transaction);
    
    try {
      // Phase 2: Commit
      await this.commit(participants);
    } catch (error) {
      // Rollback if any participant fails
      await this.rollback(participants);
      throw error;
    }
  }
}
```

### Outbox Pattern
```typescript
interface OutboxMessage {
  id: string;
  aggregateType: string;
  aggregateId: string;
  type: string;
  payload: any;
  status: 'PENDING' | 'PUBLISHED' | 'FAILED';
  createdAt: Date;
}

class OutboxService {
  async saveMessage(message: OutboxMessage): Promise<void> {
    await this.outboxCollection.insertOne(message);
  }

  async processMessages(): Promise<void> {
    const messages = await this.outboxCollection
      .find({ status: 'PENDING' })
      .toArray();
      
    for (const message of messages) {
      try {
        await this.eventBus.publish(message);
        await this.markAsPublished(message.id);
      } catch (error) {
        await this.markAsFailed(message.id, error);
      }
    }
  }
}
```

## Best Practices

### 1. Data Storage
- Choose appropriate database per service
- Implement proper indexing
- Use connection pooling
- Regular backup strategies

### 2. Data Access
- Use repository pattern
- Implement caching strategies
- Handle connection failures
- Monitor query performance

### 3. Data Consistency
- Define consistency boundaries
- Use eventual consistency where appropriate
- Implement retry mechanisms
- Handle partial failures

### 4. Security
- Encrypt sensitive data
- Implement access controls
- Regular security audits
- Secure backup storage

### 5. Performance
- Optimize queries
- Implement caching
- Monitor database metrics
- Regular maintenance 