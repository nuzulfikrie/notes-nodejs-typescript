### docs/microservices/service-design.md
# Service Design Guidelines

This document outlines the principles and practices for designing microservices in our architecture. It provides detailed guidance on service boundaries, domain-driven design, and API design patterns.

## Table of Contents
- [Service Boundaries](#service-boundaries)
- [Domain-Driven Design](#domain-driven-design)
- [API Design](#api-design)
- [Service Templates](#service-templates)

## Service Boundaries

### Single Responsibility
- Each service should focus on one business capability
- Services should be cohesive and independent
- Avoid shared dependencies between services
- Follow the "Database per Service" pattern

### Size Guidelines
- Services should be small enough to be:
  - Understood by a single team
  - Deployed independently
  - Tested comprehensively
  - Rewritten within a single sprint if necessary

### Boundary Definition Checklist
- [ ] Clear business capability
- [ ] Independent data model
- [ ] Minimal dependencies on other services
- [ ] Well-defined API contract
- [ ] Independent deployment capability

## Domain-Driven Design

### Bounded Contexts
```typescript
// Example of a bounded context for Order Management
interface Order {
  orderId: string;
  customerId: string;
  items: OrderItem[];
  status: OrderStatus;
  totalAmount: Money;
  createdAt: Date;
}

interface OrderItem {
  productId: string;
  quantity: number;
  price: Money;
}

enum OrderStatus {
  CREATED = 'CREATED',
  CONFIRMED = 'CONFIRMED',
  SHIPPED = 'SHIPPED',
  DELIVERED = 'DELIVERED',
  CANCELLED = 'CANCELLED'
}

interface Money {
  amount: number;
  currency: string;
}
```

### Domain Events
```typescript
interface DomainEvent {
  eventId: string;
  timestamp: Date;
  type: string;
  payload: any;
}

// Example domain event
interface OrderCreatedEvent extends DomainEvent {
  type: 'ORDER_CREATED';
  payload: {
    orderId: string;
    customerId: string;
    totalAmount: Money;
  };
}
```

## API Design

### RESTful Endpoints
- Use consistent naming conventions
- Implement proper HTTP methods
- Include versioning strategy
- Provide comprehensive documentation

```typescript
// Example REST controller
@Controller('api/v1/orders')
export class OrderController {
  @Post()
  async createOrder(@Body() orderData: CreateOrderDto): Promise<Order> {
    // Implementation
  }

  @Get(':id')
  async getOrder(@Param('id') orderId: string): Promise<Order> {
    // Implementation
  }

  @Put(':id')
  async updateOrder(
    @Param('id') orderId: string,
    @Body() updateData: UpdateOrderDto
  ): Promise<Order> {
    // Implementation
  }

  @Delete(':id')
  async deleteOrder(@Param('id') orderId: string): Promise<void> {
    // Implementation
  }
}
```

### API Documentation
```yaml
openapi: 3.0.0
info:
  title: Order Service API
  version: 1.0.0
paths:
  /api/v1/orders:
    post:
      summary: Create a new order
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/CreateOrderDto'
      responses:
        201:
          description: Order created successfully
```

## Service Templates

### Base Service Structure
```
service/
├── src/
│   ├── controllers/
│   ├── services/
│   ├── repositories/
│   ├── domain/
│   ├── interfaces/
│   └── utils/
├── test/
├── Dockerfile
└── package.json
```

### Implementation Guidelines
1. **Controllers**: Handle HTTP requests and responses
2. **Services**: Implement business logic
3. **Repositories**: Manage data access
4. **Domain**: Define core business models
5. **Interfaces**: Define contracts and DTOs
6. **Utils**: Shared utilities and helpers

### Error Handling
```typescript
// Standard error response format
interface ApiError {
  code: string;
  message: string;
  details?: any;
  timestamp: string;
}

// Error handling middleware
export const errorHandler = (
  error: Error,
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const apiError: ApiError = {
    code: error.name,
    message: error.message,
    timestamp: new Date().toISOString()
  };
  
  res.status(500).json(apiError);
};
```

## Best Practices

### 1. Service Design
- Follow SOLID principles
- Implement clean architecture
- Use dependency injection
- Maintain comprehensive tests

### 2. API Design
- Use consistent error handling
- Implement proper validation
- Include API documentation
- Version your APIs

### 3. Security
- Implement authentication
- Add authorization checks
- Validate inputs
- Handle sensitive data properly

### 4. Testing
- Unit tests
- Integration tests
- Contract tests
- Performance tests

### 5. Monitoring
- Health check endpoints
- Metrics collection
- Logging strategy
- Tracing implementation
````

This service-design.md file complements the architecture.md by providing:
1. Detailed guidelines for service boundaries and design
2. Practical examples of domain-driven design
3. Concrete API design patterns and examples
4. Service template structure and best practices
5. Code examples for common patterns and implementations

The document maintains consistency with the architecture principles while providing more detailed, implementation-focused guidance.