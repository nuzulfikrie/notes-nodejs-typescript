# Monitoring Guidelines

This document outlines the monitoring strategies, observability practices, and operational guidelines for our microservices architecture.

## Table of Contents
- [Distributed Tracing](#distributed-tracing)
- [Logging Strategy](#logging-strategy)
- [Metrics Collection](#metrics-collection)
- [Health Checks](#health-checks)
- [Alerting](#alerting)
- [Dashboards](#dashboards)

## Distributed Tracing

### OpenTelemetry Implementation
```typescript
// Tracing configuration
import { NodeTracerProvider } from '@opentelemetry/node';
import { registerInstrumentations } from '@opentelemetry/instrumentation';
import { ExpressInstrumentation } from '@opentelemetry/instrumentation-express';
import { HttpInstrumentation } from '@opentelemetry/instrumentation-http';

export function setupTracing(serviceName: string) {
  const provider = new NodeTracerProvider();
  
  registerInstrumentations({
    instrumentations: [
      new ExpressInstrumentation(),
      new HttpInstrumentation(),
    ],
    tracerProvider: provider,
  });

  provider.register();
  
  return provider.getTracer(serviceName);
}

// Usage in service
const tracer = setupTracing('user-service');

app.use(async (req, res, next) => {
  const span = tracer.startSpan('http_request');
  span.setAttribute('http.method', req.method);
  span.setAttribute('http.url', req.url);
  
  try {
    await next();
  } finally {
    span.end();
  }
});
```

### Trace Context Propagation
```typescript
interface TraceContext {
  traceId: string;
  spanId: string;
  parentId?: string;
  sampled: boolean;
}

class TracingMiddleware {
  async handle(req: Request, res: Response, next: NextFunction) {
    const traceContext = this.extractTraceContext(req);
    
    const span = tracer.startSpan('operation_name', {
      parent: traceContext,
      attributes: {
        'service.name': 'user-service',
        'operation.type': 'http_request'
      }
    });

    try {
      await next();
    } catch (error) {
      span.recordException(error);
      throw error;
    } finally {
      span.end();
    }
  }
}
```

## Logging Strategy

### Structured Logging
```typescript
import winston from 'winston';

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  defaultMeta: { service: 'user-service' },
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' })
  ]
});

// Logging middleware
class LoggingMiddleware {
  async handle(req: Request, res: Response, next: NextFunction) {
    const start = Date.now();
    
    try {
      await next();
    } finally {
      logger.info('Request processed', {
        method: req.method,
        path: req.path,
        duration: Date.now() - start,
        statusCode: res.statusCode,
        traceId: req.headers['x-trace-id']
      });
    }
  }
}
```

### Log Aggregation Configuration
```yaml
# Fluentd configuration
<source>
  @type forward
  port 24224
  bind 0.0.0.0
</source>

<match service.**>
  @type elasticsearch
  host elasticsearch
  port 9200
  logstash_format true
  logstash_prefix service-logs
  flush_interval 5s
</match>
```

## Metrics Collection

### Prometheus Metrics
```typescript
import { Registry, Counter, Histogram } from 'prom-client';

export class MetricsService {
  private registry: Registry;
  
  private httpRequestsTotal: Counter;
  private httpRequestDuration: Histogram;
  
  constructor() {
    this.registry = new Registry();
    
    this.httpRequestsTotal = new Counter({
      name: 'http_requests_total',
      help: 'Total number of HTTP requests',
      labelNames: ['method', 'path', 'status']
    });
    
    this.httpRequestDuration = new Histogram({
      name: 'http_request_duration_seconds',
      help: 'HTTP request duration in seconds',
      labelNames: ['method', 'path']
    });
    
    this.registry.registerMetric(this.httpRequestsTotal);
    this.registry.registerMetric(this.httpRequestDuration);
  }
  
  recordRequest(method: string, path: string, status: number, duration: number) {
    this.httpRequestsTotal.labels(method, path, status.toString()).inc();
    this.httpRequestDuration.labels(method, path).observe(duration);
  }
}
```

### Grafana Dashboard Configuration
```json
{
  "dashboard": {
    "title": "Service Metrics",
    "panels": [
      {
        "title": "Request Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(http_requests_total[5m])",
            "legendFormat": "{{method}} {{path}}"
          }
        ]
      },
      {
        "title": "Response Time",
        "type": "graph",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))",
            "legendFormat": "P95 {{method}} {{path}}"
          }
        ]
      }
    ]
  }
}
```

## Health Checks

### Health Check Implementation
```typescript
interface HealthCheck {
  name: string;
  status: 'UP' | 'DOWN';
  details?: Record<string, any>;
}

class HealthCheckService {
  private checks: Map<string, () => Promise<HealthCheck>>;

  constructor() {
    this.checks = new Map();
    this.registerChecks();
  }

  private registerChecks() {
    this.checks.set('database', this.checkDatabase);
    this.checks.set('redis', this.checkRedis);
    this.checks.set('external-api', this.checkExternalApi);
  }

  async checkHealth(): Promise<{
    status: 'UP' | 'DOWN';
    checks: HealthCheck[];
  }> {
    const results = await Promise.all(
      Array.from(this.checks.values()).map(check => check())
    );

    return {
      status: results.every(r => r.status === 'UP') ? 'UP' : 'DOWN',
      checks: results
    };
  }
}
```

## Alerting

### Alert Rules
```yaml
groups:
- name: service-alerts
  rules:
  - alert: HighErrorRate
    expr: |
      rate(http_requests_total{status=~"5.."}[5m]) 
      / 
      rate(http_requests_total[5m]) > 0.1
    for: 5m
    labels:
      severity: critical
    annotations:
      summary: High error rate detected
      description: Error rate is above 10% for the last 5 minutes

  - alert: SlowResponses
    expr: |
      histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m])) > 2
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: Slow response times detected
      description: 95th percentile of response times is above 2 seconds
```

### Alert Notification
```typescript
interface AlertNotification {
  alertName: string;
  severity: 'critical' | 'warning' | 'info';
  message: string;
  timestamp: Date;
  metadata: Record<string, any>;
}

class AlertManager {
  async sendAlert(notification: AlertNotification): Promise<void> {
    // Send to multiple channels
    await Promise.all([
      this.sendSlackNotification(notification),
      this.sendEmailNotification(notification),
      this.sendPagerDuty(notification)
    ]);
  }
}
```

## Best Practices

### 1. Tracing
- Implement distributed tracing
- Propagate trace context
- Sample traces appropriately
- Add business context

### 2. Logging
- Use structured logging
- Include correlation IDs
- Define log levels
- Implement log rotation

### 3. Metrics
- Define SLIs/SLOs
- Use appropriate metric types
- Add relevant labels
- Monitor resource usage

### 4. Health Checks
- Implement readiness probes
- Add liveness probes
- Check dependencies
- Include version info

### 5. Alerting
- Define clear thresholds
- Avoid alert fatigue
- Include runbooks
- Set up escalations

### 6. Dashboards
- Create service dashboards
- Include key metrics
- Add error tracking
- Monitor dependencies 