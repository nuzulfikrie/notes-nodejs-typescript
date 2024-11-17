# Deployment Guidelines

This document outlines the deployment strategies and best practices for our microservices architecture.

## Table of Contents
- [Container Orchestration](#container-orchestration)
- [Service Discovery](#service-discovery)
- [Load Balancing](#load-balancing)
- [Deployment Strategies](#deployment-strategies)
- [Infrastructure as Code](#infrastructure-as-code)
- [Monitoring and Operations](#monitoring-and-operations)

## Container Orchestration

### Docker Configuration
```dockerfile
# Base Dockerfile for Node.js services
FROM node:18-alpine as builder

WORKDIR /app
COPY package*.json ./
RUN npm ci

COPY . .
RUN npm run build

FROM node:18-alpine
WORKDIR /app
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY package*.json ./

EXPOSE 3000
CMD ["npm", "run", "start:prod"]
```

### Kubernetes Configuration
```yaml
# Basic service deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: user-service
  namespace: production
spec:
  replicas: 3
  selector:
    matchLabels:
      app: user-service
  template:
    metadata:
      labels:
        app: user-service
    spec:
      containers:
      - name: user-service
        image: registry.company.com/user-service:1.0.0
        ports:
        - containerPort: 3000
        env:
        - name: NODE_ENV
          value: "production"
        resources:
          requests:
            memory: "256Mi"
            cpu: "200m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        readinessProbe:
          httpGet:
            path: /health
            port: 3000
          initialDelaySeconds: 5
          periodSeconds: 10
        livenessProbe:
          httpGet:
            path: /health
            port: 3000
          initialDelaySeconds: 15
          periodSeconds: 20
```

## Service Discovery

### Kubernetes Service
```yaml
apiVersion: v1
kind: Service
metadata:
  name: user-service
  namespace: production
spec:
  type: ClusterIP
  selector:
    app: user-service
  ports:
  - port: 80
    targetPort: 3000
```

### Service Registry Implementation
```typescript
interface ServiceInstance {
  id: string;
  name: string;
  version: string;
  endpoints: string[];
  health: {
    status: 'UP' | 'DOWN';
    lastCheck: Date;
  };
}

class ServiceRegistry {
  private instances: Map<string, ServiceInstance> = new Map();

  async register(instance: ServiceInstance): Promise<void> {
    this.instances.set(instance.id, {
      ...instance,
      health: {
        status: 'UP',
        lastCheck: new Date()
      }
    });
  }

  async deregister(instanceId: string): Promise<void> {
    this.instances.delete(instanceId);
  }

  async getService(name: string): Promise<ServiceInstance[]> {
    return Array.from(this.instances.values())
      .filter(instance => instance.name === name && instance.health.status === 'UP');
  }
}
```

## Load Balancing

### Ingress Configuration
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: microservices-ingress
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /
spec:
  rules:
  - host: api.company.com
    http:
      paths:
      - path: /users
        pathType: Prefix
        backend:
          service:
            name: user-service
            port:
              number: 80
      - path: /orders
        pathType: Prefix
        backend:
          service:
            name: order-service
            port:
              number: 80
```

## Deployment Strategies

### Blue-Green Deployment
```yaml
# Blue deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: user-service-blue
spec:
  replicas: 3
  template:
    metadata:
      labels:
        app: user-service
        version: blue
    # ... rest of deployment spec

---
# Green deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: user-service-green
spec:
  replicas: 3
  template:
    metadata:
      labels:
        app: user-service
        version: green
    # ... rest of deployment spec

---
# Service switch
apiVersion: v1
kind: Service
metadata:
  name: user-service
spec:
  selector:
    app: user-service
    version: blue  # Switch to green for deployment
```

### Canary Deployment
```yaml
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: user-service
spec:
  hosts:
  - user-service
  http:
  - route:
    - destination:
        host: user-service
        subset: v1
      weight: 90
    - destination:
        host: user-service
        subset: v2
      weight: 10
```

## Infrastructure as Code

### Terraform Configuration
```hcl
# EKS cluster configuration
module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 19.0"

  cluster_name    = "microservices-cluster"
  cluster_version = "1.24"

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  eks_managed_node_groups = {
    general = {
      desired_size = 3
      min_size     = 2
      max_size     = 5

      instance_types = ["t3.medium"]
      capacity_type  = "ON_DEMAND"
    }
  }
}
```

### Helm Chart Structure
```yaml
# values.yaml
service:
  name: user-service
  replicas: 3
  image:
    repository: registry.company.com/user-service
    tag: 1.0.0
  resources:
    requests:
      cpu: 200m
      memory: 256Mi
    limits:
      cpu: 500m
      memory: 512Mi

# templates/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .Values.service.name }}
spec:
  replicas: {{ .Values.service.replicas }}
  template:
    spec:
      containers:
      - name: {{ .Values.service.name }}
        image: "{{ .Values.image.repository }}:{{ .Values.image.tag }}"
        resources:
          {{- toYaml .Values.resources | nindent 12 }}
```

## Monitoring and Operations

### Prometheus Configuration
```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: user-service-monitor
spec:
  selector:
    matchLabels:
      app: user-service
  endpoints:
  - port: metrics
    interval: 15s
```

### Health Check Implementation
```typescript
import { HealthCheck, HealthIndicator } from '@nestjs/terminus';

class ServiceHealthIndicator extends HealthIndicator {
  async check(key: string) {
    try {
      // Perform health checks
      const isHealthy = await this.checkDependencies();
      
      return this.getStatus(key, isHealthy, {
        version: process.env.SERVICE_VERSION,
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      return this.getStatus(key, false, { error: error.message });
    }
  }
}
```

## Best Practices

### 1. Container Management
- Use multi-stage builds
- Minimize image size
- Implement security scanning
- Version all images

### 2. Kubernetes Configuration
- Use namespaces for isolation
- Implement resource limits
- Configure health checks
- Use config maps and secrets

### 3. Deployment Process
- Automate deployments
- Implement rollback strategies
- Use deployment strategies
- Monitor deployment health

### 4. Security
- Network policies
- RBAC configuration
- Secret management
- Security scanning

### 5. Monitoring
- Resource monitoring
- Application metrics
- Alerting rules
- Logging strategy

### 6. Scaling
- Horizontal pod autoscaling
- Cluster autoscaling
- Load testing
- Capacity planning
