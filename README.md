# AI Gateway

A multi-tenant API Gateway designed for AI service providers with support for rate limiting, authentication, and plugin system.

## Architecture

The gateway consists of two main components:
1. Admin API (Port 8080) - For tenant and configuration management
2. Proxy API (Port 8081) - For handling and forwarding requests

### Components
- **Admin Server**: Manages tenants, API keys, and forwarding rules
- **Proxy Server**: Handles request forwarding and plugin execution
- **Redis**: Stores configuration and state
- **Plugin System**: Modular system for request/response processing

## Rate Limiting System

### Overview
The gateway implements a sophisticated rate limiting system with:

- **Hierarchical Rate Limiting**
  - Gateway-level limits (applies to all routes)
  - Rule-level limits (specific to routes)
  - Cascading evaluation: rule limits → gateway limits

- **Performance Optimizations**
  - In-memory config caching
  - Periodic Redis checks (configurable)
  - Memory cleanup for inactive gateways
  - Thread-safe operations

- **Configuration Persistence**
  - Configs stored in Redis
  - Survives gateway restarts
  - Automatic config reloading

- **Memory Management**
  - Automatic cleanup of unused configs
  - Configurable cleanup intervals
  - Last access tracking
  - Prevention of memory leaks

### Rate Limiter Design
```go
type RateLimiter struct {
    configs         map[string]RateLimiterConfig // In-memory cache
    lastConfigCheck map[string]time.Time         // Track last config check
    lastAccess      map[string]time.Time         // Track last access
    configTTL       time.Duration                // Config refresh interval
    cleanupInterval time.Duration                // Cleanup frequency
    maxIdleTime     time.Duration                // Max time to keep unused configs
}
```

### Flow
1. Request arrives at gateway
2. Gateway identifies target service
3. Rate limiter checks:
   - Rule-specific limits
   - Gateway-wide limits
4. Request processed or rate limited
5. Periodic cleanup of unused configs

### Configuration Example
```json
{
    "gateway": {
        "enabled": true,
        "limits": {
            "global": {
                "limit": 5,
                "window": "1m"
            }
        }
    },
    "rule": {
        "enabled": true,
        "limits": {
            "global": {
                "limit": 3,
                "window": "10s"
            }
        }
    }
}
```

### Performance Considerations
- In-memory caching for fast access
- Periodic Redis checks to reduce latency
- Automatic cleanup to prevent memory leaks
- Thread-safe operations with minimal lock contention

## Quick Start

1. Clone the repository:

```bash
git clone https://github.com/ai-gateway/ai-gateway.git
cd ai-gateway
```

2. Create config.yaml:

```yaml
server:
  admin_port: 8080
  proxy_port: 8081
  base_domain: "example.com"
redis:
  host: "localhost"
  port: 6379
  password: ""
  db: 0
```

3. Start Redis:
```bash
docker-compose up -d
```

4. Start the servers:
```bash
./scripts/run_local.sh
```

## API Usage

### Admin API (Port 8080)

1. Create a tenant:
```bash
curl -X POST http://localhost:8080/api/v1/tenants \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test Company",
    "subdomain": "testcompany",
    "tier": "pro",
    "enabled_plugins": ["rate_limiter"],
    "required_plugins": {
      "security_validator": {
        "name": "security_validator",
        "enabled": true,
        "priority": 1,
        "stage": "pre_request",
        "settings": {
          "required_headers": ["X-Request-ID"]
        }
      }
    }
  }'
```

2. Create a forwarding rule:
```bash
curl -X POST http://localhost:8080/api/v1/tenants/{tenant_id}/rules \
  -H "Authorization: Bearer {api_key}" \
  -H "Content-Type: application/json" \
  -d '{
    "path": "/v1/chat/completions",
    "target": "https://api.openai.com",
    "methods": ["POST"],
    "strip_path": true,
    "plugin_chain": [
      {
        "name": "rate_limiter",
        "enabled": true,
        "priority": 1,
        "stage": "pre_request",
        "settings": {
          "limit": 100,
          "window": "1m"
        }
      }
    ]
  }'
```

### Proxy API (Port 8081)

Forward requests through the proxy:
```bash
curl -X POST http://testcompany.example.com:8081/v1/chat/completions \
  -H "Authorization: Bearer {api_key}" \
  -H "Content-Type: application/json" \
  -H "X-Request-ID: req-123" \
  -d '{
    "model": "gpt-3.5-turbo",
    "messages": [{"role": "user", "content": "Hello!"}]
  }'
```

## Development

### Prerequisites
- Go 1.21+
- Docker and Docker Compose
- Redis

### Project Structure
```
.
├── cmd/
│   └── gateway/          # Application entry points
├── internal/
│   ├── cache/           # Redis cache implementation
│   ├── middleware/      # HTTP middleware
│   ├── plugins/         # Plugin implementations
│   ├── proxy/           # Request forwarding logic
│   ├── types/           # Common types
│   └── server/          # HTTP server implementation
├── scripts/             # Development and test scripts
├── config.yaml          # Configuration file
└── docker-compose.yaml  # Redis setup
```

### Testing

Run all tests:
```bash
./scripts/test.sh
```

Run specific tests:
```bash
./scripts/test_tenant.sh    # Test tenant management
./scripts/test_rate_limiter.sh  # Test rate limiting
```

### Plugin System

Available plugins:
- `rate_limiter`: Rate limiting functionality
- `content_validator`: Request/response content validation
- `security_validator`: Security checks and validations

Plugin stages:
- `pre_request`: Before forwarding
- `post_request`: After forwarding, before response
- `pre_response`: Before sending response
- `post_response`: After sending response

### Parallel Plugin Execution

The plugin system supports both sequential and parallel execution of plugins. This is controlled through two mechanisms:

1. **Priority Levels**: Plugins are executed in order of their priority (lower numbers run first)
2. **Parallel Flag**: Plugins with the same priority can run in parallel if configured to do so

#### Example Configuration:
```json
"plugin_chain": [
    {
        "name": "rate_limiter",
        "enabled": true,
        "parallel": false,  // Must run sequentially
        "priority": 1      // Runs first
    },
    {
        "name": "external_validator",
        "enabled": true,
        "parallel": true,   // Can run in parallel
        "priority": 2      // Runs after rate_limiter
    },
    {
        "name": "content_validator",
        "enabled": true,
        "parallel": true,   // Can run in parallel
        "priority": 2      // Runs alongside external_validator
    }
]
```

#### Execution Flow:
1. Plugins are grouped by priority
2. Each priority group is executed in order (lowest to highest)
3. Within each priority group:
   - If there's only one plugin, it runs sequentially
   - If there are multiple plugins and they support parallel execution, they run concurrently

#### Plugin Types:
- **Sequential Plugins** (parallel: false):
  - Need to maintain state
  - Order-dependent operations
  - Example: Rate Limiter

- **Parallel Plugins** (parallel: true):
  - Stateless operations
  - Order-independent
  - Example: External Validators

This design allows for optimal performance by running independent operations concurrently while maintaining necessary ordering constraints.
