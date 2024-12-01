# AI Gateway

A multi-tenant API Gateway designed to forward and manage API requests with support for multiple backends, AI model providers, and a powerful plugin system.

## Features

- Multi-tenant support via subdomains
- Dynamic forwarding rules
- Plugin system with parallel execution support
- Custom headers and authentication
- Path rewriting
- Request retry mechanism
- Redis-based rule storage
- Health checks

## Plugin System

The gateway includes a powerful plugin system that allows for request/response modification and validation. Plugins can be executed in parallel and can access specific fields of the request.

### Available Plugins

#### 1. Content Validator
Validates request content type and size.

```json
{
  "name": "content_validator",
  "enabled": true,
  "stage": "pre_request",
  "priority": 1,
  "parallel": true,
  "settings": {
    "allowed_types": ["application/json"],
    "max_size": 1048576,
    "fields": ["messages", "model"] // Optional: specific fields to validate
  }
} 
```

#### 2. Security Validator
Validates headers and IP addresses.

```json
{
    "name": "security_validator",
    "enabled": true,
    "stage": "pre_request",
    "priority": 1,
    "parallel": true,
    "settings": {
        "required_headers": ["Authorization", "X-Request-ID"],
        "blocked_ips": ["192.168.1.100"],
        "fields": ["api_key", "user_id"]  // Optional: specific fields to validate
    }
}
```

#### 3. External Validator
Forwards request data to an external validation service.

```json
{
    "name": "external_validator",
    "enabled": true,
    "stage": "pre_request",
    "priority": 1,
    "parallel": true,
    "settings": {
        "endpoint": "https://your-validator-api.com/validate",
        "auth_header": "Bearer your-validator-api-key",
        "timeout": "5s",
        "retry_count": 2,
        "fields": ["messages", "model"]  // Optional: specific fields to validate
    }
}
```

### Plugin Configuration Options

- `name`: Plugin identifier
- `enabled`: Enable/disable the plugin
- `stage`: Execution stage (pre_request, post_request, pre_response, post_response)
- `priority`: Execution order (lower numbers run first)
- `parallel`: Whether the plugin can run in parallel with others
- `settings`: Plugin-specific configuration
- `fields`: Specific fields to process (optional)

### Plugin Execution Stages

1. `pre_request`: Before forwarding the request
2. `post_request`: After preparing the forward request but before sending
3. `pre_response`: After receiving the response but before processing
4. `post_response`: Before sending the response back to the client

## Example Usage

### Creating a Forwarding Rule with Multiple Plugins

```bash
curl -X POST -H "Host: tenant1.example.com" \
  -H "Content-Type: application/json" \
  -d '{
    "path": "/v1/chat/completions",
    "target": "https://api.openai.com",
    "methods": ["POST"],
    "strip_path": false,
    "headers": {
      "Authorization": "Bearer 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"
    },
    "plugin_chain": [
        {
            "name": "content_validator",
            "enabled": true,
            "stage": "pre_request",
            "priority": 1,
            "settings": {
                "allowed_types": ["application/json"],
                "max_size": 1048576,
                "fields": ["messages", "model"]
            }
        }
    ]
  }' \
  http://localhost:8080/api/v1/forwarding-rules
```

### Testing the Rule

```bash
curl -X POST -H "Host: tenant1.example.com" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your-key" \
  -d '{
    "model": "gpt-4o-mini",
    "messages": [
        {"role": "user", "content": "Hello!"}
    ],
    "temperature": 0.7
  }' \
  http://localhost:8080/v1/chat/completions
```

## Plugin Development

Plugins must implement the Plugin interface:

```go
type Plugin interface {
    Name() string
    Priority() int
    Stage() ExecutionStage
    Parallel() bool
    ProcessRequest(ctx context.Context, reqCtx *RequestContext) error
    ProcessResponse(ctx context.Context, respCtx *ResponseContext) error
}
```

See the existing plugins in `internal/plugins/` for implementation examples.

## Configuration

Create a `config.yaml` file:

```yaml
server:
  port: 8080
  base_domain: "example.com"

redis:
  host: "localhost"
  port: 6379
  password: ""
  db: 0
```

## Development

### Prerequisites

- Go 1.21 or later
- Redis
- Make (optional)

### Project Structure

```
.
├── cmd/
│   └── gateway/          # Application entry point
├── internal/
│   ├── cache/           # Redis cache implementation
│   ├── middleware/      # HTTP middleware
│   ├── plugins/         # Plugin implementations
│   ├── proxy/           # Request forwarding logic
│   ├── rules/           # Forwarding rules
│   └── server/          # HTTP server implementation
├── pkg/
│   └── utils/           # Shared utilities
├── config.yaml          # Configuration file
└── go.mod              # Go module file
```

## Rate Limiting Options

The gateway supports advanced rate limiting configurations through the rate_limiter plugin.

### 1. Tiered Rate Limiting

Configure different rate limits for different service tiers:

```json
{
  "name": "rate_limiter",
  "enabled": true,
  "stage": "pre_request",
  "priority": 1,
  "parallel": true,
  "settings": {
    "tiers": {
      "tier1": {
        "limit": 100,
        "duration": "1m"
      },
      "tier2": {
        "limit": 200,
        "duration": "1m"
      }
    },
    "default_tier": "tier1",
    "limit_types": ["requests", "bandwidth"],
    "dynamic": true,
    "quota": 1000,
    "actions": {
      "tier1": {
        "requests": 100,
        "bandwidth": 1048576
      },
      "tier2": {
        "requests": 200,
        "bandwidth": 2097152
      }
    }
  }
}
```

### 2. Rate Limit Types

Different types of rate limiting strategies:

```json
{
    "limit_types": {
        "global": false,
        "per_ip": true,
        "per_user": true,
        "per_method": true,
        "cost_based": true
    },
    "endpoint_costs": {
        "/v1/chat/completions": 2,
        "/v1/embeddings": 1,
        "/v1/moderations": 0.5
    }
}
```

### 3. Dynamic Rate Limiting

Automatically adjust rate limits based on system load:

```json
{
    "dynamic": {
        "auto_scale": true,
        "concurrency_max": 100,
        "error_threshold": 0.05,
        "load_factor": 0.75
    }
}
```

### 4. Quota Management

Manage long-term usage quotas:

```json
{
    "quota": {
        "daily": 1000,
        "monthly": 25000,
        "rollover": true,
        "reset_time": "00:00 UTC"
    }
}
```

### 5. Rate Limit Actions

Configure actions when limits are exceeded:

```json
{
    "actions": {
        "on_exceeded": "degrade",
        "retry_after": "60s",
        "fallback_service": "https://backup-api.example.com",
        "alert_threshold": 80,
        "notification_webhook": "https://alerts.example.com/webhook"
    }
}
```

### Example Usage

Create a forwarding rule with rate limiting:

```bash
curl -X POST -H "Host: tenant1.example.com" \
  -H "Content-Type: application/json" \
  -d '{
    "path": "/v1/chat/completions",
    "target": "https://api.openai.com",
    "plugin_chain": [
        {
            "name": "rate_limiter",
            "enabled": true,
            "settings": {
                "tiers": {
                    "enterprise": {
                        "limit": 1000,
                        "window": "1h",
                        "burst": 50
                    }
                },
                "default_tier": "enterprise",
                "limit_types": {
                    "per_ip": true,
                    "cost_based": true
                },
                "endpoint_costs": {
                    "/v1/chat/completions": 2
                },
                "dynamic": {
                    "auto_scale": true,
                    "concurrency_max": 100
                },
                "quota": {
                    "daily": 10000,
                    "monthly": 250000
                },
                "actions": {
                    "on_exceeded": "degrade",
                    "fallback_service": "https://backup-api.example.com"
                }
            }
        }
    ]
  }' \
  http://localhost:8080/api/v1/forwarding-rules
```

### Rate Limiting Features

1. **Tiered Rate Limiting**
   - Different limits for different service tiers
   - Burst allowance for handling spikes
   - Configurable time windows

2. **Rate Limit Types**
   - Global limits across all endpoints
   - Per-IP address limiting
   - Per-user limiting
   - Method-specific limits
   - Cost-based limiting for different endpoints

3. **Dynamic Rate Limiting**
   - Auto-scaling based on system load
   - Concurrency control
   - Error rate monitoring
   - Load-based adjustments

4. **Quota Management**
   - Daily and monthly quotas
   - Quota rollover options
   - Configurable reset times
   - Usage tracking

5. **Rate Limit Actions**
   - Multiple action types (block, delay, degrade)
   - Retry-After header support
   - Fallback service configuration
   - Alert thresholds
   - Webhook notifications
