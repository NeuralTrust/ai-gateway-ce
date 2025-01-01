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

### Token Rate Limiter Plugin

The Token Rate Limiter plugin provides token-based rate limiting specifically designed for AI API requests. It tracks and limits token usage per request, making it ideal for services like OpenAI that use token-based billing.

#### Features
- **Pre-Request Token Check**: Validates if enough tokens are available before forwarding requests
- **Post-Response Token Tracking**: Accurately tracks actual token usage from API responses
- **Configurable Parameters**:
  - `tokens_per_request`: Default number of tokens consumed per request (used as fallback)
  - `tokens_per_minute`: Token replenishment rate per minute
  - `bucket_size`: Maximum number of tokens that can be accumulated

#### Token Calculation
1. **Pre-Request Stage**:
   - Checks if the token bucket has at least `tokens_per_request` tokens
   - Returns 429 error if insufficient tokens available

2. **Post-Response Stage**:
   - Extracts actual token usage from API response if available
   - Falls back to `tokens_per_request` if actual usage can't be determined
   - Updates token bucket and rate limit headers

#### Rate Limit Headers
The plugin sets the following headers in responses:
- `X-RateLimit-Remaining`: Current number of tokens available
- `X-RateLimit-Limit`: Maximum bucket size
- `X-RateLimit-Reset`: Unix timestamp when tokens will be replenished
- `X-Tokens-Consumed`: Number of tokens consumed by the request

## Token Rate Limiter Plugin

The token rate limiter plugin implements a token bucket algorithm to control the rate of requests and token consumption for LLM APIs. It tracks both request counts and token usage per API key.

### Configuration

```json
{
  "name": "token_rate_limiter",
  "enabled": true,
  "settings": {
    "tokens_per_request": 20,       // Default tokens to consume if can't get from response
    "tokens_per_minute": 100,       // Token replenishment rate per minute
    "bucket_size": 150000,          // Maximum tokens that can be accumulated
    "requests_per_minute": 60       // Maximum requests allowed per minute
  }
}
```

### Settings Description

- `tokens_per_request`: Default number of tokens to consume when actual token usage cannot be determined from the response
- `tokens_per_minute`: Number of tokens replenished per minute
- `bucket_size`: Maximum number of tokens that can be accumulated in the bucket
- `requests_per_minute`: Maximum number of requests allowed per minute

### Rate Limit Headers

The plugin adds the following headers to responses:

- `x-ratelimit-limit-requests`: Maximum requests allowed per minute
- `x-ratelimit-limit-tokens`: Maximum tokens allowed in bucket
- `x-ratelimit-remaining-requests`: Remaining requests for current minute
- `x-ratelimit-remaining-tokens`: Remaining tokens in bucket
- `x-ratelimit-reset-requests`: Seconds until request count resets
- `x-ratelimit-reset-tokens`: Seconds until next token replenishment
- `x-tokens-consumed`: Number of tokens consumed by the request

### Behavior

1. **Pre-Request Stage**:
   - Checks if enough tokens are available in the bucket
   - Verifies request count hasn't exceeded limit
   - Returns 429 status if either limit is exceeded

2. **Post-Response Stage**:
   - Extracts actual token usage from LLM response
   - Falls back to `tokens_per_request` if usage data unavailable
   - Updates token bucket and request count
   - Adds rate limit headers to response

### Token Bucket Algorithm

- Tokens are replenished at the rate of `tokens_per_minute`
- Request count resets every minute
- Both tokens and requests are tracked per API key
- Token bucket cannot exceed `bucket_size`
- Request count cannot exceed `requests_per_minute`

### Example Usage

```json
{
  "required_plugins": [
    {
      "name": "token_rate_limiter",
      "enabled": true,
      "settings": {
        "tokens_per_request": 20,
        "tokens_per_minute": 100,
        "bucket_size": 150000,
        "requests_per_minute": 60
      }
    }
  ]
}
```

This configuration allows:
- Maximum 60 requests per minute
- Token replenishment of 100 tokens per minute
- Maximum bucket size of 150,000 tokens
- Default consumption of 20 tokens per request

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

### Traffic Management

The gateway supports two methods of traffic distribution across multiple target endpoints:

#### Round-Robin Distribution
When multiple targets are specified without weights, requests are distributed evenly across all targets in a round-robin fashion. This is useful for basic load balancing.

Example rule with round-robin distribution:
```bash
curl -X POST http://localhost:8080/api/v1/tenants/{tenant_id}/rules \
  -H "Authorization: Bearer {api_key}" \
  -H "Content-Type: application/json" \
  -d '{
    "path": "/api/*",
    "targets": [
      {"url": "https://api1.example.com"},
      {"url": "https://api2.example.com"},
      {"url": "https://api3.example.com"}
    ],
    "methods": ["GET", "POST"],
    "strip_path": true
  }'
```

#### Weighted Distribution
For more precise traffic control, you can specify percentage-based weights. The weights must sum to 100%. This is particularly useful for:
- Canary deployments
- A/B testing
- Gradual traffic migration
- Blue/Green deployments

Example rule with weighted distribution:
```bash
curl -X POST http://localhost:8080/api/v1/tenants/{tenant_id}/rules \
  -H "Authorization: Bearer {api_key}" \
  -H "Content-Type: application/json" \
  -d '{
    "path": "/api/*",
    "targets": [
      {
        "url": "https://production.example.com",
        "weight": 90
      },
      {
        "url": "https://canary.example.com",
        "weight": 10
      }
    ],
    "methods": ["GET", "POST"],
    "strip_path": true
  }'
```

#### Implementation Details
- Uses Redis for distributed counter management
- Ensures consistent distribution across multiple gateway instances
- Automatically falls back to round-robin if weights don't sum to 100%
- Includes TTL on counters to prevent memory leaks
- Handles Redis failures gracefully with random selection fallback

### Rule Validation

When creating or updating rules, the following validations are applied:

#### Required Fields
- `path`: Must be non-empty
- `methods`: Must contain at least one valid HTTP method
- `targets`: Must contain at least one target

#### Target Validation
- Each target must have a valid URL
- When using weighted distribution:
  - All weights must be positive integers
  - Total weights must sum to 100%
  - If any target has a weight, all targets must have weights

Example with validation errors:
```bash
# Invalid: Weights don't sum to 100
curl -X POST http://localhost:8080/api/v1/tenants/{tenant_id}/rules \
  -H "Authorization: Bearer {api_key}" \
  -H "Content-Type: application/json" \
  -d '{
    "path": "/api/*",
    "targets": [
      {
        "url": "https://production.example.com",
        "weight": 80  # Error: weights sum to 80
      }
    ],
    "methods": ["GET"]
  }'

# Response:
{
    "error": "when using weighted distribution, weights must sum to 100 (got 80)"
}
```

#### Method Validation
Valid HTTP methods:
- GET
- POST
- PUT
- DELETE
- PATCH
- HEAD
- OPTIONS

#### Plugin Chain Validation
For each plugin in the chain:
- Name is required
- Stage must be one of:
  - pre_request
  - post_request
  - pre_response
  - post_response
- Priority must be between 0 and 999 (defaults to 0)
- Settings are required and validated per plugin type

Example plugin configuration:
```json
{
    "name": "external_validator",
    "enabled": true,
    "stage": "pre_request",
    "priority": 1,
    "settings": {
        "endpoint": "http://validator.example.com",
        "timeout": "5s"
    }
}
```

## Gateway Types and Configuration

The gateway supports two main types of configurations: `models` and `backends`.

### Models Gateway

Used for AI model providers like OpenAI and Anthropic. Automatically configures routing rules and handles authentication.

```json
{
  "name": "ai-models-gateway",
  "type": "models",
  "subdomain": "ai",
  "settings": {
    "traffic": [
      {"provider": "openai", "weight": 80},
      {"provider": "anthropic", "weight": 20}
    ],
    "providers": [{
      "name": "openai",
      "credentials": {
        "header_name": "Authorization",
        "header_value": "Bearer sk-..."
      },
      "fallback_provider": "anthropic",
      "fallback_credentials": {
        "header_name": "X-API-Key",
        "header_value": "sk-..."
      },
      "plugin_chain": ["rate-limiter", "logger"]
    }, {
      "name": "anthropic",
      "credentials": {
        "header_name": "X-API-Key",
        "header_value": "sk-..."
      }
    }]
  }
}
```

#### Traffic Distribution
- Configure multiple providers with weighted traffic distribution
- Weights must sum to 100
- Useful for cost optimization and reliability

#### Provider Configuration
- `name` - Provider identifier (e.g., "openai", "anthropic")
- `fallback_provider` - Backup provider if primary fails
- `plugin_chain` - Array of plugins to apply to this provider

### Backends Gateway

Used for routing to backend services with custom rules.

```json
{
  "name": "backend-gateway",
  "type": "backends",
  "subdomain": "api",
  "settings": {
    "forwarding_rules": [{
      "path": "/api/**",
      "targets": [{"url": "http://backend:8080"}],
      "methods": ["GET", "POST"],
      "strip_path": false,
      "preserve_host": false,
      "active": true
    }]
  }
}
```

### Authentication Options

#### Header-based Authentication
- `header_name` - Name of the authorization header (e.g., "Authorization", "X-API-Key")
- `header_value` - Value of the authorization header (e.g., "Bearer sk-...")

#### Parameter-based Authentication
- `param_name` - Name of the authentication parameter
- `param_value` - Value of the authentication parameter
- `param_location` - Location of the parameter ("query" or "body")

#### Azure Authentication
- `azure_use_managed_identity` - Use Azure Managed Identity (default: false)
- `azure_client_id` - Azure Client ID for user-assigned identity
- `azure_client_secret` - Azure Client Secret for user-assigned identity
- `azure_tenant_id` - Azure Tenant ID for user-assigned identity

#### GCP Authentication
- `gcp_use_service_account` - Use GCP Service Account (default: false)
- `gcp_service_account_json` - GCP Service Account JSON credentials

#### AWS Authentication
- `aws_access_key_id` - AWS Access Key ID for static credentials
- `aws_secret_access_key` - AWS Secret Access Key for static credentials

#### General Settings
- `allow_override` - Allow credentials to be overridden in requests (default: false)

### Automatic Rule Generation

For `models` type gateways, the following rules are automatically generated:

#### OpenAI
- `/v1/chat/completions` - Chat completions API
- `/v1/completions` - Completions API
- `/v1/embeddings` - Embeddings API

#### Anthropic
- `/v1/complete` - Complete API
- `/v1/messages` - Messages API

### Plugin Support

Both gateway types support plugins through the `plugin_chain` configuration:
- Rate limiting
- Logging
- Authentication
- Custom plugins can be added through the plugin interface

### Fallback Configuration

The gateway supports fallback targets for both gateway types:

#### Models Gateway Fallback
```json
{
  "settings": {
    "providers": [{
      "name": "openai",
      "credentials": {
        "header_name": "Authorization",
        "header_value": "Bearer sk-..."
      },
      "fallback_provider": "anthropic",
      "fallback_credentials": {
        "header_name": "X-API-Key",
        "header_value": "sk-..."
      }
    }]
  }
}
```

#### Backends Gateway Fallback
```json
{
  "settings": {
    "forwarding_rules": [{
      "path": "/api/**",
      "targets": [
        {"url": "http://primary:8080"}
      ],
      "fallback_targets": [
        {"url": "http://backup:8080"}
      ],
      "retry_attempts": 3
    }]
  }
}
```

#### Fallback Behavior
- Primary targets are tried first
- If primary fails after retry_attempts, fallback targets are used
- Fallback targets follow the same retry policy
- Headers and authentication are preserved for fallback requests
- Supports weighted distribution for fallback targets
