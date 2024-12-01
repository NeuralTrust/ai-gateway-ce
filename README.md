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
    "headers": {
      "Authorization": "Bearer your-api-key"
    },
    "plugin_chain": [
        {
            "name": "content_validator",
            "enabled": true,
            "stage": "pre_request",
            "priority": 1,
            "parallel": true,
            "settings": {
                "allowed_types": ["application/json"],
                "max_size": 1048576,
                "fields": ["messages", "model"]
            }
        },
        {
            "name": "security_validator",
            "enabled": true,
            "stage": "pre_request",
            "priority": 1,
            "parallel": true,
            "settings": {
                "required_headers": ["Authorization"],
                "fields": ["api_key"]
            }
        },
        {
            "name": "external_validator",
            "enabled": true,
            "stage": "pre_request",
            "priority": 2,
            "parallel": false,
            "settings": {
                "endpoint": "https://validator.example.com/check",
                "timeout": "5s",
                "fields": ["messages"]
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
    "model": "gpt-3.5-turbo",
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
