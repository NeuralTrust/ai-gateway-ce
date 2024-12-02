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

## License

MIT