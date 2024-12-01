## Running the Gateway

```bash
Start Redis (required)
redis-server
Run the gateway
go run cmd/gateway/main.go
```

## API Examples

### 1. Managing Forwarding Rules

#### Create a Rule

```bash
curl -X POST -H "Host: tenant1.example.com" \
  -H "Content-Type: application/json" \
  -d '{
    "path": "/v1/chat",
    "target": "https://api.openai.com",
    "methods": ["POST"],
    "headers": {
      "Authorization": "Bearer your-api-key-here"
    },
    "strip_path": false
  }' \
  http://localhost:8080/api/v1/forwarding-rules
```

#### List Rules

```bash
curl -H "Host: tenant1.example.com" \
  http://localhost:8080/api/v1/forwarding-rules
```

#### Update a Rule

```bash
curl -X PUT -H "Host: tenant1.example.com" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://api.anthropic.com",
    "active": true
  }' \
  http://localhost:8080/api/v1/forwarding-rules/{rule_id}
```

#### Delete a Rule

```bash
curl -X DELETE -H "Host: tenant1.example.com" \
  http://localhost:8080/api/v1/forwarding-rules/{rule_id}
```

### 2. Example Use Cases

#### AI Model Provider Forwarding

```bash
# Create OpenAI forwarding rule
curl -X POST -H "Host: tenant1.example.com" \
  -H "Content-Type: application/json" \
  -d '{
    "path": "/v1/chat/completions",
    "target": "https://api.openai.com",
    "methods": ["POST"],
    "headers": {
      "Authorization": "Bearer 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"
    },
    "strip_path": false
  }' \
  http://localhost:8080/api/v1/forwarding-rules

# Use the forwarding rule
curl -X POST -H "Host: tenant1.example.com" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4o-mini",
    "messages": [{"role": "user", "content": "Hello!"}]
  }' \
  http://localhost:8080/v1/chat/completions
```

#### Generic API Forwarding

```bash
# Create weather API forwarding rule
curl -X POST -H "Host: tenant1.example.com" \
  -H "Content-Type: application/json" \
  -d '{
    "path": "/api/weather",
    "target": "https://api.weatherapi.com/v1",
    "methods": ["GET"],
    "headers": {
      "key": "your-weather-api-key"
    },
    "strip_path": true
  }' \
  http://localhost:8080/api/v1/forwarding-rules

# Use the forwarding rule
curl -H "Host: tenant1.example.com" \
  http://localhost:8080/api/weather/current.json?q=London
```

#### Internal Service Forwarding

```bash
# Create internal service forwarding rule
curl -X POST -H "Host: tenant1.example.com" \
  -H "Content-Type: application/json" \
  -d '{
    "path": "/internal/users",
    "target": "http://user-service:8080/users",
    "methods": ["GET", "POST", "PUT", "DELETE"],
    "preserve_host": true,
    "retry_attempts": 3
  }' \
  http://localhost:8080/api/v1/forwarding-rules

# Use the forwarding rule
curl -H "Host: tenant1.example.com" \
  http://localhost:8080/internal/users
```

## Forwarding Rule Options

- `path`: Base path to match (required)
- `target`: Target URL to forward requests to (required)
- `methods`: Array of allowed HTTP methods
- `headers`: Map of headers to add to forwarded requests
- `strip_path`: Remove the base path when forwarding (default: true)
- `preserve_host`: Keep original host header (default: false)
- `retry_attempts`: Number of retry attempts (default: 0)
- `active`: Enable/disable the rule (default: true)

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
│   ├── models/          # Data models
│   ├── proxy/           # Request forwarding logic
│   └── server/          # HTTP server implementation
├── pkg/
│   └── utils/           # Shared utilities
├── config.yaml          # Configuration file
└── go.mod              # Go module file
```

### Testing

```bash
# Run all tests
go test ./...

# Test specific package
go test ./internal/proxy
```

## License

MIT
```

This README provides:
1. Overview of the gateway features
2. Configuration instructions
3. Detailed API examples
4. Different use cases
5. Development setup
6. Project structure

Would you like me to add any additional sections or examples?
