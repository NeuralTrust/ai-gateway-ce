# AI Gateway CE

<div align="center">

[![Go Report Card](https://goreportcard.com/badge/github.com/NeuralTrust/ai-gateway-ce)](https://goreportcard.com/report/github.com/NeuralTrust/ai-gateway-ce)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/NeuralTrust/ai-gateway-ce.svg)](https://pkg.go.dev/github.com/NeuralTrust/ai-gateway-ce)
[![Docker Pulls](https://img.shields.io/docker/pulls/neuraltrust/ai-gateway-ce.svg)](https://hub.docker.com/r/neuraltrust/ai-gateway-ce)
[![Discord](https://img.shields.io/discord/1234567890?color=7289da&label=discord)](https://discord.gg/JGV4q3tr)

<img src="assets/ai-gateway.svg" alt="AI Gateway Logo" width="500"/>

*A powerful, AI Gateway designed from scratch for AI*

[Documentation](https://docs.neuraltrust.ai) |
[Quick Start](https://docs.neuraltrust.ai/category/step-by-step-guide) |
[Community](https://discord.gg/JGV4q3tr)

</div>

## ✨ Features

- 🚀 **High Performance**: Built in Go for maximum efficiency and minimal latency
- 🔄 **Load Balancing**: Advanced algorithms including round-robin, weighted round-robin, and IP hash
- 🔒 **Security**: Built-in authentication, rate limiting, and token management
- 🔌 **Plugin System**: Extensible architecture for custom functionality
- ⚡ **Real-time Config**: Dynamic configuration without restarts
- 🌐 **Multi-gateway**: Complete isolation between different gateways
- 🤖 **AI-Ready**: Optimized for AI model providers (OpenAI, Anthropic, etc.)

## 🚀 Quick Start

### Using Docker Compose

```bash
# Clone the repository
git clone https://github.com/NeuralTrust/ai-gateway-ce.git
cd ai-gateway-ce

# Start the services
docker compose -f docker-compose.prod.yaml up -d
```

### Using Kubernetes

```bash
# Apply configurations
kubectl apply -f k8s/storage.yaml
kubectl apply -f k8s/deployment.yaml
```

### Local Development

```bash
# Start dependencies
docker compose up -d redis postgres

# Run the servers
./scripts/run_local.sh
```

## 🏗️ Architecture

AI Gateway CE consists of two main components:

1. **Admin API** (Port 8080)
   - Tenant management
   - Configuration management
   - API key management
   - Plugin configuration

2. **Proxy API** (Port 8081)
   - Request routing
   - Load balancing
   - Plugin execution

## 🔌 Plugin System

Extend functionality with plugins:

```go
type Plugin interface {
    Name() string
    Execute(ctx *Context) error
    Configure(config map[string]interface{}) error
}
```

Built-in plugins:
- Rate Limiter
- Token Rate Limiter
- External API Call

## 🤝 Contributing

We love contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Open a Pull Request

## 📜 License

AI Gateway CE is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## 🌟 Star History

[![Star History Chart](https://api.star-history.com/svg?repos=neuraltrust/ai-gateway-ce&type=Date)](https://star-history.com/#neuraltrust/ai-gateway-ce&Date)

## 📫 Community & Support

- [Documentation](https://docs.neuraltrust.ai)
- [Discord Community](https://discord.gg/neuraltrust)
- [GitHub Issues](https://github.com/neuraltrust/ai-gateway-ce/issues)
- [Twitter](https://twitter.com/neuraltrust)
- [Blog](https://neuraltrust.ai/blog)

---

<div align="center">
Made with ❤️ by <a href="https://neuraltrust.ai">NeuralTrust</a>
</div>
