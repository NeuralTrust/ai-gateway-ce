# Build stage
FROM golang:1.22-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build binary
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/bin/ai-gateway-ce ./cmd/gateway/main.go

# Final stage
FROM alpine:latest

WORKDIR /app

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

# Copy binary and config files
COPY --from=builder /app/bin/ai-gateway-ce /app/
COPY config.yaml /app/
COPY config/providers.yaml /app/config/

# Expose ports
EXPOSE 8080 8081

# Set environment variables
ENV GIN_MODE=release

# Add entrypoint script
COPY scripts/docker-entrypoint.sh /app/
RUN chmod +x /app/docker-entrypoint.sh

ENTRYPOINT ["/app/docker-entrypoint.sh"] 