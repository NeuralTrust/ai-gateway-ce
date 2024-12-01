#!/bin/bash

# Start the server
go run cmd/gateway/main.go &
SERVER_PID=$!

# Wait for server to start
sleep 2

# Test health endpoint
echo "Testing health endpoint..."
curl -i http://localhost:8080/health

# Test forwarding rules endpoints with valid tenant
echo -e "\n\nTesting forwarding rules with valid tenant..."
curl -i -H "Host: tenant1.example.com" http://localhost:8080/api/v1/forwarding-rules

# Test forwarding rules endpoints with invalid tenant
echo -e "\n\nTesting forwarding rules with invalid tenant..."
curl -i -H "Host: invalid@.example.com" http://localhost:8080/api/v1/forwarding-rules

# Cleanup
kill $SERVER_PID 