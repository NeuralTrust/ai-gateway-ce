#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

# Check if hey is installed
if ! command -v hey &> /dev/null; then
    echo -e "${RED}Error: 'hey' is not installed${NC}"
    echo "Installing hey..."
    export PATH=$PATH:$(go env GOPATH)/bin
    go install github.com/rakyll/hey@latest
    if ! command -v hey &> /dev/null; then
        echo -e "${RED}Failed to install hey. Please install it manually:${NC}"
        echo "go install github.com/rakyll/hey@latest"
        echo "And make sure your GOPATH/bin is in your PATH"
        exit 1
    fi
fi

# Configuration
ADMIN_URL=${ADMIN_URL:-"http://localhost:8080/api/v1"}
PROXY_URL=${PROXY_URL:-"http://localhost:8081"}
CONCURRENT_USERS=50
TOTAL_REQUESTS=10000
DURATION="30s"

echo -e "${BLUE}AI Gateway Benchmark Tool${NC}\n"

# Test 1: System endpoint (ping)
echo -e "${GREEN}Testing system ping endpoint...${NC}"
echo -e "\n${BLUE}Starting system benchmark with ${CONCURRENT_USERS} concurrent users for ${DURATION}...${NC}"
hey -z ${DURATION} \
    -c ${CONCURRENT_USERS} \
    -disable-keepalive \
    -cpus 2 \
    "${PROXY_URL}/__/ping"

# Create test tenant first
echo -e "${GREEN}Creating test tenant...${NC}"
TENANT_RESPONSE=$(curl -s -X POST "$ADMIN_URL/tenants" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Benchmark Tenant",
    "subdomain": "benchmark",
    "tier": "premium"
  }')

TENANT_ID=$(echo $TENANT_RESPONSE | jq -r '.id')
API_KEY=$(echo $TENANT_RESPONSE | jq -r '.api_key')

echo -e "Tenant ID: $TENANT_ID"
echo -e "API Key: $API_KEY"

# Create forwarding rule
echo -e "${GREEN}Creating forwarding rule...${NC}"
RULE_RESPONSE=$(curl -s -X POST "$ADMIN_URL/tenants/$TENANT_ID/rules" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "path": "/test",
    "target": "http://localhost:8081/__/ping",
    "methods": ["GET"],
    "strip_path": true,
    "public": true
  }')

# Verify the rule was created
echo -e "Rule Response: $RULE_RESPONSE"

# Test 2: Forwarded ping endpoint
echo -e "${GREEN}Testing forwarded ping endpoint...${NC}"
echo -e "\n${BLUE}Starting forwarded benchmark with ${CONCURRENT_USERS} concurrent users for ${DURATION}...${NC}"
hey -z ${DURATION} \
    -c ${CONCURRENT_USERS} \
    -disable-keepalive \
    -cpus 2 \
    -host "benchmark.example.com" \
    "${PROXY_URL}/test"
