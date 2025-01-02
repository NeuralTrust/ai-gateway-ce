#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Test configuration
ADMIN_URL=${ADMIN_URL:-"http://localhost:8080/api/v1"}
PROXY_URL=${PROXY_URL:-"http://localhost:8081"}
BASE_DOMAIN=${BASE_DOMAIN:-"example.com"}
SUBDOMAIN="balancer-$(date +%s)"
GATEWAY_ID=""
API_KEY=""

# Initialize counters for providers
openai_count=0
anthropic_count=0
total_requests=100

echo -e "${GREEN}1. Creating test gateway with multiple providers...${NC}"

# First create an upstream
UPSTREAM_RESPONSE=$(curl -s -X POST "$ADMIN_URL/upstreams" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "ai-providers-upstream",
        "algorithm": "weighted-round-robin",
        "targets": [
            {
                "provider": "openai",
                "weight": 70,
                "models": ["gpt-3.5-turbo", "gpt-4"],
                "credentials": {
                    "header_name": "Authorization",
                    "header_value": "Bearer sk-openai-key"
                }
            },
            {
                "provider": "anthropic",
                "weight": 20,
                "models": ["claude-2", "claude-instant-1"],
                "credentials": {
                    "header_name": "x-api-key",
                    "header_value": "sk-anthropic-key"
                }
            }
        ]
    }')

UPSTREAM_ID=$(echo "$UPSTREAM_RESPONSE" | jq -r '.id')

# Then create a service that uses this upstream
SERVICE_RESPONSE=$(curl -s -X POST "$ADMIN_URL/services" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "ai-chat-service",
        "type": "ai",
        "description": "Load balanced AI chat completion service",
        "upstream_id": "'"$UPSTREAM_ID"'",
        "path": "/v1/chat/completions",
        "retries": 3,
        "tags": ["ai", "chat"]
    }')

SERVICE_ID=$(echo "$SERVICE_RESPONSE" | jq -r '.id')

# Finally create a gateway with a forwarding rule that points to the service
GATEWAY_RESPONSE=$(curl -s -X POST "$ADMIN_URL/gateways" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "'"$GATEWAY_NAME"'",
        "subdomain": "'"$SUBDOMAIN"'",
        "forwarding_rules": [
            {
                "path": "/chat",
                "service_id": "'"$SERVICE_ID"'",
                "methods": ["POST"],
                "strip_path": true,
                "active": true
            }
        ]
    }')

# Extract gateway ID and API key
GATEWAY_ID=$(echo "$GATEWAY_RESPONSE" | jq -r '.id')

if [ -z "$GATEWAY_ID" ] || [ "$GATEWAY_ID" = "null" ]; then
    echo -e "${RED}Failed to create gateway. Response: $GATEWAY_RESPONSE${NC}"
    exit 1
fi

echo "Gateway ID: $GATEWAY_ID"

# 2. Create API key
echo -e "\n${GREEN}2. Creating API key...${NC}"
API_KEY_RESPONSE=$(curl -s -X POST "$ADMIN_URL/gateways/$GATEWAY_ID/keys" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test Key",
    "expires_at": "2026-01-01T00:00:00Z"
}')

API_KEY=$(echo "$API_KEY_RESPONSE" | jq -r '.key')

if [ "$API_KEY" == "null" ] || [ -z "$API_KEY" ]; then
    echo -e "${RED}Failed to create API key. Response: $API_KEY_RESPONSE${NC}"
    exit 1
fi

echo "API Key created: $API_KEY"
# Wait for configuration to propagate
sleep 2

echo -e "\n${GREEN}2. Testing provider load balancing...${NC}"
for i in $(seq 1 $total_requests); do
    # Alternate between models to test both providers
    if [ $((i % 2)) -eq 0 ]; then
        MODEL="gpt-3.5-turbo"
    else
        MODEL="claude-2"
    fi
    
    # Make request and capture response headers
    RESPONSE_HEADERS=$(curl -s -D - -X POST "http://$PROXY_URL/v1/chat/completions" \
        -H "Content-Type: application/json" \
        -H "Host: $SUBDOMAIN.$BASE_DOMAIN" \
        -H "Authorization: Bearer $API_KEY" \
        -d '{
            "model": "'"$MODEL"'",
            "messages": [{"role": "user", "content": "Hello"}]
        }' 2>&1)
    
    # Extract the selected provider from response headers
    SELECTED_PROVIDER=$(echo "$RESPONSE_HEADERS" | grep -i "X-Selected-Provider" | cut -d' ' -f2 | tr -d '\r')
    
    # Update counters
    case $SELECTED_PROVIDER in
        "openai")
            ((openai_count++))
            echo -n "O"
            ;;
        "anthropic")
            ((anthropic_count++))
            echo -n "A"
            ;;
        *)
            echo -n "?"
            ;;
    esac
    
    # Add newline every 10 requests for readability
    if [ $((i % 10)) -eq 0 ]; then
        echo ""
    fi
done

echo -e "\n\n${GREEN}3. Results:${NC}"
echo "Total requests: $total_requests"
echo "OpenAI requests: $openai_count ($(echo "scale=1; $openai_count * 100 / $total_requests" | bc)%)"
echo "Anthropic requests: $anthropic_count ($(echo "scale=1; $anthropic_count * 100 / $total_requests" | bc)%)"

# Clean up
echo -e "\n${GREEN}4. Cleaning up...${NC}"
curl -s -X DELETE "$ADMIN_URL/gateways/$GATEWAY_ID" > /dev/null
echo "Gateway deleted" 