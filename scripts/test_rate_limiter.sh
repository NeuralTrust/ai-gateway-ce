#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# Use environment variables or defaults
ADMIN_URL=${ADMIN_URL:-"http://localhost:8080/api/v1"}
PROXY_URL=${PROXY_URL:-"http://localhost:8081"}
BASE_DOMAIN=${BASE_DOMAIN:-"example.com"}

echo -e "${GREEN}Testing Rate Limiter${NC}\n"

# 1. Create a gateway with rate limiting
echo -e "${GREEN}1. Creating gateway with rate limiting...${NC}"
GATEWAY_RESPONSE=$(curl -s -X POST "$ADMIN_URL/gateways" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Rate Limited Company",
    "subdomain": "ratelimited27",
    "tier": "basic",
    "enabled_plugins": ["rate_limiter"]
  }')

# Extract fields from response
GATEWAY_ID=$(echo $GATEWAY_RESPONSE | jq -r '.ID // .id')
SUBDOMAIN=$(echo $GATEWAY_RESPONSE | jq -r '.Subdomain // .subdomain')

# Check if we got valid values
if [ -z "$GATEWAY_ID" ] || [ "$GATEWAY_ID" = "null" ]; then
    echo -e "${RED}Failed to get gateway ID. Response: $GATEWAY_RESPONSE${NC}"
    exit 1
fi

if [ -z "$SUBDOMAIN" ] || [ "$SUBDOMAIN" = "null" ]; then
    echo -e "${RED}Failed to get subdomain. Response: $GATEWAY_RESPONSE${NC}"
    exit 1
fi

# Check gateway status
STATUS=$(echo $GATEWAY_RESPONSE | jq -r '.Status // .status')
if [ "$STATUS" != "active" ]; then
    echo -e "${RED}Gateway is not active. Status: $STATUS${NC}"
    exit 1
fi

echo -e "${GREEN}Successfully created gateway:${NC}"
echo -e "Gateway ID: $GATEWAY_ID"
wait 2
# Create API key for the gateway
echo -e "${GREEN}Creating API key for the gateway...${NC}"
API_KEY_RESPONSE=$(curl -s -X POST "$ADMIN_URL/gateways/$GATEWAY_ID/keys" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test Rate Limiter Key",
    "expires_at": null
  }')
echo "API Key Response: $API_KEY_RESPONSE"
# Extract API key from response
API_KEY=$(echo $API_KEY_RESPONSE | jq -r '.key')

# Check if we got a valid API key
if [ -z "$API_KEY" ] || [ "$API_KEY" = "null" ]; then
    echo -e "${RED}Failed to get API key. Response: $API_KEY_RESPONSE${NC}"
    exit 1
fi

echo -e "${GREEN}Successfully created API key:${NC}"
echo -e "API Key: $API_KEY\n"

# 2. Create forwarding rule with rate limiter
echo -e "${GREEN}2. Creating forwarding rule...${NC}"

# Prepare the request body
RULE_REQUEST='{
    "path": "/test",
    "target": "https://httpbin.org/get",
    "methods": ["GET"],
    "strip_path": true,
    "plugin_chain": [
        {
            "name": "rate_limiter",
            "enabled": true,
            "stage": "pre_request",
            "parallel": false,
            "settings": {
                "limits": {
                    "global": {
                        "limit": 10,
                        "window": "1m"
                    }
                },
                "limit_types": {
                    "global": true
                },
                "actions": {
                    "type": "block",
                    "retry_after": "60"
                }
            }
        }
    ]
}'

# Make the request and capture the response
RULE_RESPONSE=$(curl -s -X POST "$ADMIN_URL/gateways/$GATEWAY_ID/rules" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d "$RULE_REQUEST")

echo "Rule Response: $RULE_RESPONSE"

# Check if rule creation was successful
if [[ "$RULE_RESPONSE" == *"error"* ]]; then
    echo -e "${RED}Failed to create rule. Response: $RULE_RESPONSE${NC}"
    exit 1
fi

RULE_ID=$(echo "$RULE_RESPONSE" | jq -r '.id')
if [ -z "$RULE_ID" ] || [ "$RULE_ID" = "null" ]; then
    echo -e "${RED}Failed to get rule ID from response${NC}"
    exit 1
fi

echo -e "${GREEN}Successfully created rule with ID: $RULE_ID${NC}\n"

# Add a small delay to ensure rule propagation
sleep 2

# 3. Test Global Rate Limit (limit: 10 per minute)
echo -e "\n${GREEN}Testing Global Rate Limit (10 requests/minute)${NC}"
echo -e "Making 12 requests (should see rate limit after 10)..."
for i in {1..12}; do
    response=$(curl -s -w "\n%{http_code}" \
        -H "Host: ${SUBDOMAIN}.${BASE_DOMAIN}" \
        -H "Authorization: Bearer ${API_KEY}" \
        -H "X-Forwarded-For: 1.2.3.4" \
        "${PROXY_URL}/test")
    
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n 1)
    if [ "$http_code" == "200" ]; then
        echo -e "${GREEN}Request $i: Success${NC}"
    else
        echo -e "${RED}Request $i: Rate Limited (${http_code})${NC}"
        echo "Response: $body"
    fi
    sleep 0.1  # Small delay to ensure proper order
done

echo -e "\n${GREEN}Rate limiter tests completed${NC}"