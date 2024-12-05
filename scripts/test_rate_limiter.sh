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
    "subdomain": "ratelimited6",
    "tier": "basic",
    "enabled_plugins": ["rate_limiter"]
  }')

# Extract fields from response
GATEWAY_ID=$(echo $GATEWAY_RESPONSE | jq -r '.ID // .id')
SUBDOMAIN=$(echo $GATEWAY_RESPONSE | jq -r '.Subdomain // .subdomain')
API_KEY=$(echo $GATEWAY_RESPONSE | jq -r '.ApiKey // .api_key')

# Check if we got valid values
if [ -z "$GATEWAY_ID" ] || [ "$GATEWAY_ID" = "null" ]; then
    echo -e "${RED}Failed to get gateway ID. Response: $GATEWAY_RESPONSE${NC}"
    exit 1
fi

if [ -z "$API_KEY" ] || [ "$API_KEY" = "null" ]; then
    echo -e "${RED}Failed to get API key. Response: $GATEWAY_RESPONSE${NC}"
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
echo -e "API Key: $API_KEY"
echo -e "Status: $STATUS\n"

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
            "priority": 0,
            "stage": "",
            "parallel": false,
            "settings": {
                "limits": {
                    "global": {
                        "limit": 10,
                        "window": "1m"
                    },
                    "per_ip": {
                        "limit": 5,
                        "window": "1m"
                    },
                    "per_user": {
                        "limit": 3,
                        "window": "1m"
                    }
                },
                "limit_types": {
                    "global": true,
                    "per_ip": true,
                    "per_user": true
                }
            }
        }
    ]
}'

echo -e "Request URL: $ADMIN_URL/gateways/$GATEWAY_ID/rules"
echo -e "Gateway ID: $GATEWAY_ID"
echo -e "API Key: $API_KEY"
echo -e "Request body: $RULE_REQUEST\n"

# Create a temporary file for the response
TMPFILE=$(mktemp)

# Make the request and save verbose output to stderr
curl -v -X POST "$ADMIN_URL/gateways/$GATEWAY_ID/rules" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d "$RULE_REQUEST" 2>"$TMPFILE.verbose" >"$TMPFILE.response"

# Show verbose output
echo -e "\nVerbose output:"
cat "$TMPFILE.verbose"

# Get the response
RULE_RESPONSE=$(cat "$TMPFILE.response")
echo -e "\nResponse body:"
echo "$RULE_RESPONSE"

# Clean up temp files
rm -f "$TMPFILE.verbose" "$TMPFILE.response"

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
        -H "X-Forwarded-For: 1.2.3.$i" \
        "${PROXY_URL}/test")
    
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n 1)
    if [ "$http_code" == "200" ]; then
        echo -e "${GREEN}Request $i: Success${NC}"
    else
        echo -e "${RED}Request $i: Rate Limited (${http_code})${NC}"
        echo "Response: $body"
    fi
done

# 4. Test Per-IP Rate Limit (limit: 5 per minute)
echo -e "\n${GREEN}Testing Per-IP Rate Limit (5 requests/minute)${NC}"
echo -e "Making 6 requests from same IP..."
for i in {1..6}; do
    response=$(curl -s -w "\n%{http_code}" \
        -H "Host: ${SUBDOMAIN}.${BASE_DOMAIN}" \
        -H "Authorization: Bearer ${API_KEY}" \
        -H "X-Forwarded-For: 1.2.3.4" \
        "${PROXY_URL}/test")
    
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n 1)
    echo -e "Request $i - Status: $http_code"
    if [ "$http_code" != "200" ]; then
        echo "Response: $body"
    fi
done

# 5. Test Per-User Rate Limit (limit: 3 per minute)
echo -e "\n${GREEN}Testing Per-User Rate Limit (3 requests/minute)${NC}"
echo -e "Making 4 requests as same user..."
for i in {1..4}; do
    response=$(curl -s -w "\n%{http_code}" \
        -H "Host: ${SUBDOMAIN}.${BASE_DOMAIN}" \
        -H "Authorization: Bearer ${API_KEY}" \
        -H "X-User-ID: test-user" \
        "${PROXY_URL}/test")
    
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n 1)
    echo -e "Request $i - Status: $http_code"
    if [ "$http_code" != "200" ]; then
        echo "Response: $body"
    fi
done

echo -e "\n${GREEN}Rate limiter tests completed${NC}"