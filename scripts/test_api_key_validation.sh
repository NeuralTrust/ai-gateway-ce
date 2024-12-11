#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# Use environment variables or defaults
ADMIN_URL=${ADMIN_URL:-"http://localhost:8080/api/v1"}
PROXY_URL=${PROXY_URL:-"http://localhost:8081"}
BASE_DOMAIN=${BASE_DOMAIN:-"example.com"}

echo -e "${GREEN}Testing API Key Validation${NC}\n"

# 1. Create a gateway
echo -e "${GREEN}1. Creating gateway...${NC}"
GATEWAY_RESPONSE=$(curl -s -X POST "$ADMIN_URL/gateways" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "API Key Test Gateway",
    "subdomain": "apikey-test-26",
    "tier": "basic"
  }')

# Extract fields from response
GATEWAY_ID=$(echo $GATEWAY_RESPONSE | jq -r '.ID // .id')
SUBDOMAIN=$(echo $GATEWAY_RESPONSE | jq -r '.Subdomain // .subdomain')

if [ -z "$GATEWAY_ID" ] || [ "$GATEWAY_ID" = "null" ]; then
    echo -e "${RED}Failed to create gateway. Response: $GATEWAY_RESPONSE${NC}"
    exit 1
fi

# 2. Create API key
echo -e "${GREEN}2. Creating API key...${NC}"
API_KEY_RESPONSE=$(curl -s -X POST "$ADMIN_URL/gateways/$GATEWAY_ID/keys" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test Key",
    "expires_at": null
  }')

API_KEY=$(echo $API_KEY_RESPONSE | jq -r '.key')

if [ -z "$API_KEY" ] || [ "$API_KEY" = "null" ]; then
    echo -e "${RED}Failed to create API key. Response: $API_KEY_RESPONSE${NC}"
    exit 1
fi

# 3. Create a simple forwarding rule
echo -e "${GREEN}3. Creating forwarding rule...${NC}"
RULE_RESPONSE=$(curl -s -X POST "$ADMIN_URL/gateways/$GATEWAY_ID/rules" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "path": "/test",
    "target": "https://httpbin.org/get",
    "methods": ["GET"],
    "strip_path": true
  }')

sleep 2

# 4. Test with valid API key
echo -e "\n${GREEN}4. Testing with valid API key...${NC}"
VALID_RESPONSE=$(curl -s -w "\n%{http_code}" \
    -H "Host: ${SUBDOMAIN}.${BASE_DOMAIN}" \
    -H "Authorization: Bearer ${API_KEY}" \
    "${PROXY_URL}/test")

VALID_STATUS=$(echo "$VALID_RESPONSE" | tail -n1)
echo -e "Valid key status code: ${VALID_STATUS}"

# 5. Test with invalid API key
echo -e "\n${GREEN}5. Testing with invalid API key...${NC}"
INVALID_RESPONSE=$(curl -s -w "\n%{http_code}" \
    -H "Host: ${SUBDOMAIN}.${BASE_DOMAIN}" \
    -H "Authorization: Bearer invalid_key" \
    "${PROXY_URL}/test")

INVALID_STATUS=$(echo "$INVALID_RESPONSE" | tail -n1)
echo -e "Invalid key status code: ${INVALID_STATUS}"

# 6. Test with no API key
echo -e "\n${GREEN}6. Testing with no API key...${NC}"
NO_KEY_RESPONSE=$(curl -s -w "\n%{http_code}" \
    -H "Host: ${SUBDOMAIN}.${BASE_DOMAIN}" \
    "${PROXY_URL}/test")

NO_KEY_STATUS=$(echo "$NO_KEY_RESPONSE" | tail -n1)
echo -e "No key status code: ${NO_KEY_STATUS}"

# Check results
echo -e "\n${GREEN}Results:${NC}"
if [ "$VALID_STATUS" = "200" ]; then
    echo -e "✅ Valid API key test passed"
else
    echo -e "❌ Valid API key test failed (got $VALID_STATUS, expected 200)"
fi

if [ "$INVALID_STATUS" = "401" ]; then
    echo -e "✅ Invalid API key test passed"
else
    echo -e "❌ Invalid API key test failed (got $INVALID_STATUS, expected 401)"
fi

if [ "$NO_KEY_STATUS" = "401" ]; then
    echo -e "✅ No API key test passed"
else
    echo -e "❌ No API key test failed (got $NO_KEY_STATUS, expected 401)"
fi 