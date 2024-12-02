#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# Use environment variables or defaults
ADMIN_URL=${ADMIN_URL:-"http://localhost:8080/api/v1"}
PROXY_URL=${PROXY_URL:-"http://localhost:8081"}
BASE_DOMAIN=${BASE_DOMAIN:-"example.com"}

echo -e "${GREEN}Testing Tenant Management API${NC}\n"

# 1. Create a new tenant
echo -e "${GREEN}1. Creating new tenant...${NC}"
TENANT_RESPONSE=$(curl -s -X POST "$ADMIN_URL/tenants" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test Company",
    "subdomain": "testcompany",
    "tier": "pro",
    "enabled_plugins": ["rate_limiter", "content_validator"],
    "required_plugins": {
        "security_validator": {
            "name": "security_validator",
            "enabled": true,
            "priority": 1,
            "stage": "pre_request",
            "settings": {
                "required_headers": ["X-Request-ID"],
                "blocked_ips": []
            }
        }
    }
  }')

echo "Response: $TENANT_RESPONSE"
TENANT_ID=$(echo $TENANT_RESPONSE | jq -r '.id')
SUBDOMAIN=$(echo $TENANT_RESPONSE | jq -r '.subdomain')
API_KEY=$(echo $TENANT_RESPONSE | jq -r '.api_key')

echo -e "Tenant ID: $TENANT_ID"
echo -e "API Key: $API_KEY\n"

if [ "$TENANT_ID" = "null" ]; then
    echo -e "${RED}Failed to create tenant${NC}"
    exit 1
fi

# 2. Create API Keys for the tenant
echo -e "${GREEN}2. Creating API keys...${NC}"

# Create first API key
APIKEY1_RESPONSE=$(curl -s -X POST "$ADMIN_URL/tenants/$TENANT_ID/api-keys" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Production Key"
  }')

echo "API Key 1 Response: $APIKEY1_RESPONSE"
APIKEY1=$(echo $APIKEY1_RESPONSE | jq -r '.key')

# Create second API key with expiration
APIKEY2_RESPONSE=$(curl -s -X POST "$ADMIN_URL/tenants/$TENANT_ID/api-keys" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test Key",
    "expires_at": "2024-12-31T23:59:59Z"
  }')

echo -e "API Key 2 Response: $APIKEY2_RESPONSE\n"
APIKEY2_ID=$(echo $APIKEY2_RESPONSE | jq -r '.id')

# 3. List API Keys
echo -e "${GREEN}3. Listing API keys...${NC}"
curl -s -H "Authorization: Bearer $API_KEY" \
  "$ADMIN_URL/tenants/$TENANT_ID/api-keys" | jq .
echo -e "\n"

# 4. Create a forwarding rule
echo -e "${GREEN}4. Creating forwarding rule...${NC}"
RULE_RESPONSE=$(curl -s -X POST "$ADMIN_URL/tenants/$TENANT_ID/rules" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "path": "/v1/chat/completions",
    "target": "https://api.openai.com",
    "methods": ["POST"],
    "strip_path": false,
    "headers": {
        "Authorization": "Bearer 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"
    },
    "plugin_chain": [
        {
            "name": "rate_limiter",
            "enabled": true,
            "priority": 2,
            "stage": "pre_request",
            "settings": {
                "limit": 100,
                "window": "1m"
            }
        }
    ]
  }')

echo -e "Rule Response: $RULE_RESPONSE\n"
RULE_ID=$(echo $RULE_RESPONSE | jq -r '.id')

# 5. Test invalid API key
echo -e "${GREEN}5. Testing invalid API key...${NC}"
INVALID_RESPONSE=$(curl -s -X POST \
  -H "Host: ${SUBDOMAIN}.${BASE_DOMAIN}" \
  -H "Authorization: Bearer invalid-key" \
  "$PROXY_URL/v1/chat/completions")

echo -e "Invalid Key Response: $INVALID_RESPONSE\n"

# 6. Revoke an API key
echo -e "${GREEN}6. Revoking API key...${NC}"
curl -s -X DELETE -H "Authorization: Bearer $API_KEY" \
  "$ADMIN_URL/tenants/$TENANT_ID/api-keys/$APIKEY2_ID"
echo -e "\n"

# 7. List API Keys after revocation
echo -e "${GREEN}7. Listing API keys after revocation...${NC}"
curl -s -H "Authorization: Bearer $API_KEY" \
  "$ADMIN_URL/tenants/$TENANT_ID/api-keys" | jq .
echo -e "\n"

# 8. Update tenant
echo -e "${GREEN}8. Updating tenant...${NC}"
curl -s -X PUT -H "Authorization: Bearer $API_KEY" \
  "$ADMIN_URL/tenants/$TENANT_ID" \
  -H "Content-Type: application/json" \
  -d '{
    "tier": "enterprise",
    "required_plugins": {
        "security_validator": {
            "priority": 1,
            "settings": {
                "required_headers": ["X-Request-ID", "X-Correlation-ID"],
                "blocked_ips": []
            }
        }
    }
  }' | jq .
echo -e "\n"

# 9. Get tenant details
echo -e "${GREEN}9. Getting tenant details...${NC}"
curl -s -H "Authorization: Bearer $API_KEY" \
  "$ADMIN_URL/tenants/$TENANT_ID" | jq .
echo -e "\n"

# 10. Test forwarding with valid API key
echo -e "${GREEN}10. Testing forwarding with valid API key...${NC}"
curl -s -X POST \
  -H "Host: ${SUBDOMAIN}.${BASE_DOMAIN}" \
  -H "Authorization: Bearer $APIKEY1" \
  -H "Content-Type: application/json" \
  -H "X-Request-ID: test-123" \
  -d '{
    "model": "gpt-4o-mini",
    "messages": [{"role": "user", "content": "Hello!"}]
  }' \
  "$PROXY_URL/v1/chat/completions"

echo -e "\n${GREEN}Tests completed${NC}" 