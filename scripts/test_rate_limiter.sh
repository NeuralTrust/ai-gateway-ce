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

# 1. Create a tenant with rate limiting
echo -e "${GREEN}1. Creating tenant with rate limiting...${NC}"
TENANT_RESPONSE=$(curl -s -X POST "$ADMIN_URL/tenants" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Rate Limited Company",
    "subdomain": "ratelimited",
    "tier": "basic",
    "enabled_plugins": ["rate_limiter"]
  }')

TENANT_ID=$(echo $TENANT_RESPONSE | jq -r '.id')
SUBDOMAIN=$(echo $TENANT_RESPONSE | jq -r '.subdomain')
API_KEY=$(echo $TENANT_RESPONSE | jq -r '.api_key')

echo -e "Tenant ID: $TENANT_ID"
echo -e "API Key: $API_KEY\n"

# 2. Create forwarding rule
echo -e "${GREEN}2. Creating forwarding rule...${NC}"
RULE_RESPONSE=$(curl -s -X POST "$ADMIN_URL/tenants/$TENANT_ID/rules" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "path": "/test",
    "target": "https://httpbin.org",
    "methods": ["GET"],
    "headers": {
        "X-Rate-Limit-Tier": "premium"
    },
    "strip_path": true,
    "plugin_chain": [
        {
            "name": "rate_limiter",
            "enabled": true,
            "settings": {
                "tiers": {
                    "basic": {
                        "name": "basic",
                        "limit": 5,
                        "window": "1m",
                        "burst": 2
                    },
                    "premium": {
                        "name": "premium",
                        "limit": 10,
                        "window": "1m",
                        "burst": 3
                    }
                },
                "default_tier": "basic",
                "limit_types": {
                    "per_ip": true,
                    "per_method": true
                },
                "quota": {
                    "daily": 100
                }
            }
        }
    ]
  }')

echo -e "Rule Response: $RULE_RESPONSE\n"

# 2. Test basic rate limiting (should succeed for first 5 requests)
for i in {1..5}; do
    response=$(curl -s -w "\n%{http_code}" -H "Authorization: Bearer $API_KEY" -H "Host: ${SUBDOMAIN}.${BASE_DOMAIN}" $PROXY_URL/test/get)
    http_code=$(echo "$response" | tail -n1)
    if [ "$http_code" == "200" ]; then
        echo -e "${GREEN}Request $i: Success${NC}"
    else
        echo -e "${RED}Request $i: Failed with code $http_code${NC}"
    fi
    sleep 1
done

echo -e "\n${GREEN}Testing rate limit exceeded...${NC}"

# 3. Test rate limit exceeded (should fail)
response=$(curl -s -w "\n%{http_code}" -H "Authorization: Bearer $API_KEY" -H "X-Rate-Limit-Tier: basic" -H "Host: ${SUBDOMAIN}.${BASE_DOMAIN}" $PROXY_URL/test/get)
echo $response
http_code=$(echo "$response" | tail -n1)
if [ "$http_code" != "200" ]; then
    echo -e "${GREEN}Rate limit exceeded test: Success (got expected error)${NC}"
else
    echo -e "${RED}Rate limit exceeded test: Failed (unexpected success)${NC}"
fi

# 4. Wait for rate limit window to reset
echo -e "\n${GREEN}4. Waiting for rate limit window to reset (60s)...${NC}"
sleep 60

# 5. Test after reset
echo -e "\n${GREEN}5. Testing after rate limit reset...${NC}"
response=$(curl -s -w "\n%{http_code}" \
  -H "Host: ${SUBDOMAIN}.${BASE_DOMAIN}" \
  -H "Authorization: Bearer $API_KEY" \
  -H "X-Rate-Limit-Tier: basic" \
  "$PROXY_URL/test")

http_code=$(echo "$response" | tail -n1)
if [ "$http_code" == "200" ]; then
    echo -e "${GREEN}Request after reset: Success${NC}"
else
    echo -e "${RED}Request after reset: Failed with code $http_code${NC}"
fi

echo -e "\n${GREEN}Rate limiter tests completed${NC}"