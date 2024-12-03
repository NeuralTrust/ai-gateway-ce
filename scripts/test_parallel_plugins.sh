#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# Use environment variables or defaults
ADMIN_URL=${ADMIN_URL:-"http://localhost:8080/api/v1"}
PROXY_URL=${PROXY_URL:-"http://localhost:8081"}
BASE_DOMAIN=${BASE_DOMAIN:-"example.com"}

echo -e "${GREEN}Testing Parallel Plugin Execution${NC}\n"

# 1. Create a tenant with multiple plugins
echo -e "${GREEN}1. Creating tenant...${NC}"
TENANT_RESPONSE=$(curl -s -X POST "$ADMIN_URL/tenants" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Parallel Test Company",
    "subdomain": "parallel",
    "tier": "pro",
    "enabled_plugins": ["rate_limiter", "external_validator"],
    "required_plugins": {
        "rate_limiter": {
            "name": "rate_limiter",
            "enabled": true,
            "priority": 1,
            "parallel": false,
            "stage": "pre_request",
            "settings": {
                "limit": 5,
                "window": "1m"
            }
        }
    }
  }')

TENANT_ID=$(echo $TENANT_RESPONSE | jq -r '.id')
SUBDOMAIN=$(echo $TENANT_RESPONSE | jq -r '.subdomain')
API_KEY=$(echo $TENANT_RESPONSE | jq -r '.api_key')

echo -e "Tenant ID: $TENANT_ID"
echo -e "API Key: $API_KEY\n"

# 2. Create forwarding rule with parallel plugins
echo -e "${GREEN}2. Creating forwarding rule with parallel plugins...${NC}"
RULE_RESPONSE=$(curl -s -X POST "$ADMIN_URL/tenants/$TENANT_ID/rules" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "path": "/test",
    "target": "https://httpbin.org",
    "methods": ["POST"],
    "strip_path": true,
    "plugin_chain": [
        {
            "name": "rate_limiter",
            "enabled": true,
            "parallel": false,
            "priority": 1,
            "settings": {
                "limit": 5,
                "window": "1m"
            }
        },
        {
            "name": "external_validator",
            "enabled": true,
            "parallel": true,
            "priority": 2,
            "conditions": [
                {
                    "field": "json.data.score",
                    "operator": "gte",
                    "value": 0.8,
                    "stop_flow": true,
                    "message": "Score too high"
                }
            ]
        }
    ]
  }')

echo -e "Rule Response: $RULE_RESPONSE\n"

# 3. Test parallel execution (multiple concurrent requests)
echo -e "${GREEN}3. Testing parallel execution with multiple requests...${NC}"
for i in {1..3}; do
    (
        response=$(curl -s -w "\n%{http_code}" \
            -H "Host: ${SUBDOMAIN}.${BASE_DOMAIN}" \
            -H "Authorization: Bearer $API_KEY" \
            -H "Content-Type: application/json" \
            -d "{
                \"data\": {
                    \"score\": 0.$i,
                    \"request_id\": \"test_$i\"
                }
            }" \
            "$PROXY_URL/test")
        
        http_code=$(echo "$response" | tail -n1)
        body=$(echo "$response" | head -n1)
        
        echo -e "Request $i (Score: 0.$i):"
        echo -e "Status Code: $http_code"
        echo -e "Response: $body\n"
    ) &
done

# Wait for all requests to complete
wait

# 4. Test rate limit with parallel requests
echo -e "\n${GREEN}4. Testing rate limit with parallel requests...${NC}"
for i in {1..6}; do
    (
        response=$(curl -s -w "\n%{http_code}" \
            -H "Host: ${SUBDOMAIN}.${BASE_DOMAIN}" \
            -H "Authorization: Bearer $API_KEY" \
            -H "Content-Type: application/json" \
            -d "{
                \"data\": {
                    \"score\": 0.5,
                    \"request_id\": \"rate_test_$i\"
                }
            }" \
            "$PROXY_URL/test")
        
        http_code=$(echo "$response" | tail -n1)
        echo -e "Request $i - Status Code: $http_code"
    ) &
done

# Wait for all requests to complete
wait

echo -e "\n${GREEN}Parallel plugin tests completed${NC}" 