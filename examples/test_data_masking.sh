#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# Use environment variables or defaults
ADMIN_URL=${ADMIN_URL:-"http://localhost:8080/api/v1"}
PROXY_URL=${PROXY_URL:-"http://localhost:8081"}
BASE_DOMAIN=${BASE_DOMAIN:-"example.com"}
SUBDOMAIN="datamask-$(date +%s)"

echo -e "${GREEN}Testing Data Masking Plugin${NC}\n"

# 1. Create a gateway with data masking plugin
echo -e "${GREEN}1. Creating gateway with data masking plugin...${NC}"
GATEWAY_RESPONSE=$(curl -s -X POST "$ADMIN_URL/gateways" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Data Masking Gateway",
    "subdomain": "'$SUBDOMAIN'",
    "required_plugins": [
        {
            "name": "data_masking",
            "enabled": true,
            "stage": "pre_response",
            "priority": 1,
            "settings": {
                "rules": [
                    {
                        "pattern": "credit_card",
                        "type": "keyword",
                        "mask_with": "****",
                        "preserve_len": true
                    },
                    {
                        "pattern": "\\b\\d{4}[-\\s]?\\d{4}[-\\s]?\\d{4}[-\\s]?\\d{4}\\b",
                        "type": "regex",
                        "mask_with": "X",
                        "preserve_len": true
                    },
                    {
                        "pattern": "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b",
                        "type": "regex",
                        "mask_with": "[MASKED_EMAIL]",
                        "preserve_len": false
                    }
                ]
            }
        }
    ]
}')

# Extract gateway details
GATEWAY_ID=$(echo $GATEWAY_RESPONSE | jq -r '.id')
SUBDOMAIN=$(echo $GATEWAY_RESPONSE | jq -r '.subdomain')

if [ "$GATEWAY_ID" == "null" ] || [ -z "$GATEWAY_ID" ]; then
    echo -e "${RED}Failed to create gateway. Response: $GATEWAY_RESPONSE${NC}"
    exit 1
fi

echo "Gateway created with ID: $GATEWAY_ID"

# Create API key
echo -e "\n${GREEN}2. Creating API key...${NC}"
API_KEY_RESPONSE=$(curl -s -X POST "$ADMIN_URL/gateways/$GATEWAY_ID/keys" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test Key",
    "expires_at": "2026-01-01T00:00:00Z"
}')

API_KEY=$(echo $API_KEY_RESPONSE | jq -r '.key')

if [ "$API_KEY" == "null" ] || [ -z "$API_KEY" ]; then
    echo -e "${RED}Failed to create API key. Response: $API_KEY_RESPONSE${NC}"
    exit 1
fi

echo "API Key created: $API_KEY"

# Create upstream
echo -e "\n${GREEN}3. Creating upstream...${NC}"
UPSTREAM_RESPONSE=$(curl -s -X POST "$ADMIN_URL/gateways/$GATEWAY_ID/upstreams" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "echo-upstream-'$(date +%s)'",
    "algorithm": "round-robin",
    "targets": [{
        "host": "postman-echo.com",
        "port": 443,
        "protocol": "https",
        "weight": 100,
        "priority": 1
    }],
    "health_checks": {
        "passive": true,
        "threshold": 3,
        "interval": 60
    }
}')

UPSTREAM_ID=$(echo $UPSTREAM_RESPONSE | jq -r '.id')

if [ "$UPSTREAM_ID" == "null" ] || [ -z "$UPSTREAM_ID" ]; then
    echo -e "${RED}Failed to create upstream. Response: $UPSTREAM_RESPONSE${NC}"
    exit 1
fi

echo "Upstream created with ID: $UPSTREAM_ID"

# Create service
echo -e "\n${GREEN}4. Creating service...${NC}"
SERVICE_RESPONSE=$(curl -s -X POST "$ADMIN_URL/gateways/$GATEWAY_ID/services" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "echo-service-'$(date +%s)'",
    "type": "upstream",
    "description": "Echo test service",
    "upstream_id": "'$UPSTREAM_ID'"
}')

SERVICE_ID=$(echo $SERVICE_RESPONSE | jq -r '.id')

if [ "$SERVICE_ID" == "null" ] || [ -z "$SERVICE_ID" ]; then
    echo -e "${RED}Failed to create service. Response: $SERVICE_RESPONSE${NC}"
    exit 1
fi

echo "Service created with ID: $SERVICE_ID"

# Create rule for testing
echo -e "\n${GREEN}5. Creating rule for testing...${NC}"
RULE_RESPONSE=$(curl -s -X POST "$ADMIN_URL/gateways/$GATEWAY_ID/rules" \
  -H "Content-Type: application/json" \
  -d '{
    "path": "/post",
    "service_id": "'$SERVICE_ID'",
    "methods": ["POST"],
    "strip_path": false,
    "active": true
}')

# Wait for configuration to propagate
sleep 2

# Test data masking
echo -e "\n${GREEN}6. Testing data masking...${NC}"

# Test keyword masking
echo -e "\n${GREEN}6.1 Testing keyword masking...${NC}"
RESPONSE=$(curl -s -w "\n%{http_code}" "$PROXY_URL/post" \
    -H "Host: ${SUBDOMAIN}.${BASE_DOMAIN}" \
    -H "X-API-Key: ${API_KEY}" \
    -H "Content-Type: application/json" \
    -d '{
        "message": "My credit_card number is 4111-2222-3333-4444",
        "email": "test@example.com",
        "notes": "This is a test message"
    }')

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n1)

if [ "$HTTP_CODE" == "200" ]; then
    echo -e "${GREEN}Request successful${NC}"
    echo "Response body:"
    echo "$BODY" | jq '.'
    
    # Check if masking worked
    if echo "$BODY" | grep -q "credit_card"; then
        echo -e "${RED}WARNING: Keyword 'credit_card' was not masked${NC}"
    else
        echo -e "${GREEN}Keyword masking successful${NC}"
    fi
    
    if echo "$BODY" | grep -q "4111-2222-3333-4444"; then
        echo -e "${RED}WARNING: Credit card number was not masked${NC}"
    else
        echo -e "${GREEN}Credit card number masking successful${NC}"
    fi
    
    if echo "$BODY" | grep -q "test@example.com"; then
        echo -e "${RED}WARNING: Email was not masked${NC}"
    else
        echo -e "${GREEN}Email masking successful${NC}"
    fi
else
    echo -e "${RED}Request failed with status code: $HTTP_CODE${NC}"
    echo "Response: $BODY"
fi

echo -e "\n${GREEN}Data masking tests completed${NC}" 