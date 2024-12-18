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

# 1. Create a gateway with multiple rate limiting types
echo -e "${GREEN}1. Creating gateway with multiple rate limiting types...${NC}"
GATEWAY_RESPONSE=$(curl -s -X POST "$ADMIN_URL/gateways" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Multi Rate Limited Gateway",
    "subdomain": "multirate8",
    "tier": "basic",
    "enabled_plugins": ["rate_limiter"],
    "required_plugins": [
        {
            "name": "rate_limiter",
            "enabled": true,
            "stage": "pre_request",
            "priority": 1,
            "settings": {
                "limits": {
                    "global": {
                        "limit": 15,
                        "window": "1m"
                    },
                    "per_ip": {
                        "limit": 5,
                        "window": "1m"
                    },
                    "per_user": {
                        "limit": 5,
                        "window": "1m"
                    }
                },
                "actions": {
                    "type": "reject",
                    "retry_after": "60"
                }
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
    "name": "Test Key"
}')

API_KEY=$(echo $API_KEY_RESPONSE | jq -r '.key')

if [ "$API_KEY" == "null" ] || [ -z "$API_KEY" ]; then
    echo -e "${RED}Failed to create API key. Response: $API_KEY_RESPONSE${NC}"
    exit 1
fi

echo "API Key created: $API_KEY"

# Create rules for different paths
echo -e "\n${GREEN}3. Creating rules for different paths...${NC}"
RULE1_RESPONSE=$(curl -s -X POST "$ADMIN_URL/gateways/$GATEWAY_ID/rules" \
  -H "Content-Type: application/json" \
  -d '{
    "path": "/path1",
    "targets": [{"url": "https://httpbin.org/get", "weight": 30}, {"url": "https://httpbin.org/anything", "weight": 70}],
    "methods": ["GET"],
    "strip_path": true
}')

RULE2_RESPONSE=$(curl -s -X POST "$ADMIN_URL/gateways/$GATEWAY_ID/rules" \
  -H "Content-Type: application/json" \
  -d '{
    "path": "/path2",
    "targets": [{"url": "https://httpbin.org/get", "weight": 30}, {"url": "https://httpbin.org/anything", "weight": 70}],
    "methods": ["GET"],
    "strip_path": true
}')

# Wait for configuration to propagate
sleep 2

# Test different rate limit types
echo -e "\n${GREEN}4. Testing different rate limit types...${NC}"

# Test IP-based rate limit
echo -e "\n${GREEN}4.1 Testing IP-based rate limit (limit: 5/min)...${NC}"
for i in {1..6}; do
    RESPONSE=$(curl -s -w "\n%{http_code}" "$PROXY_URL/path2" \
        -H "Host: ${SUBDOMAIN}.${BASE_DOMAIN}" \
        -H "Authorization: Bearer ${API_KEY}" \
        -H "X-Real-IP: 192.168.1.1")
    
    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    BODY=$(echo "$RESPONSE" | head -n1)
    
    if [ "$HTTP_CODE" == "200" ]; then
        echo -e "${GREEN}IP-based Request $i: Success${NC}"
    elif [ "$HTTP_CODE" == "429" ]; then
        echo -e "${RED}IP-based Request $i: Rate Limited (Expected after 5 requests)${NC}"
        echo "Response: $BODY"
    else
        echo -e "${RED}IP-based Request $i: Unexpected status code: $HTTP_CODE${NC}"
        echo "Response: $BODY"
    fi
    sleep 0.1
done

# Test user-based rate limit
echo -e "\n${GREEN}4.2 Testing user-based rate limit (limit: 5/min)...${NC}"
for i in {1..6}; do
    RESPONSE=$(curl -s -w "\n%{http_code}" "$PROXY_URL/path2" \
        -H "Host: ${SUBDOMAIN}.${BASE_DOMAIN}" \
        -H "Authorization: Bearer ${API_KEY}" \
        -H "X-User-ID: 123" \
        -H "X-Real-IP: 192.168.1.2")
    
    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    BODY=$(echo "$RESPONSE" | head -n1)

    if [ "$HTTP_CODE" == "200" ]; then
        echo -e "${GREEN}User-based Request $i: Success${NC}"
    elif [ "$HTTP_CODE" == "429" ]; then
        echo -e "${RED}User-based Request $i: Rate Limited (Expected after 5 requests)${NC}"
        echo "Response: $BODY"
    else
        echo -e "${RED}User-based Request $i: Unexpected status code: $HTTP_CODE${NC}"
        echo "Response: $BODY"
    fi
    sleep 0.1
done

# Test global rate limit
echo -e "\n${GREEN}4.3 Testing global rate limit (limit: 10/min)...${NC}"
for i in {1..11}; do
    RESPONSE=$(curl -s -w "\n%{http_code}" "$PROXY_URL/path1" \
        -H "Host: ${SUBDOMAIN}.${BASE_DOMAIN}" \
        -H "Authorization: Bearer ${API_KEY}" \
        -H "X-Real-IP: 192.168.1.$((i + 2))")
    
    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    BODY=$(echo "$RESPONSE" | head -n1)
    
    if [ "$HTTP_CODE" == "200" ]; then
        echo -e "${GREEN}Global Request $i: Success${NC}"
    elif [ "$HTTP_CODE" == "429" ]; then
        echo -e "${RED}Global Request $i: Rate Limited (Expected after 10 requests)${NC}"
        echo "Response: $BODY"
    else
        echo -e "${RED}Global Request $i: Unexpected status code: $HTTP_CODE${NC}"
        echo "Response: $BODY"
    fi
    sleep 0.1
done

echo -e "\n${GREEN}Rate limiter tests completed${NC}"