#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# Use environment variables or defaults
ADMIN_URL=${ADMIN_URL:-"http://localhost:8080/api/v1"}
PROXY_URL=${PROXY_URL:-"http://localhost:8081"}
BASE_DOMAIN=${BASE_DOMAIN:-"example.com"}

echo -e "${GREEN}Testing WebSocket Support${NC}\n"

# 1. Create a gateway with WebSocket support
echo -e "${GREEN}1. Creating gateway...${NC}"
GATEWAY_RESPONSE=$(curl -s -X POST "$ADMIN_URL/gateways" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "WebSocket Test",
    "subdomain": "wstest",
    "tier": "basic",
    "enabled_plugins": [],
    "required_plugins": {}
  }')

GATEWAY_ID=$(echo $GATEWAY_RESPONSE | jq -r '.id')
SUBDOMAIN=$(echo $GATEWAY_RESPONSE | jq -r '.subdomain')
API_KEY=$(echo $GATEWAY_RESPONSE | jq -r '.api_key')

echo -e "Gateway ID: $GATEWAY_ID"
echo -e "API Key: $API_KEY\n"

# 2. Create forwarding rule with WebSocket support
echo -e "${GREEN}2. Creating forwarding rule...${NC}"
RULE_RESPONSE=$(curl -s -X POST "$ADMIN_URL/gateways/$GATEWAY_ID/rules" \
  -H "Content-Type: application/json" \
  -d '{
    "path": "/ws",
    "target": "wss://echo.websocket.org",
    "methods": ["GET"],
    "strip_path": true,
    "websocket": true,
    "plugin_chain": []
  }')

echo -e "Rule Response: $RULE_RESPONSE\n"

# 3. Test WebSocket connection using wscat
echo -e "${GREEN}3. Testing WebSocket connection...${NC}"
echo -e "Please install wscat if not already installed: npm install -g wscat"
echo -e "Then run the following command to test:"
echo -e "${GREEN}wscat -c ws://wstest.example.com:8081/ws${NC}"
echo -e "Type messages to send them to the echo server."
echo -e "Press Ctrl+C to exit." 