#!/bin/bash

# Configuration
ADMIN_URL="http://localhost:8080"
PROXY_URL="http://localhost:8081"
TIMESTAMP=$(date +%s)
BASE_DOMAIN=${BASE_DOMAIN:-"example.com"}
SUBDOMAIN="fallbacktest-$TIMESTAMP"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Function to print section header
print_header() {
    echo -e "\n${YELLOW}=== $1 ===${NC}"
}

# Check if OPENAI_API_KEY and ANTHROPIC_API_KEY are set
if [ -z "$OPENAI_API_KEY" ]; then
    echo -e "${RED}Error: OPENAI_API_KEY environment variable is not set${NC}"
    echo "Please set your OpenAI API key first:"
    echo "export OPENAI_API_KEY=your_api_key"
    exit 1
fi

if [ -z "$ANTHROPIC_API_KEY" ]; then
    echo -e "${RED}Error: ANTHROPIC_API_KEY environment variable is not set${NC}"
    echo "Please set your Anthropic API key first:"
    echo "export ANTHROPIC_API_KEY=your_api_key"
    exit 1
fi

print_header "Creating Gateway with Fallback Configuration"

# Create gateway with fallback configuration
GATEWAY_RESPONSE=$(curl -s -X POST "$ADMIN_URL/api/v1/gateways" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Fallback Test Gateway",
    "subdomain": "'$SUBDOMAIN'",
    "type": "models",
    "settings": {
      "traffic": [
        {"provider": "anthropic", "weight": 100}
      ],
      "providers": [
        {
          "name": "anthropic",
          "path": "/anthropic",
          "headers": {
            "anthropic-version": "2023-06-01"
          },
          "strip_path": true,
          "credentials": {
            "header_name": "x-api-key",
            "header_value": "'$ANTHROPIC_API_KEY'"
          }
        }
      ]
    },
    "required_plugins": [
      {
        "name": "token_rate_limiter",
        "enabled": true,
        "settings": {
          "tokens_per_request": 20,
          "tokens_per_minute": 100,
          "bucket_size": 150000,
          "requests_per_minute": 60
        }
      }
    ]
  }')

GATEWAY_ID=$(echo $GATEWAY_RESPONSE | jq -r '.id')

if [ -z "$GATEWAY_ID" ] || [ "$GATEWAY_ID" == "null" ]; then
    echo -e "${RED}Failed to create gateway${NC}"
    echo $GATEWAY_RESPONSE
    exit 1
fi

echo -e "${GREEN}Gateway created with ID: $GATEWAY_ID${NC}"

# Create API key
print_header "Creating API Key"
API_KEY_RESPONSE=$(curl -s -X POST "$ADMIN_URL/api/v1/gateways/$GATEWAY_ID/keys" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "test-key",
    "expires_at": "2025-01-01T00:00:00Z"
  }')

API_KEY=$(echo $API_KEY_RESPONSE | jq -r '.key')

if [ -z "$API_KEY" ] || [ "$API_KEY" == "null" ]; then
    echo -e "${RED}Failed to create API key${NC}"
    echo $API_KEY_RESPONSE
    exit 1
fi

echo -e "${GREEN}API key created: $API_KEY${NC}"

# Wait for gateway to be ready
echo "Waiting for gateway to be ready..."
sleep 2

# Function to make a chat completion request
make_chat_request() {
    local provider=$1
    local prompt=$2
    local model=$3
    local description=$4
    
    # Make the request and capture both headers and body
    local response=$(curl -s -i -X POST "${PROXY_URL}/${provider}/v1/messages" \
        -H "Content-Type: application/json" \
        -H "Host: ${SUBDOMAIN}.${BASE_DOMAIN}" \
        -H "X-Api-Key: $API_KEY" \
        -H "anthropic-version: 2023-06-01" \
        -d '{
            "model": "'$model'",
            "messages": [
                {
                    "role": "user",
                    "content": "'"$prompt"'"
                }
            ],
            "max_tokens": 1024
        }')
    
    echo "Response: $response"
    # Split headers and body
    local headers=$(echo "$response" | awk 'BEGIN{RS="\r\n\r\n"}NR==1')
    local body=$(echo "$response" | awk 'BEGIN{RS="\r\n\r\n"}NR==2')
    
    # Check if response is valid JSON and print preview
    if echo "$body" | jq -e . >/dev/null 2>&1; then
        # Check if response contains an error
        if echo "$body" | jq -e '.error' >/dev/null 2>&1; then
            echo -e "\n${RED}Error Response:${NC}"
            echo "$body" | jq -r '.error'
        else
            echo -e "\n${GREEN}Response Preview:${NC}"
            echo "$body" | jq -r '.choices[0].message.content' | head -n 3
        fi
    else
        echo -e "${RED}Error: Invalid response${NC}"
        echo "$body"
    fi
    
    echo "----------------------------------------"
    sleep 1
}

# Test Sequence

# Test 1: Valid OpenAI model
make_chat_request "anthropic" "Hello, how are you?" "claude-3-5-sonnet-20241022" "Test 1: OpenAI GPT-4o-mini"

# # Test 2: Invalid OpenAI model (should trigger fallback)
# make_chat_request "openai" "Hello, how are you?" "gpt-4o" "Test 2: Invalid Model (Fallback Test)"

# # Test 4: Trigger fallback with error
# make_chat_request "openai" "Tell me about quantum computing" "gpt-5" "Test 4: Non-existent Model (Fallback Test)"
``` 
