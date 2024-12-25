#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Base URL for the admin API
ADMIN_URL="http://localhost:8080"
PROXY_URL=${PROXY_URL:-"http://localhost:8081"}
BASE_DOMAIN=${BASE_DOMAIN:-"example.com"}

# Create OpenAI gateway
echo "Testing OpenAI gateway creation..."
openai_response=$(curl -s -X POST "${ADMIN_URL}/api/v1/gateways" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "openai-gateway",
        "type": "models",
        "subdomain": "openai77",
        "settings": {
            "traffic": [
                {"provider": "openai", "weigth": 90}, 
                {"provider": "anthropic", "weigth": 10}
            ],
            "providers": [{
                "name": "openai",
                "path": "/openai",
                "credentials": {
                    "header_name": "Authorization",
                    "header_value": "Bearer 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"
                },
                "fallback_provider": "anthropic",
                "fallback_credentials": {
                    "header_name": "X-Api-Key",
                    "header_value": "anthropic"
                },
                "plugin_chain": ["plugin1", "plugin2"]
            }, {
                "name": "anthropic",
                "path": "anthropic",
                "credentials": {
                    "header_name": "X-Api-Key",
                    "header_value": "anthropic"
                },
                "fallback_provider": "openai",
                "fallback_credentials": {
                    "header_name": "Authorization",
                    "header_value": "Bearer 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"
                },
                "plugin_chain": ["plugin1", "plugin2"]
            }]
        }
    }')

GATEWAY_ID=$(echo $openai_response | jq -r '.id')
SUBDOMAIN=$(echo $openai_response | jq -r '.subdomain')

echo "Gateway ID: $GATEWAY_ID"
echo "Subdomain: $SUBDOMAIN"

# Create API key for OpenAI gateway
echo "Creating API key for OpenAI gateway..."
openai_key_response=$(curl -s -X POST "${ADMIN_URL}/api/v1/gateways/${GATEWAY_ID}/keys" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "test-key",
        "expires_at": "2025-01-01T00:00:00Z"
    }')

# Extract the key from the response
API_KEY=$(echo $openai_key_response | jq -r '.key')
echo "Created API key: $API_KEY"

# Test OpenAI forwarding
echo "Testing OpenAI forwarding..."
openai_response=$(curl -s -X POST "${PROXY_URL}/openai/v1/chat/completions" \
    -H "Content-Type: application/json" \
    -H "X-Api-Key: ${API_KEY}" \
    -H "Host: ${SUBDOMAIN}.${BASE_DOMAIN}" \
    -d '{
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": "Hello"}]
    }')

# Debug the response
echo "OpenAI forwarding response: $openai_response"

echo "Tests completed!" 