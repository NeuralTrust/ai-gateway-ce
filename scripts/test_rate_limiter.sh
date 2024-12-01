#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo "Creating forwarding rule with rate limiting..."

# 1. First, create a forwarding rule with rate limiting
curl -X POST -H "Host: tenant1.example.com" \
  -H "Content-Type: application/json" \
  -d '{
    "path": "/test",
    "target": "https://httpbin.org",
    "methods": ["GET"],
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
                    }
                },
                "default_tier": "basic",
                "limit_types": {
                    "per_ip": true,
                    "per_method": true
                },
                "quota": {
                    "daily": 100
                },
                "actions": {
                    "on_exceeded": "block",
                    "retry_after": "60s"
                }
            }
        }
    ]
  }' \
  http://localhost:8080/api/v1/forwarding-rules

echo -e "\n${GREEN}Testing basic rate limiting...${NC}"

# 2. Test basic rate limiting (should succeed for first 5 requests)
for i in {1..5}; do
    response=$(curl -s -w "\n%{http_code}" -H "Host: tenant1.example.com" http://localhost:8080/test/get)
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
response=$(curl -s -w "\n%{http_code}" -H "Host: tenant1.example.com" http://localhost:8080/test/get)
http_code=$(echo "$response" | tail -n1)
if [ "$http_code" != "200" ]; then
    echo -e "${GREEN}Rate limit exceeded test: Success (got expected error)${NC}"
else
    echo -e "${RED}Rate limit exceeded test: Failed (unexpected success)${NC}"
fi

echo -e "\n${GREEN}Testing burst capacity...${NC}"

# 4. Create a rule with burst capacity
curl -X POST -H "Host: tenant2.example.com" \
  -H "Content-Type: application/json" \
  -d '{
    "path": "/test",
    "target": "https://httpbin.org",
    "methods": ["GET"],
    "plugin_chain": [
        {
            "name": "rate_limiter",
            "enabled": true,
            "settings": {
                "tiers": {
                    "burst": {
                        "name": "burst",
                        "limit": 2,
                        "window": "1m",
                        "burst": 3
                    }
                },
                "default_tier": "burst"
            }
        }
    ]
  }' \
  http://localhost:8080/api/v1/forwarding-rules

# 5. Test burst capacity (should allow 5 quick requests)
for i in {1..5}; do
    response=$(curl -s -w "\n%{http_code}" -H "Host: tenant2.example.com" http://localhost:8080/test/get)
    http_code=$(echo "$response" | tail -n1)
    if [ "$http_code" == "200" ]; then
        echo -e "${GREEN}Burst request $i: Success${NC}"
    else
        echo -e "${RED}Burst request $i: Failed with code $http_code${NC}"
    fi
done

echo -e "\n${GREEN}Testing different tiers...${NC}"

# 6. Create a rule with multiple tiers
curl -X POST -H "Host: tenant3.example.com" \
  -H "Content-Type: application/json" \
  -d '{
    "path": "/test",
    "target": "https://httpbin.org",
    "methods": ["GET"],
    "plugin_chain": [
        {
            "name": "rate_limiter",
            "enabled": true,
            "settings": {
                "tiers": {
                    "free": {
                        "name": "free",
                        "limit": 2,
                        "window": "1m"
                    },
                    "premium": {
                        "name": "premium",
                        "limit": 10,
                        "window": "1m"
                    }
                },
                "default_tier": "free"
            }
        }
    ]
  }' \
  http://localhost:8080/api/v1/forwarding-rules

# 7. Test free tier
echo "Testing free tier..."
for i in {1..3}; do
    response=$(curl -s -w "\n%{http_code}" -H "Host: tenant3.example.com" http://localhost:8080/test/get)
    http_code=$(echo "$response" | tail -n1)
    echo -e "Free tier request $i: $([ "$http_code" == "200" ] && echo "${GREEN}Success${NC}" || echo "${RED}Failed${NC}")"
done

# 8. Test premium tier
echo "Testing premium tier..."
for i in {1..5}; do
    response=$(curl -s -w "\n%{http_code}" -H "Host: tenant3.example.com" -H "X-Tier: premium" http://localhost:8080/test/get)
    http_code=$(echo "$response" | tail -n1)
    echo -e "Premium tier request $i: $([ "$http_code" == "200" ] && echo "${GREEN}Success${NC}" || echo "${RED}Failed${NC}")"
done

echo -e "\n${GREEN}All tests completed${NC}" 