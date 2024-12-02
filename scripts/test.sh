#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# Configuration
ADMIN_URL="http://localhost:8080/api/v1"
PROXY_URL="http://localhost:8081"
BASE_DOMAIN="example.com"

echo -e "${GREEN}Running all tests...${NC}\n"

# Check if Redis is running
redis-cli ping > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo -e "${RED}Redis is not running. Starting Redis...${NC}"
    docker-compose up -d redis
    sleep 2
fi

# Check if both servers are running
echo -e "${GREEN}Checking servers...${NC}"
admin_health=$(curl -s "http://localhost:8080/health")
if [ $? -ne 0 ]; then
    echo -e "${RED}Admin server is not running${NC}"
    exit 1
fi

proxy_health=$(curl -s "http://localhost:8081/health")
if [ $? -ne 0 ]; then
    echo -e "${RED}Proxy server is not running${NC}"
    exit 1
fi

echo -e "Both servers are running\n"

# Run tenant tests
echo -e "${GREEN}Running tenant tests...${NC}"
ADMIN_URL=$ADMIN_URL PROXY_URL=$PROXY_URL BASE_DOMAIN=$BASE_DOMAIN ./scripts/test_tenant.sh

# Run rate limiter tests
echo -e "\n${GREEN}Running rate limiter tests...${NC}"
ADMIN_URL=$ADMIN_URL PROXY_URL=$PROXY_URL BASE_DOMAIN=$BASE_DOMAIN ./scripts/test_rate_limiter.sh

echo -e "\n${GREEN}All tests completed${NC}" 