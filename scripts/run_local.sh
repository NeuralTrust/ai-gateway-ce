#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# Create logs directory
mkdir -p logs

# Check if Redis is running
redis-cli ping > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo -e "${RED}Redis is not running. Starting Redis...${NC}"
    docker compose up -d
    sleep 2
fi

# Function to wait for server to be ready
wait_for_server() {
    local port=$1
    local name=$2
    echo -e "Waiting for $name to be ready..."
    while ! curl -s http://localhost:$port/health > /dev/null; do
        sleep 1
    done
    echo -e "${GREEN}$name is ready!${NC}"
}

# Start Admin server in background
echo -e "${GREEN}Starting Admin server...${NC}"
go run cmd/gateway/main.go admin > logs/admin.log 2>&1 &
ADMIN_PID=$!

# Start Proxy server in background
echo -e "${GREEN}Starting Proxy server...${NC}"
go run cmd/gateway/main.go proxy > logs/proxy.log 2>&1 &
PROXY_PID=$!

# Wait for both servers to be ready
wait_for_server 8080 "Admin server"
wait_for_server 8081 "Proxy server"

echo -e "${GREEN}Both servers are running!${NC}"
echo -e "Admin server (PID: $ADMIN_PID) - http://localhost:8080"
echo -e "Proxy server (PID: $PROXY_PID) - http://localhost:8081"
echo -e "Logs are available in the logs directory"
echo -e "\nPress Ctrl+C to stop both servers"

# Handle shutdown
trap "kill $ADMIN_PID $PROXY_PID; echo -e '\n${GREEN}Servers stopped${NC}'" INT TERM

# Keep script running
wait 