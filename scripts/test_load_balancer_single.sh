#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color
BLUE='\033[0;34m'

# Configuration
GATEWAY_ID="test-gateway"
API_KEY="test-key"
BASE_URL="http://localhost:8080"
STRATEGY=$1
REQUESTS=${2:-100}
TIMEOUT=${3:-5}  # Timeout in seconds

if [ -z "$STRATEGY" ]; then
    echo "Usage: $0 <strategy> [requests]"
    echo "Strategy can be 'round-robin' or 'weighted'"
    echo "Requests is optional, defaults to 100"
    exit 1
fi

# Check if strategy is valid
if [[ "$STRATEGY" != "round-robin" && "$STRATEGY" != "weighted" ]]; then
    echo -e "${RED}Error: Invalid strategy. Must be 'round-robin' or 'weighted'${NC}"
    exit 1
fi

# Function to make a single request with timeout
make_request() {
    local url=$1
    local timeout=$2
    response=$(curl -s -m "$timeout" -H "Authorization: Bearer $API_KEY" "$url")
    if [ $? -ne 0 ]; then
        echo -e "\n${RED}Error: Request failed or timed out${NC}"
        return 1
    fi
    echo "$response"
}

# Make requests and collect statistics
declare -A responses
declare -A latencies
total_latency=0
failed_requests=0

echo -e "${BLUE}Testing $STRATEGY load balancing with $REQUESTS requests...${NC}"
echo "Making requests..."

for i in $(seq 1 $REQUESTS); do
    start_time=$(date +%s.%N)
    response=$(make_request "$BASE_URL/$STRATEGY" "$TIMEOUT")
    
    if [ $? -eq 0 ]; then
        server=$(echo "$response" | jq -r '.server')
        if [ "$server" != "null" ] && [ ! -z "$server" ]; then
            responses[$server]=$((responses[$server] + 1))
            
            # Calculate latency
            end_time=$(date +%s.%N)
            latency=$(echo "$end_time - $start_time" | bc)
            latencies[$server]=$(echo "${latencies[$server]:-0} + $latency" | bc)
            total_latency=$(echo "$total_latency + $latency" | bc)
        else
            failed_requests=$((failed_requests + 1))
        fi
    else
        failed_requests=$((failed_requests + 1))
    fi
    echo -n "."
done
echo -e "\n\n${GREEN}Test completed!${NC}\n"

# Print distribution
echo "Distribution:"
for server in "${!responses[@]}"; do
    count=${responses[$server]}
    percentage=$((count * 100 / REQUESTS))
    echo "$server: $count requests ($percentage%)"
    
    # Calculate average latency for this server
    if [ ${responses[$server]} -gt 0 ]; then
        avg_latency=$(echo "scale=3; ${latencies[$server]} / ${responses[$server]}" | bc)
        echo "  Average latency: ${avg_latency}s"
    fi
done

# Print summary
echo -e "\nSummary:"
echo "Total requests: $REQUESTS"
echo "Failed requests: $failed_requests"
successful_requests=$((REQUESTS - failed_requests))
if [ $successful_requests -gt 0 ]; then
    avg_total_latency=$(echo "scale=3; $total_latency / $successful_requests" | bc)
    echo "Average total latency: ${avg_total_latency}s"
fi 