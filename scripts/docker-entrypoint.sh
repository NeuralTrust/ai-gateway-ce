#!/bin/sh
set -e

# Default values
SERVER_TYPE=${SERVER_TYPE:-"admin"}  # admin or proxy

# Start the appropriate server
case "$SERVER_TYPE" in
    "admin")
        echo "Starting Admin server..."
        exec /app/ai-gateway-ce admin
        ;;
    "proxy")
        echo "Starting Proxy server..."
        exec /app/ai-gateway-ce proxy
        ;;
    *)
        echo "Invalid SERVER_TYPE. Must be 'admin' or 'proxy'"
        exit 1
        ;;
esac 