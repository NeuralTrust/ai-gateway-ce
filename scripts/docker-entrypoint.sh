#!/bin/sh
set -e

# Wait for dependencies if needed
wait_for_service() {
    host="$1"
    port="$2"
    timeout="$3"
    
    echo "Waiting for $host:$port..."
    for i in $(seq 1 $timeout); do
        if nc -z "$host" "$port" > /dev/null 2>&1; then
            echo "$host:$port is available"
            return 0
        fi
        sleep 1
    done
    echo "Error: timeout waiting for $host:$port"
    return 1
}

# Wait for Redis and PostgreSQL if configured
if [ -n "$REDIS_HOST" ] && [ -n "$REDIS_PORT" ]; then
    wait_for_service "$REDIS_HOST" "$REDIS_PORT" 30
fi

if [ -n "$DB_HOST" ] && [ -n "$DB_PORT" ]; then
    wait_for_service "$DB_HOST" "$DB_PORT" 30
fi

# Start the gateway
exec /app/gateway "$@" 