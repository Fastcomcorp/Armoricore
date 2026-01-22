#!/bin/bash

# Monitor Database Connectivity Script
# Continuously checks Aiven PostgreSQL connectivity
# Runs until connectivity is restored

DATABASE_HOST="${DATABASE_HOST:-localhost}"
DATABASE_PORT="15431"
CHECK_INTERVAL=300  # 5 minutes
LOG_FILE="./db_connectivity.log"

echo "=== Database Connectivity Monitor Started ==="
echo "Monitoring: $DATABASE_HOST:$DATABASE_PORT"
echo "Check Interval: $CHECK_INTERVAL seconds"
echo "Log File: $LOG_FILE"
echo "Press Ctrl+C to stop monitoring"
echo ""

# Function to check DNS resolution
check_dns() {
    echo "$(date): Checking DNS resolution..."
    if nslookup "$DATABASE_HOST" >/dev/null 2>&1; then
        echo "✅ DNS resolution: SUCCESS"
        return 0
    else
        echo "❌ DNS resolution: FAILED"
        return 1
    fi
}

# Function to check network connectivity
check_network() {
    echo "$(date): Checking network connectivity..."
    if nc -z -w5 "$DATABASE_HOST" "$DATABASE_PORT" >/dev/null 2>&1; then
        echo "✅ Network connectivity: SUCCESS"
        return 0
    else
        echo "❌ Network connectivity: FAILED"
        return 1
    fi
}

# Function to check database connection
check_database() {
    echo "$(date): Checking database connection..."
    # DATABASE_URL should be set in environment
    # Example: export DATABASE_URL="postgres://user:pass@host:port/db?sslmode=require"

    if cd elixir_realtime && mix run -e "
        try do
          ArmoricoreRealtime.Repo.query('SELECT 1 as test')
          IO.puts('✅ Database connection: SUCCESS')
          System.halt(0)
        rescue
          e ->
            IO.puts('❌ Database connection: FAILED - #{inspect(e)}')
            System.halt(1)
        end
    " 2>/dev/null; then
        return 0
    else
        return 1
    fi
}

# Function to send notification (macOS)
notify() {
    local message="$1"
    echo "$message"

    # macOS notification
    if command -v osascript >/dev/null 2>&1; then
        osascript -e "display notification \"$message\" with title \"Database Connectivity\""
    fi

    # Log to file
    echo "$(date): $message" >> "$LOG_FILE"
}

# Main monitoring loop
attempt=1
while true; do
    echo ""
    echo "=== Connectivity Check #$attempt ($(date)) ==="

    dns_ok=false
    network_ok=false
    db_ok=false

    # Check DNS
    if check_dns; then
        dns_ok=true

        # Check network if DNS works
        if check_network; then
            network_ok=true

            # Check database if network works
            if check_database; then
                db_ok=true
            fi
        fi
    fi

    # Check if all checks passed
    if $dns_ok && $network_ok && $db_ok; then
        notify "🎉 DATABASE CONNECTIVITY RESTORED! All checks passed."
        notify "Ready to run: mix ecto.migrate && mix test"
        echo ""
        echo "=== SUCCESS: Database is accessible! ==="
        echo "You can now run:"
        echo "  cd elixir_realtime"
        echo "  mix ecto.migrate"
        echo "  mix test"
        echo "  mix phx.server"
        exit 0
    else
        echo "❌ Connectivity check failed. Will retry in $CHECK_INTERVAL seconds..."
        if [ $attempt -eq 1 ] || [ $((attempt % 6)) -eq 0 ]; then
            # Notify every 30 minutes (6 * 5 minutes)
            notify "Database still unreachable after $((attempt * CHECK_INTERVAL / 60)) minutes. Continuing to monitor..."
        fi
    fi

    attempt=$((attempt + 1))
    sleep $CHECK_INTERVAL
done