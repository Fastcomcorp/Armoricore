#!/bin/bash

# Armoricore v1.0.0 - Development Startup Script
# Copyright 2025 Francisco F. Pinochet
# Copyright 2026 Fastcomcorp, LLC
#
# This script provides a quick way to start Armoricore for development.
# It starts only essential services and skips long-running builds.

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ELIXIR_DIR="$SCRIPT_DIR/elixir_realtime"
LOG_DIR="$SCRIPT_DIR/logs"
PID_DIR="$SCRIPT_DIR/pids"

# Create directories
mkdir -p "$LOG_DIR"
mkdir -p "$PID_DIR"

# Load environment variables from .env file if it exists
if [ -f "$SCRIPT_DIR/.env" ]; then
    set -a
    source "$SCRIPT_DIR/.env"
    set +a
fi

# Function to print status
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Function to check if a port is in use
port_in_use() {
    lsof -i :"$1" >/dev/null 2>&1 || nc -z localhost "$1" >/dev/null 2>&1
}

# Wait for service
wait_for_service() {
    local service_name=$1
    local port=$2
    local max_attempts=${3:-30}
    local attempt=0

    while [ $attempt -lt $max_attempts ]; do
        if port_in_use "$port"; then
            return 0
        fi
        attempt=$((attempt + 1))
        sleep 1
    done
    return 1
}

# Start NATS if not running
start_nats() {
    if port_in_use 4222; then
        print_success "NATS already running on port 4222"
        return 0
    fi
    
    if command -v nats-server >/dev/null 2>&1; then
        print_status "Starting NATS server..."
        nats-server -js -p 4222 -m 8222 > "$LOG_DIR/nats.log" 2>&1 &
        echo $! > "$PID_DIR/nats.pid"
        
        if wait_for_service "NATS" 4222 10; then
            print_success "NATS server started"
        else
            print_error "NATS server failed to start"
            return 1
        fi
    else
        print_warning "NATS server not installed. Some features may not work."
        print_status "Install NATS: brew install nats-server (macOS) or see https://nats.io"
    fi
}

# Check database connection
check_database() {
    if [[ -n "$DATABASE_URL" ]]; then
        print_success "Database URL configured"
        return 0
    elif port_in_use 5432; then
        print_success "Local PostgreSQL running on port 5432"
        return 0
    else
        print_warning "No database configured. Set DATABASE_URL in .env"
        return 1
    fi
}

# Start Phoenix in development mode
start_phoenix() {
    if port_in_use 4000; then
        print_warning "Port 4000 already in use. Phoenix may already be running."
        return 0
    fi
    
    print_status "Starting Phoenix server..."
    
    cd "$ELIXIR_DIR"
    
    # Check dependencies
    if [[ ! -d "deps" ]]; then
        print_status "Installing dependencies..."
        mix deps.get
    fi
    
    # Run migrations
    print_status "Running database migrations..."
    mix ecto.migrate 2>/dev/null || print_warning "Migration failed (database may not be configured)"
    
    # Start Phoenix with iex for interactive development
    if [[ "${1:-}" == "--interactive" ]] || [[ "${1:-}" == "-i" ]]; then
        print_status "Starting Phoenix in interactive mode (iex)..."
        iex -S mix phx.server
    else
        # Start in background
        mix phx.server > "$LOG_DIR/phoenix.log" 2>&1 &
        echo $! > "$PID_DIR/phoenix.pid"
        
        print_status "Waiting for Phoenix to start..."
        if wait_for_service "Phoenix" 4000 30; then
            print_success "Phoenix server started on http://localhost:4000"
        else
            print_error "Phoenix failed to start. Check $LOG_DIR/phoenix.log"
            return 1
        fi
    fi
}

# Show development URLs
show_dev_urls() {
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                                                              ║"
    echo "║              ARMORICORE DEVELOPMENT SERVER                   ║"
    echo "║                                                              ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
    echo "  API Endpoints:"
    echo "    Health Check:     http://localhost:4000/api/v1/health"
    echo "    Auth:             http://localhost:4000/api/v1/auth/*"
    echo "    Videos:           http://localhost:4000/api/v1/videos"
    echo "    Categories:       http://localhost:4000/api/v1/categories"
    echo "    Live Streams:     http://localhost:4000/api/v1/live-streams"
    echo ""
    echo "  WebSocket:"
    echo "    Socket:           ws://localhost:4000/socket/websocket"
    echo ""
    echo "  Monitoring:"
    echo "    NATS Monitor:     http://localhost:8222"
    echo ""
    echo "  Logs:"
    echo "    Phoenix:          $LOG_DIR/phoenix.log"
    echo "    NATS:             $LOG_DIR/nats.log"
    echo ""
    echo "  Commands:"
    echo "    Stop all:         ./stop_all.sh"
    echo "    View logs:        tail -f $LOG_DIR/phoenix.log"
    echo ""
}

# Main function
main() {
    echo ""
    echo -e "${CYAN}Starting Armoricore Development Environment...${NC}"
    echo ""
    
    # Check for interactive mode flag
    local interactive_mode=""
    if [[ "${1:-}" == "--interactive" ]] || [[ "${1:-}" == "-i" ]]; then
        interactive_mode="--interactive"
    fi
    
    # Start services
    start_nats
    echo ""
    
    check_database
    echo ""
    
    start_phoenix $interactive_mode
    
    # Only show URLs if not in interactive mode
    if [[ -z "$interactive_mode" ]]; then
        show_dev_urls
        
        echo "Press Ctrl+C to stop, or use ./stop_all.sh"
        echo ""
        
        # Keep script running and show logs
        if [[ -f "$LOG_DIR/phoenix.log" ]]; then
            tail -f "$LOG_DIR/phoenix.log"
        fi
    fi
}

# Handle Ctrl+C
cleanup() {
    echo ""
    print_status "Stopping development server..."
    "$SCRIPT_DIR/stop_all.sh" 2>/dev/null || true
    exit 0
}

trap cleanup INT TERM

# Show help
if [[ "${1:-}" == "--help" ]] || [[ "${1:-}" == "-h" ]]; then
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -i, --interactive   Start Phoenix in interactive mode (iex)"
    echo "  -h, --help          Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                  Start in background mode"
    echo "  $0 -i               Start in interactive mode (for debugging)"
    exit 0
fi

# Run main function
main "$@"
