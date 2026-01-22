#!/bin/bash

# Armoricore v1.0.0 - Secure Communications Platform
# Copyright 2025 Francisco F. Pinochet
# Copyright 2026 Fastcomcorp, LLC
#
# Armoricore by Fastcomcorp, LLC - Enterprise-grade secure communications
# This script starts all services required for Armoricore to run

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUST_SERVICES_DIR="$SCRIPT_DIR/rust-services"
ELIXIR_SERVICES_DIR="$SCRIPT_DIR/elixir_realtime"
LOG_DIR="$SCRIPT_DIR/logs"
PID_DIR="$SCRIPT_DIR/pids"

# Load environment variables from .env file if it exists
if [ -f "$SCRIPT_DIR/.env" ]; then
    set -a
    source "$SCRIPT_DIR/.env"
    set +a
fi

# Create directories
mkdir -p "$LOG_DIR"
mkdir -p "$PID_DIR"

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

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check if a port is in use
port_in_use() {
    lsof -i :"$1" >/dev/null 2>&1 || nc -z localhost "$1" >/dev/null 2>&1
}

# Function to wait for a service to be ready
wait_for_service() {
    local service_name=$1
    local port=$2
    local max_attempts=30
    local attempt=0

    print_status "Waiting for $service_name to be ready on port $port..."
    while [ $attempt -lt $max_attempts ]; do
        if port_in_use "$port"; then
            print_success "$service_name is ready!"
            return 0
        fi
        attempt=$((attempt + 1))
        sleep 1
    done

    print_error "$service_name failed to start on port $port"
    return 1
}

# Function to check prerequisites
check_prerequisites() {
    print_status "Checking prerequisites..."

    local missing=0

    # Check Rust
    if ! command_exists cargo; then
        print_error "Rust/Cargo is not installed"
        missing=1
    else
        print_success "Rust/Cargo found: $(cargo --version)"
    fi

    # Check Elixir
    if ! command_exists mix; then
        print_error "Elixir/Mix is not installed"
        missing=1
    else
        print_success "Elixir/Mix found: $(elixir --version | head -1)"
    fi

    # Check FFmpeg
    if ! command_exists ffmpeg; then
        print_warning "FFmpeg is not installed (required for media processing)"
    else
        print_success "FFmpeg found: $(ffmpeg -version | head -1 | cut -d' ' -f3)"
    fi

    # Check NATS (optional - will start if not running)
    if command_exists nats-server; then
        print_success "NATS server found"
    else
        print_warning "NATS server not found in PATH (will check if running)"
    fi

    # Check PostgreSQL (optional - will warn if not running)
    if command_exists psql; then
        print_success "PostgreSQL client found"
    else
        print_warning "PostgreSQL client not found"
    fi

    if [ $missing -eq 1 ]; then
        print_error "Missing required prerequisites. Please install them first."
        exit 1
    fi
}

# Function to start NATS server
start_nats() {
    if port_in_use 4222; then
        print_success "NATS server is already running on port 4222"
        return 0
    fi

    print_status "Starting NATS server..."

    if command_exists nats-server; then
        # Start NATS with JetStream enabled
        nats-server -js -p 4222 -m 8222 > "$LOG_DIR/nats.log" 2>&1 &
        NATS_PID=$!
        echo $NATS_PID > "$PID_DIR/nats.pid"
        print_success "NATS server started (PID: $NATS_PID)"
        wait_for_service "NATS" 4222
    else
        print_error "NATS server not found. Please install it or start it manually."
        print_warning "You can install NATS: https://docs.nats.io/running-a-nats-service/introduction/installation"
        return 1
    fi
}

# Function to check PostgreSQL
check_postgresql() {
    # Check if DATABASE_URL is set and doesn't point to localhost
    if [ -n "$DATABASE_URL" ] && ! echo "$DATABASE_URL" | grep -q "localhost"; then
        print_success "Using remote PostgreSQL database from DATABASE_URL"
        return 0
    fi

    # Check local PostgreSQL if no remote DATABASE_URL is set
    if port_in_use 5432; then
        print_success "PostgreSQL appears to be running on port 5432"
        return 0
    else
        print_warning "PostgreSQL is not running on port 5432"
        print_warning "Elixir services require PostgreSQL. Please start it manually or set DATABASE_URL for remote database."
        return 1
    fi
}

# Function to build Rust services
build_rust_services() {
    print_status "Building Rust services..."
    cd "$RUST_SERVICES_DIR"
    
    if cargo build --release > "$LOG_DIR/rust-build.log" 2>&1; then
        print_success "Rust services built successfully"
    else
        print_error "Failed to build Rust services. Check $LOG_DIR/rust-build.log"
        exit 1
    fi
}

# Function to start Rust service
start_rust_service() {
    local service_name=$1
    local binary_name=$2
    
    print_status "Starting $service_name..."
    
    cd "$RUST_SERVICES_DIR"
    cargo run --release --bin "$binary_name" > "$LOG_DIR/$service_name.log" 2>&1 &
    local pid=$!
    echo $pid > "$PID_DIR/$service_name.pid"
    print_success "$service_name started (PID: $pid)"
    
    sleep 2  # Give service time to initialize
}

# Function to start Elixir Phoenix
start_elixir_phoenix() {
    print_status "Starting Elixir Phoenix server..."
    
    cd "$ELIXIR_SERVICES_DIR"
    
    # Check if dependencies are installed
    if [ ! -d "deps" ]; then
        print_status "Installing Elixir dependencies..."
        mix deps.get > "$LOG_DIR/elixir-deps.log" 2>&1
    fi
    
    # Run database migrations if needed
    if [ -f "mix.exs" ]; then
        print_status "Running database migrations..."
        mix ecto.migrate > "$LOG_DIR/elixir-migrate.log" 2>&1 || print_warning "Migration may have failed (check logs)"
    fi
    
    # Start Phoenix server
    mix phx.server > "$LOG_DIR/elixir-phoenix.log" 2>&1 &
    local pid=$!
    echo $pid > "$PID_DIR/elixir-phoenix.pid"
    print_success "Elixir Phoenix started (PID: $pid)"
    
    wait_for_service "Phoenix" 4000
}

# Function to stop all services
stop_all_services() {
    print_status "Stopping all services..."
    
    if [ -d "$PID_DIR" ]; then
        for pidfile in "$PID_DIR"/*.pid; do
            if [ -f "$pidfile" ]; then
                local pid=$(cat "$pidfile")
                local service=$(basename "$pidfile" .pid)
                if kill -0 "$pid" 2>/dev/null; then
                    print_status "Stopping $service (PID: $pid)..."
                    kill "$pid" 2>/dev/null || true
                    rm "$pidfile"
                fi
            fi
        done
    fi
    
    print_success "All services stopped"
}

# Function to show service status
show_status() {
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                        SERVICE STATUS                        ║"
    echo "║                Armoricore by Fastcomcorp, LLC                ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
    
    # Check NATS
    if port_in_use 4222; then
        echo -e "NATS Server:        ${GREEN}Running${NC} (port 4222)"
    else
        echo -e "NATS Server:        ${RED}Not Running${NC}"
    fi
    
    # Check PostgreSQL
    if port_in_use 5432; then
        echo -e "PostgreSQL:         ${GREEN}Running${NC} (port 5432)"
    else
        echo -e "PostgreSQL:         ${RED}Not Running${NC}"
    fi
    
    # Check Rust services
    for service in media-processor ai-workers realtime-media-engine-grpc; do
        if [ -f "$PID_DIR/$service.pid" ]; then
            local pid=$(cat "$PID_DIR/$service.pid")
            if kill -0 "$pid" 2>/dev/null; then
                echo -e "$service:  ${GREEN}Running${NC} (PID: $pid)"
            else
                echo -e "$service:  ${RED}Not Running${NC}"
            fi
        else
            echo -e "$service:  ${RED}Not Running${NC}"
        fi
    done
    
    # Check Elixir Phoenix
    if port_in_use 4000; then
        echo -e "Elixir Phoenix:    ${GREEN}Running${NC} (port 4000)"
    else
        echo -e "Elixir Phoenix:    ${RED}Not Running${NC}"
    fi
    
    echo ""
    echo "Logs directory: $LOG_DIR"
    echo "PID directory: $PID_DIR"
    echo ""
    echo "Powered by Fastcomcorp, LLC"
    echo "Enterprise-grade secure communications"
    echo ""
}

# Main function
main() {
    case "${1:-start}" in
        start)
            echo "╔══════════════════════════════════════════════════════════════╗"
            echo "║                                                              ║"
            echo "║                   ARMORICORE v1.0.0                          ║"
            echo "║            Secure Communications Platform                    ║"
            echo "║                                                              ║"
            echo "║                by Fastcomcorp, LLC                           ║"
            echo "║                                                              ║"
            echo "║  Post-Quantum Cryptography    Real-Time Messaging            ║"
            echo "║  Enterprise Security          Privacy by Design              ║"
            echo "║                                                              ║"
            echo "╚══════════════════════════════════════════════════════════════╝"
            echo ""
            echo "Starting Armoricore Secure Communications Platform..."
            echo "   Copyright 2025 Francisco F. Pinochet"
            echo "   Copyright 2026 Fastcomcorp, LLC"
            echo ""
            
            check_prerequisites
            echo ""
            
            # Start infrastructure
            start_nats
            echo ""
            
            check_postgresql
            echo ""
            
            # Build Rust services
            build_rust_services
            echo ""
            
            # Start Rust services
            start_rust_service "media-processor" "media-processor"
            start_rust_service "ai-workers" "ai-workers"
            # Note: realtime-media-engine-grpc is optional
            # start_rust_service "realtime-media-engine-grpc" "realtime-media-engine-grpc"
            echo ""
            
            # Start Elixir Phoenix
            start_elixir_phoenix
            echo ""
            
            print_success "All services started!"
            echo ""
            echo "╔══════════════════════════════════════════════════════════════╗"
            echo "║                                                              ║"
            echo "║               ARMORICORE IS NOW RUNNING!                     ║"
            echo "║                                                              ║"
            echo "╚══════════════════════════════════════════════════════════════╝"
            echo ""
            echo "Access Points:"
            echo "   API Endpoints:    http://localhost:4000/api/v1/*"
            echo "   Health Check:     http://localhost:4000/api/v1/health"
            echo "   Internal Tools:   http://localhost:4000/internal/dashboard"
            echo ""
            echo "Powered by Fastcomcorp, LLC - Enterprise Security Solutions"
            echo "Featuring Post-Quantum Cryptography & Privacy by Design"
            echo ""
            show_status
            ;;
        stop)
            stop_all_services
            ;;
        status)
            show_status
            ;;
        restart)
            stop_all_services
            sleep 2
            main start
            ;;
        *)
            echo "Usage: $0 {start|stop|status|restart}"
            echo ""
            echo "Commands:"
            echo "  start   - Start all services"
            echo "  stop    - Stop all services"
            echo "  status  - Show service status"
            echo "  restart - Restart all services"
            exit 1
            ;;
    esac
}

# Handle Ctrl+C
trap 'echo ""; print_warning "Interrupted. Use '$0' stop to stop all services."; exit 1' INT

# Run main function
main "$@"

