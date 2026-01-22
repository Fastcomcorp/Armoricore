#!/bin/bash

# Armoricore v1.0.0 - Stop All Services
# Copyright 2025 Francisco F. Pinochet
# Copyright 2026 Fastcomcorp, LLC
#
# This script stops all Armoricore services

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_DIR="$SCRIPT_DIR/pids"

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

# Stop a service by PID file
stop_service_by_pid() {
    local pidfile=$1
    local service_name=$(basename "$pidfile" .pid)
    
    if [[ -f "$pidfile" ]]; then
        local pid=$(cat "$pidfile")
        if kill -0 "$pid" 2>/dev/null; then
            print_status "Stopping $service_name (PID: $pid)..."
            kill "$pid" 2>/dev/null || true
            
            # Wait for process to stop
            local count=0
            while kill -0 "$pid" 2>/dev/null && [[ $count -lt 10 ]]; do
                sleep 1
                count=$((count + 1))
            done
            
            if kill -0 "$pid" 2>/dev/null; then
                print_warning "Force killing $service_name..."
                kill -9 "$pid" 2>/dev/null || true
            fi
            
            print_success "Stopped $service_name"
        else
            print_warning "$service_name was not running"
        fi
        rm -f "$pidfile"
    fi
}

# Stop Phoenix server
stop_phoenix() {
    print_status "Stopping Phoenix server..."
    
    # Try PID file first
    if [[ -f "$PID_DIR/elixir-phoenix.pid" ]]; then
        stop_service_by_pid "$PID_DIR/elixir-phoenix.pid"
    fi
    
    # Also try to kill by process name
    pkill -f "mix phx.server" 2>/dev/null || true
    pkill -f "beam.smp.*armoricore" 2>/dev/null || true
    
    if ! port_in_use 4000; then
        print_success "Phoenix server stopped"
    else
        print_warning "Phoenix server may still be running"
    fi
}

# Stop NATS server
stop_nats() {
    print_status "Stopping NATS server..."
    
    # Try PID file first
    if [[ -f "$PID_DIR/nats.pid" ]]; then
        stop_service_by_pid "$PID_DIR/nats.pid"
    fi
    
    # Also try to kill by process name
    pkill -f "nats-server" 2>/dev/null || true
    
    if ! port_in_use 4222; then
        print_success "NATS server stopped"
    else
        print_warning "NATS server may still be running"
    fi
}

# Stop Rust services
stop_rust_services() {
    print_status "Stopping Rust services..."
    
    for service in media-processor ai-workers realtime-media-engine-grpc live-ingest; do
        if [[ -f "$PID_DIR/$service.pid" ]]; then
            stop_service_by_pid "$PID_DIR/$service.pid"
        fi
    done
    
    # Also try to kill by process name
    pkill -f "media-processor" 2>/dev/null || true
    pkill -f "ai-workers" 2>/dev/null || true
    pkill -f "realtime-media-engine-grpc" 2>/dev/null || true
    pkill -f "live-ingest" 2>/dev/null || true
    
    print_success "Rust services stopped"
}

# Stop all services from PID directory
stop_all_pid_services() {
    if [[ -d "$PID_DIR" ]]; then
        for pidfile in "$PID_DIR"/*.pid; do
            if [[ -f "$pidfile" ]]; then
                stop_service_by_pid "$pidfile"
            fi
        done
    fi
}

# Show status after stopping
show_status() {
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                        SERVICE STATUS                        ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
    
    # Check NATS
    if port_in_use 4222; then
        echo -e "NATS Server:        ${RED}Still Running${NC} (port 4222)"
    else
        echo -e "NATS Server:        ${GREEN}Stopped${NC}"
    fi
    
    # Check Phoenix
    if port_in_use 4000; then
        echo -e "Phoenix Server:     ${RED}Still Running${NC} (port 4000)"
    else
        echo -e "Phoenix Server:     ${GREEN}Stopped${NC}"
    fi
    
    # Check gRPC
    if port_in_use 50051; then
        echo -e "gRPC Server:        ${RED}Still Running${NC} (port 50051)"
    else
        echo -e "gRPC Server:        ${GREEN}Stopped${NC}"
    fi
    
    echo ""
}

# Main function
main() {
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                                                              ║"
    echo "║                STOPPING ARMORICORE SERVICES                  ║"
    echo "║                                                              ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
    
    case "${1:-all}" in
        all)
            stop_phoenix
            stop_rust_services
            stop_nats
            stop_all_pid_services
            ;;
        phoenix|elixir)
            stop_phoenix
            ;;
        nats)
            stop_nats
            ;;
        rust)
            stop_rust_services
            ;;
        *)
            echo "Usage: $0 {all|phoenix|nats|rust}"
            echo ""
            echo "Commands:"
            echo "  all     - Stop all services (default)"
            echo "  phoenix - Stop Phoenix server only"
            echo "  nats    - Stop NATS server only"
            echo "  rust    - Stop Rust services only"
            exit 1
            ;;
    esac
    
    show_status
    
    echo ""
    print_success "Shutdown complete"
    echo ""
}

# Run main function
main "$@"
