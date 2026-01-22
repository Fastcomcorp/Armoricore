#!/bin/bash

# Armoricore v1.0.0 - Installation Script
# Copyright 2025 Francisco F. Pinochet
# Copyright 2026 Fastcomcorp, LLC
#
# This script installs all dependencies and sets up Armoricore
# for development or production use.

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
LOG_DIR="$SCRIPT_DIR/logs"
INSTALL_LOG="$LOG_DIR/install.log"

# Create log directory
mkdir -p "$LOG_DIR"

# Function to print status
print_header() {
    echo -e "${CYAN}$1${NC}"
}

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
    echo "[INFO] $1" >> "$INSTALL_LOG"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
    echo "[SUCCESS] $1" >> "$INSTALL_LOG"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    echo "[ERROR] $1" >> "$INSTALL_LOG"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
    echo "[WARNING] $1" >> "$INSTALL_LOG"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Detect OS
detect_os() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
        PACKAGE_MANAGER="brew"
    elif [[ -f /etc/debian_version ]]; then
        OS="debian"
        PACKAGE_MANAGER="apt"
    elif [[ -f /etc/redhat-release ]]; then
        OS="redhat"
        PACKAGE_MANAGER="yum"
    elif [[ -f /etc/arch-release ]]; then
        OS="arch"
        PACKAGE_MANAGER="pacman"
    else
        OS="unknown"
        PACKAGE_MANAGER="unknown"
    fi
    print_status "Detected OS: $OS (package manager: $PACKAGE_MANAGER)"
}

# Print banner
print_banner() {
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                                                              ║"
    echo "║                   ARMORICORE v1.0.0                          ║"
    echo "║            Secure Communications Platform                    ║"
    echo "║                                                              ║"
    echo "║                    INSTALLATION                              ║"
    echo "║                                                              ║"
    echo "║                by Fastcomcorp, LLC                           ║"
    echo "║                                                              ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
    echo "   Copyright 2025 Francisco F. Pinochet"
    echo "   Copyright 2026 Fastcomcorp, LLC"
    echo ""
}

# Check system requirements
check_system_requirements() {
    print_header "Checking System Requirements..."
    echo ""
    
    local missing=0
    
    # Check for basic tools
    for cmd in curl wget git make; do
        if command_exists "$cmd"; then
            print_success "$cmd found"
        else
            print_error "$cmd not found"
            missing=1
        fi
    done
    
    # Check disk space (need at least 5GB)
    local available_space
    if [[ "$OS" == "macos" ]]; then
        available_space=$(df -g "$SCRIPT_DIR" | tail -1 | awk '{print $4}')
    else
        available_space=$(df -BG "$SCRIPT_DIR" | tail -1 | awk '{print $4}' | sed 's/G//')
    fi
    
    if [[ "$available_space" -ge 5 ]]; then
        print_success "Disk space: ${available_space}GB available (minimum 5GB)"
    else
        print_warning "Low disk space: ${available_space}GB available (recommend 5GB)"
    fi
    
    # Check RAM (recommend at least 4GB)
    local total_ram
    if [[ "$OS" == "macos" ]]; then
        total_ram=$(($(sysctl -n hw.memsize) / 1024 / 1024 / 1024))
    else
        total_ram=$(($(grep MemTotal /proc/meminfo | awk '{print $2}') / 1024 / 1024))
    fi
    
    if [[ "$total_ram" -ge 4 ]]; then
        print_success "RAM: ${total_ram}GB available (minimum 4GB)"
    else
        print_warning "Low RAM: ${total_ram}GB available (recommend 4GB)"
    fi
    
    echo ""
    
    if [[ $missing -eq 1 ]]; then
        print_error "Missing required tools. Please install them first."
        exit 1
    fi
}

# Install Homebrew (macOS)
install_homebrew() {
    if [[ "$OS" != "macos" ]]; then
        return 0
    fi
    
    if command_exists brew; then
        print_success "Homebrew already installed"
        return 0
    fi
    
    print_status "Installing Homebrew..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    print_success "Homebrew installed"
}

# Install Elixir and Erlang
install_elixir() {
    print_header "Installing Elixir/Erlang..."
    
    if command_exists elixir && command_exists mix; then
        local elixir_version=$(elixir --version | head -1)
        print_success "Elixir already installed: $elixir_version"
        return 0
    fi
    
    case "$PACKAGE_MANAGER" in
        brew)
            print_status "Installing Elixir via Homebrew..."
            brew install elixir
            ;;
        apt)
            print_status "Installing Elixir via apt..."
            sudo apt-get update
            sudo apt-get install -y erlang elixir
            ;;
        yum)
            print_status "Installing Elixir via yum..."
            sudo yum install -y erlang elixir
            ;;
        pacman)
            print_status "Installing Elixir via pacman..."
            sudo pacman -S --noconfirm elixir
            ;;
        *)
            print_error "Cannot install Elixir automatically. Please install manually."
            print_status "Visit: https://elixir-lang.org/install.html"
            exit 1
            ;;
    esac
    
    print_success "Elixir installed: $(elixir --version | head -1)"
}

# Install Rust
install_rust() {
    print_header "Installing Rust..."
    
    if command_exists cargo && command_exists rustc; then
        local rust_version=$(rustc --version)
        print_success "Rust already installed: $rust_version"
        return 0
    fi
    
    print_status "Installing Rust via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    
    # Source cargo environment
    source "$HOME/.cargo/env" 2>/dev/null || true
    
    if command_exists cargo; then
        print_success "Rust installed: $(rustc --version)"
    else
        print_warning "Rust installed but not in PATH. Please restart your terminal or run: source ~/.cargo/env"
    fi
}

# Install NATS Server
install_nats() {
    print_header "Installing NATS Server..."
    
    if command_exists nats-server; then
        local nats_version=$(nats-server --version 2>&1 | head -1)
        print_success "NATS already installed: $nats_version"
        return 0
    fi
    
    case "$PACKAGE_MANAGER" in
        brew)
            print_status "Installing NATS via Homebrew..."
            brew install nats-server
            ;;
        apt)
            print_status "Installing NATS via apt..."
            curl -L https://github.com/nats-io/nats-server/releases/download/v2.10.5/nats-server-v2.10.5-linux-amd64.tar.gz -o /tmp/nats-server.tar.gz
            tar -xzf /tmp/nats-server.tar.gz -C /tmp
            sudo mv /tmp/nats-server-v2.10.5-linux-amd64/nats-server /usr/local/bin/
            rm -rf /tmp/nats-server*
            ;;
        yum)
            print_status "Installing NATS via binary..."
            curl -L https://github.com/nats-io/nats-server/releases/download/v2.10.5/nats-server-v2.10.5-linux-amd64.tar.gz -o /tmp/nats-server.tar.gz
            tar -xzf /tmp/nats-server.tar.gz -C /tmp
            sudo mv /tmp/nats-server-v2.10.5-linux-amd64/nats-server /usr/local/bin/
            rm -rf /tmp/nats-server*
            ;;
        *)
            print_warning "Cannot install NATS automatically. Please install manually."
            print_status "Visit: https://docs.nats.io/running-a-nats-service/introduction/installation"
            return 1
            ;;
    esac
    
    if command_exists nats-server; then
        print_success "NATS installed: $(nats-server --version 2>&1 | head -1)"
    fi
}

# Install FFmpeg
install_ffmpeg() {
    print_header "Installing FFmpeg..."
    
    if command_exists ffmpeg; then
        local ffmpeg_version=$(ffmpeg -version 2>&1 | head -1 | cut -d' ' -f3)
        print_success "FFmpeg already installed: $ffmpeg_version"
        return 0
    fi
    
    case "$PACKAGE_MANAGER" in
        brew)
            print_status "Installing FFmpeg via Homebrew..."
            brew install ffmpeg
            ;;
        apt)
            print_status "Installing FFmpeg via apt..."
            sudo apt-get update
            sudo apt-get install -y ffmpeg
            ;;
        yum)
            print_status "Installing FFmpeg via yum..."
            sudo yum install -y epel-release
            sudo yum install -y ffmpeg ffmpeg-devel
            ;;
        pacman)
            print_status "Installing FFmpeg via pacman..."
            sudo pacman -S --noconfirm ffmpeg
            ;;
        *)
            print_warning "Cannot install FFmpeg automatically. Please install manually."
            return 1
            ;;
    esac
    
    if command_exists ffmpeg; then
        print_success "FFmpeg installed: $(ffmpeg -version 2>&1 | head -1 | cut -d' ' -f3)"
    fi
}

# Install PostgreSQL client
install_postgresql() {
    print_header "Checking PostgreSQL..."
    
    if command_exists psql; then
        print_success "PostgreSQL client already installed"
        return 0
    fi
    
    case "$PACKAGE_MANAGER" in
        brew)
            print_status "Installing PostgreSQL client via Homebrew..."
            brew install libpq
            brew link --force libpq
            ;;
        apt)
            print_status "Installing PostgreSQL client via apt..."
            sudo apt-get update
            sudo apt-get install -y postgresql-client
            ;;
        yum)
            print_status "Installing PostgreSQL client via yum..."
            sudo yum install -y postgresql
            ;;
        *)
            print_warning "Cannot install PostgreSQL client automatically."
            ;;
    esac
    
    if command_exists psql; then
        print_success "PostgreSQL client installed"
    else
        print_warning "PostgreSQL client not installed (optional for remote database)"
    fi
}

# Setup Elixir project
setup_elixir_project() {
    print_header "Setting up Elixir Project..."
    
    cd "$SCRIPT_DIR/elixir_realtime"
    
    # Install Hex and Rebar
    print_status "Installing Hex package manager..."
    mix local.hex --force >> "$INSTALL_LOG" 2>&1
    
    print_status "Installing Rebar..."
    mix local.rebar --force >> "$INSTALL_LOG" 2>&1
    
    # Get dependencies
    print_status "Fetching Elixir dependencies..."
    mix deps.get >> "$INSTALL_LOG" 2>&1
    
    # Compile
    print_status "Compiling Elixir project..."
    mix compile >> "$INSTALL_LOG" 2>&1
    
    print_success "Elixir project setup complete"
}

# Setup Rust project
setup_rust_project() {
    print_header "Setting up Rust Project..."
    
    cd "$SCRIPT_DIR/rust-services"
    
    # Ensure cargo is in path
    source "$HOME/.cargo/env" 2>/dev/null || true
    
    # Build in release mode
    print_status "Building Rust services (this may take a few minutes)..."
    cargo build --release >> "$INSTALL_LOG" 2>&1
    
    print_success "Rust project setup complete"
}

# Create environment file
create_env_file() {
    print_header "Creating Environment Configuration..."
    
    if [[ -f "$SCRIPT_DIR/.env" ]]; then
        print_warning ".env file already exists. Skipping..."
        return 0
    fi
    
    cat > "$SCRIPT_DIR/.env" << 'EOF'
# Armoricore Environment Configuration
# Generated by install.sh

# Environment (development, test, production)
MIX_ENV=dev

# Database Configuration
# For remote PostgreSQL (Aiven), set your DATABASE_URL:
# DATABASE_URL=postgres://user:password@host:port/database?sslmode=require

# For local PostgreSQL:
# DATABASE_URL=postgres://postgres:postgres@localhost:5432/armoricore_dev

# NATS Message Bus
NATS_URL=nats://localhost:4222

# Redis (optional - for caching and rate limiting)
# REDIS_URL=redis://localhost:6379

# ArcRTC Media Engine (optional)
MEDIA_ENGINE_GRPC_URL=http://localhost:50052

# Server Configuration
PORT=4000
HOST=localhost

# Security - Generate these for production!
# SECRET_KEY_BASE=$(mix phx.gen.secret)
# ARMORICORE_MASTER_KEY=$(openssl rand -base64 32)

# Logging
LOG_LEVEL=debug

# Feature Flags
ENABLE_LIVE_STREAMING=true
ENABLE_AI_FEATURES=true
ENABLE_E2EE=true
EOF
    
    print_success "Created .env configuration file"
    print_warning "Please edit .env and configure your DATABASE_URL"
}

# Verify installation
verify_installation() {
    print_header "Verifying Installation..."
    echo ""
    
    local all_good=true
    
    # Check Elixir
    if command_exists elixir && command_exists mix; then
        print_success "Elixir: $(elixir --version | head -1)"
    else
        print_error "Elixir: Not installed"
        all_good=false
    fi
    
    # Check Rust
    source "$HOME/.cargo/env" 2>/dev/null || true
    if command_exists cargo && command_exists rustc; then
        print_success "Rust: $(rustc --version)"
    else
        print_error "Rust: Not installed"
        all_good=false
    fi
    
    # Check NATS
    if command_exists nats-server; then
        print_success "NATS: $(nats-server --version 2>&1 | head -1)"
    else
        print_warning "NATS: Not installed (optional)"
    fi
    
    # Check FFmpeg
    if command_exists ffmpeg; then
        print_success "FFmpeg: $(ffmpeg -version 2>&1 | head -1 | cut -d' ' -f3)"
    else
        print_warning "FFmpeg: Not installed (required for media processing)"
    fi
    
    # Check PostgreSQL client
    if command_exists psql; then
        print_success "PostgreSQL client: Installed"
    else
        print_warning "PostgreSQL client: Not installed (optional for remote database)"
    fi
    
    # Check Elixir project
    if [[ -d "$SCRIPT_DIR/elixir_realtime/deps" ]]; then
        print_success "Elixir dependencies: Installed"
    else
        print_error "Elixir dependencies: Not installed"
        all_good=false
    fi
    
    # Check Rust build
    if [[ -f "$SCRIPT_DIR/rust-services/target/release/media-processor" ]] || [[ -d "$SCRIPT_DIR/rust-services/target/release" ]]; then
        print_success "Rust services: Built"
    else
        print_warning "Rust services: Not built (run: cd rust-services && cargo build --release)"
    fi
    
    echo ""
    
    if $all_good; then
        return 0
    else
        return 1
    fi
}

# Print next steps
print_next_steps() {
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                                                              ║"
    echo "║                INSTALLATION COMPLETE!                        ║"
    echo "║                                                              ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
    echo "Next Steps:"
    echo ""
    echo "  1. Configure your database:"
    echo "     Edit .env and set DATABASE_URL"
    echo ""
    echo "  2. Run database migrations:"
    echo "     cd elixir_realtime && mix ecto.migrate"
    echo ""
    echo "  3. Start Armoricore:"
    echo "     ./start_all.sh"
    echo ""
    echo "  OR for development (faster startup):"
    echo "     ./start_all_skip_rust.sh"
    echo ""
    echo "  4. Access the API:"
    echo "     Health Check: http://localhost:4000/api/v1/health"
    echo "     API Docs:     http://localhost:4000/api/v1/"
    echo ""
    echo "Documentation:"
    echo "  - README.md           - Getting started guide"
    echo "  - CONFIGURATION.md    - Configuration options"
    echo "  - API_REFERENCE.md    - API documentation"
    echo "  - ARCHITECTURE.md     - System architecture"
    echo ""
    echo "Logs:"
    echo "  - $LOG_DIR/install.log"
    echo ""
    echo "Powered by Fastcomcorp, LLC - Enterprise Security Solutions"
    echo ""
}

# Main installation function
main() {
    local skip_deps=false
    local skip_rust=false
    local verify_only=false
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --skip-deps)
                skip_deps=true
                shift
                ;;
            --skip-rust)
                skip_rust=true
                shift
                ;;
            --verify)
                verify_only=true
                shift
                ;;
            --help|-h)
                echo "Usage: $0 [options]"
                echo ""
                echo "Options:"
                echo "  --skip-deps    Skip dependency installation"
                echo "  --skip-rust    Skip Rust project build"
                echo "  --verify       Only verify installation"
                echo "  --help         Show this help message"
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
    
    # Initialize log
    echo "Armoricore Installation Log - $(date)" > "$INSTALL_LOG"
    
    print_banner
    
    if $verify_only; then
        verify_installation
        exit $?
    fi
    
    detect_os
    check_system_requirements
    
    if ! $skip_deps; then
        echo ""
        print_header "Installing Dependencies..."
        echo ""
        
        [[ "$OS" == "macos" ]] && install_homebrew
        install_elixir
        install_rust
        install_nats
        install_ffmpeg
        install_postgresql
    fi
    
    echo ""
    setup_elixir_project
    
    if ! $skip_rust; then
        echo ""
        setup_rust_project
    else
        print_warning "Skipping Rust build (use --skip-rust to skip)"
    fi
    
    echo ""
    create_env_file
    
    echo ""
    verify_installation
    
    print_next_steps
}

# Run main function
main "$@"
