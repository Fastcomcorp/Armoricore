#!/bin/bash
# Armoricore Production Setup Script
# Run this script to configure Armoricore for production deployment
# Generated: January 21, 2026

set -e

echo "🚀 Setting up Armoricore for Production Deployment"
echo "================================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# Check if running as root or with sudo
if [[ $EUID -eq 0 ]]; then
    print_error "This script should not be run as root. Please run as a regular user with sudo privileges when needed."
    exit 1
fi

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check system requirements
print_status "Checking system requirements..."

# Check for required commands
REQUIRED_COMMANDS=("curl" "wget" "git" "make" "gcc" "openssl")
for cmd in "${REQUIRED_COMMANDS[@]}"; do
    if ! command_exists "$cmd"; then
        print_error "Required command '$cmd' not found. Please install it first."
        exit 1
    fi
done

print_success "System requirements check passed"

# Install NATS Server
print_status "Installing NATS Server..."
if ! command_exists "nats-server"; then
    if command_exists "brew"; then
        brew install nats-server
    elif command_exists "apt-get"; then
        sudo apt-get update
        sudo apt-get install -y nats-server
    elif command_exists "yum"; then
        sudo yum install -y nats-server
    else
        print_error "Package manager not found. Please install NATS Server manually."
        print_status "Visit: https://docs.nats.io/running-a-nats-service/introduction/installation"
        exit 1
    fi
fi

print_success "NATS Server installed"

# Create NATS directories
print_status "Creating NATS directories..."
sudo mkdir -p /opt/nats/jetstream
sudo mkdir -p /var/log/nats
sudo mkdir -p /etc/nats

# Set proper permissions
sudo chown -R $USER:$USER /opt/nats
sudo chown -R $USER:$USER /var/log/nats

print_success "NATS directories created"

# Copy NATS configuration
print_status "Installing NATS configuration..."
if [ -f "nats-server.conf" ]; then
    sudo cp nats-server.conf /etc/nats/nats-server.conf
    sudo chown root:root /etc/nats/nats-server.conf
    sudo chmod 644 /etc/nats/nats-server.conf
    print_success "NATS configuration installed"
else
    print_error "nats-server.conf not found. Please ensure it exists in the current directory."
    exit 1
fi

# Test NATS configuration
print_status "Testing NATS configuration..."
if nats-server -c /etc/nats/nats-server.conf --test; then
    print_success "NATS configuration is valid"
else
    print_error "NATS configuration test failed"
    exit 1
fi

# Generate production secrets
print_status "Generating production secrets..."

# Phoenix secret key base
SECRET_KEY_BASE=$(mix phx.gen.secret)
echo "export SECRET_KEY_BASE=\"$SECRET_KEY_BASE\"" >> .env.production

# Armoricore master key
ARMORICORE_MASTER_KEY=$(openssl rand -base64 32)
echo "export ARMORICORE_MASTER_KEY=\"$ARMORICORE_MASTER_KEY\"" >> .env.production

# NATS tokens (from config file)
echo "export NATS_TOKEN=\"armoricore-production-token-2026\"" >> .env.production
echo "export NATS_CLUSTER_TOKEN=\"armoricore-cluster-token-2026\"" >> .env.production
echo "export NATS_WS_TOKEN=\"armoricore-ws-token-2026\"" >> .env.production

print_success "Production secrets generated and saved to .env.production"

# Set up environment variables
print_status "Setting up environment variables..."

cat > .env.production << EOF
# Armoricore Production Environment Configuration
# Generated: $(date)

# Phoenix Configuration
export MIX_ENV=prod
export SECRET_KEY_BASE="$SECRET_KEY_BASE"
export ARMORICORE_MASTER_KEY="$ARMORICORE_MASTER_KEY"

# Database Configuration
# Set your database connection string here
# Example for Aiven PostgreSQL:
# export DATABASE_URL="postgres://username:password@hostname:port/database?sslmode=require"
# Example for local PostgreSQL:
# export DATABASE_URL="postgres://postgres:postgres@localhost:5432/armoricore_prod"
export DATABASE_URL="${DATABASE_URL:-postgres://postgres:postgres@localhost:5432/armoricore_prod}"

# NATS Message Bus
export NATS_URL="nats://armoricore-production-token-2026@localhost:4222"
export NATS_CLUSTER_TOKEN="armoricore-cluster-token-2026"
export NATS_WS_TOKEN="armoricore-ws-token-2026"

# ArcRTC Media Engine (when available)
export ARCRTC_MEDIA_ENGINE_URL="grpc://localhost:50051"

# Redis (optional, for caching)
# export REDIS_URL="redis://localhost:6379"

# SSL Configuration
export SSL_CERT_PATH="/etc/armoricore/ssl/cert.pem"
export SSL_KEY_PATH="/etc/armoricore/ssl/key.pem"
export SSL_CA_PATH="/etc/armoricore/ssl/ca-bundle.crt"

# External API Keys (set these manually)
# export OPENAI_API_KEY="your-openai-key"
# export DEEPGRAM_API_KEY="your-deepgram-key"
# export ASSEMBLYAI_API_KEY="your-assemblyai-key"

# Monitoring and Logging
export LOG_LEVEL=info
export METRICS_ENABLED=true

# Security
export FORCE_SSL=true
export SESSION_COOKIE_SECURE=true
EOF

print_success "Environment configuration created"

# Set up SSL certificates
print_status "Setting up SSL certificates..."

# Certificate setup options
CERT_TYPE="${CERT_TYPE:-self-signed}"  # Options: self-signed, lets-encrypt, commercial
export DOMAIN="${DOMAIN:-armoricore.local}"
export EMAIL="${EMAIL:-admin@$DOMAIN}"

case "$CERT_TYPE" in
    "self-signed")
        print_info "Setting up self-signed SSL certificate for development..."
        if ! ./ssl_setup.sh self-signed; then
            print_error "Self-signed certificate setup failed"
            exit 1
        fi
        print_success "Self-signed SSL certificates generated and installed"
        print_warning "⚠️  Self-signed certificates are for development only!"
        print_warning "   For production, use: CERT_TYPE=lets-encrypt or CERT_TYPE=commercial"
        ;;

    "lets-encrypt")
        print_status "Setting up Let's Encrypt SSL certificate..."

        if ! command_exists "certbot"; then
            print_error "certbot not found. Installing certbot..."
            if command_exists "apt-get"; then
                sudo apt-get update
                sudo apt-get install -y certbot
            elif command_exists "yum"; then
                sudo yum install -y certbot
            else
                print_error "Please install certbot manually: https://certbot.eff.org/"
                print_error "Then run: sudo certbot certonly --standalone -d $DOMAIN"
                exit 1
            fi
        fi

        # Get Let's Encrypt certificate
        sudo certbot certonly --standalone \
            -d "$DOMAIN" \
            --email "admin@$DOMAIN" \
            --agree-tos \
            --non-interactive \
            --cert-name armoricore

        # Create symlinks to Let's Encrypt certificates
        sudo ln -sf /etc/letsencrypt/live/armoricore/fullchain.pem /etc/armoricore/ssl/cert.pem
        sudo ln -sf /etc/letsencrypt/live/armoricore/privkey.pem /etc/armoricore/ssl/key.pem

        print_success "Let's Encrypt SSL certificates configured"
        print_info "Certificate will auto-renew. Setup renewal cron job if needed."
        ;;

    "commercial")
        print_status "Setting up commercial SSL certificate..."

        # Check if certificates are provided
        CERT_PATH="${CERT_PATH:-/etc/ssl/certs/armoricore.crt}"
        KEY_PATH="${KEY_PATH:-/etc/ssl/private/armoricore.key}"
        CA_PATH="${CA_PATH:-/etc/ssl/certs/ca-bundle.crt}"

        if [ ! -f "$CERT_PATH" ] || [ ! -f "$KEY_PATH" ]; then
            print_error "Commercial certificates not found!"
            print_error "Please provide certificate files or set CERT_PATH and KEY_PATH environment variables."
            print_error ""
            print_error "Expected locations:"
            print_error "  Certificate: $CERT_PATH"
            print_error "  Private Key: $KEY_PATH"
            print_error "  CA Bundle: $CA_PATH (optional)"
            print_error ""
            print_error "Usage:"
            print_error "  CERT_TYPE=commercial CERT_PATH=/path/to/cert.crt KEY_PATH=/path/to/key.key ./setup_production.sh"
            exit 1
        fi

        # Copy commercial certificates
        sudo cp "$CERT_PATH" /etc/armoricore/ssl/cert.pem
        sudo cp "$KEY_PATH" /etc/armoricore/ssl/key.pem

        if [ -f "$CA_PATH" ]; then
            sudo cp "$CA_PATH" /etc/armoricore/ssl/ca-bundle.crt
        fi

        print_success "Commercial SSL certificates installed"
        ;;

    *)
        print_error "Invalid CERT_TYPE: $CERT_TYPE"
        print_error "Supported types: self-signed, lets-encrypt, commercial"
        exit 1
        ;;
esac

# Set proper permissions for all certificate types
sudo chown root:root /etc/armoricore/ssl/*
sudo chmod 600 /etc/armoricore/ssl/key.pem
sudo chmod 644 /etc/armoricore/ssl/cert.pem

if [ -f "/etc/armoricore/ssl/ca-bundle.crt" ]; then
    sudo chmod 644 /etc/armoricore/ssl/ca-bundle.crt
fi

print_success "SSL certificates configured successfully"

# Add certificate renewal reminders
case "$CERT_TYPE" in
    "lets-encrypt")
        print_info "📅 Let's Encrypt certificates renew automatically"
        print_info "   Monitor: sudo certbot renew --dry-run"
        ;;
    "commercial")
        print_warning "📅 Commercial certificates require manual renewal"
        print_warning "   Set up calendar reminders for certificate expiration"
        ;;
    "self-signed")
        print_warning "📅 Self-signed certificates do not expire but are not trusted"
        print_warning "   Replace with proper certificates for production"
        ;;
esac

# Create systemd service file
print_status "Creating systemd service..."

cat > armoricore.service << EOF
[Unit]
Description=Armoricore Real-time Platform
After=network.target postgresql.service nats-server.service
Requires=nats-server.service
Wants=postgresql.service

[Service]
Type=simple
User=$USER
Group=$USER
WorkingDirectory=$(pwd)
Environment=MIX_ENV=prod
EnvironmentFile=$(pwd)/.env.production
ExecStart=$(pwd)/_build/prod/rel/armoricore/bin/armoricore start
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

# Security settings
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=strict
ReadWritePaths=$(pwd)
ReadWritePaths=/tmp
ReadWritePaths=/var/log/armoricore

[Install]
WantedBy=multi-user.target
EOF

sudo cp armoricore.service /etc/systemd/system/
sudo systemctl daemon-reload

print_success "Systemd service created"

# Set up log rotation
print_status "Setting up log rotation..."

cat > armoricore-logrotate.conf << EOF
/var/log/armoricore/*.log {
    daily
    missingok
    rotate 52
    compress
    delaycompress
    notifempty
    create 644 $USER $USER
    postrotate
        systemctl reload armoricore.service || true
    endscript
}
EOF

sudo cp armoricore-logrotate.conf /etc/logrotate.d/armoricore

print_success "Log rotation configured"

# Create application directory structure
print_status "Creating application directories..."

sudo mkdir -p /var/log/armoricore
sudo mkdir -p /opt/armoricore/uploads
sudo mkdir -p /opt/armoricore/streams

# Set proper permissions
sudo chown -R $USER:$USER /var/log/armoricore
sudo chown -R $USER:$USER /opt/armoricore

print_success "Application directories created"

# Final instructions
print_success "🎉 Production setup completed successfully!"
echo ""
echo "Next steps:"
echo "1. Review and customize the generated .env.production file"
echo "2. Set up external API keys (OpenAI, Deepgram, etc.)"
echo "3. Configure SSL certificates for production domain"
echo "4. Test the NATS server: sudo systemctl start nats-server"
echo "5. Test the application: sudo systemctl start armoricore"
echo "6. Set up monitoring and alerting"
echo "7. Configure backup and disaster recovery"
echo ""
print_warning "Remember to:"
echo "- Keep .env.production secure and never commit it to version control"
echo "- Set up proper firewall rules for production ports"
echo "- Configure SSL certificate renewal (Let's Encrypt or commercial)"
echo "- Set up monitoring and alerting for production metrics"
echo "- Test failover scenarios and backup restoration"