#!/bin/bash
# Armoricore SSL Certificate Management Script
# Handles SSL certificate setup, renewal, and management for different certificate types

set -e

# Configuration
SSL_DIR="/etc/armoricore/ssl"
DOMAIN="${DOMAIN:-armoricore.local}"
EMAIL="${EMAIL:-admin@$DOMAIN}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_permissions() {
    if [[ $EUID -eq 0 ]]; then
        log_info "Running as root - proceeding with SSL setup"
    else
        log_warning "Not running as root. Some operations may require sudo."
    fi
}

# Create SSL directory
create_ssl_directory() {
    log_info "Creating SSL certificate directory..."

    sudo mkdir -p "$SSL_DIR"
    sudo chmod 755 "$SSL_DIR"

    log_success "SSL directory created: $SSL_DIR"
}

# Show certificate status
show_certificate_status() {
    log_info "Checking SSL certificate status..."

    if [ ! -f "$SSL_DIR/cert.pem" ] || [ ! -f "$SSL_DIR/key.pem" ]; then
        log_warning "SSL certificates not found in $SSL_DIR"
        return 1
    fi

    # Check certificate validity
    if command -v openssl >/dev/null 2>&1; then
        log_info "Certificate information:"
        openssl x509 -in "$SSL_DIR/cert.pem" -text -noout | grep -E "(Subject:|Issuer:|Not Before:|Not After :)" | sed 's/^/  /'

        # Check expiration
        local expiry_date
        expiry_date=$(openssl x509 -in "$SSL_DIR/cert.pem" -enddate -noout | cut -d= -f2)
        local expiry_epoch
        expiry_epoch=$(date -d "$expiry_date" +%s 2>/dev/null || date -j -f "%b %d %H:%M:%S %Y %Z" "$expiry_date" +%s 2>/dev/null)

        if [ -n "$expiry_epoch" ]; then
            local current_epoch
            current_epoch=$(date +%s)
            local days_until_expiry=$(( (expiry_epoch - current_epoch) / 86400 ))

            if [ "$days_until_expiry" -lt 0 ]; then
                log_error "Certificate has expired!"
            elif [ "$days_until_expiry" -lt 30 ]; then
                log_warning "Certificate expires in $days_until_expiry days"
            else
                log_success "Certificate is valid for $days_until_expiry more days"
            fi
        fi
    else
        log_warning "OpenSSL not available for certificate validation"
    fi
}

# Setup self-signed certificates
setup_self_signed() {
    local cert_type="${1:-rsa}"
    local days="${2:-365}"
    local key_size="${3:-2048}"

    log_info "Setting up self-signed SSL certificate..."
    log_info "Type: $cert_type, Validity: $days days, Key size: $key_size bits"

    # Check if running in Elixir project directory
    if [ ! -f "mix.exs" ]; then
        log_error "mix.exs not found. Please run this script from the Elixir project root."
        exit 1
    fi

    # Generate certificate using Phoenix
    log_info "Generating self-signed certificate..."
    mix phx.gen.cert --output-dir priv/cert --output-basename armoricore

    # Copy to SSL directory
    sudo cp priv/cert/armoricore.pem "$SSL_DIR/cert.pem"
    sudo cp priv/cert/armoricore_key.pem "$SSL_DIR/key.pem"

    # Set permissions
    sudo chown root:root "$SSL_DIR"/*
    sudo chmod 600 "$SSL_DIR/key.pem"
    sudo chmod 644 "$SSL_DIR/cert.pem"

    log_success "Self-signed SSL certificate installed"
    log_warning "⚠️  This certificate is for development/testing only!"
    log_warning "   Do not use in production - browsers will show security warnings"
}

# Setup Let's Encrypt certificates
setup_lets_encrypt() {
    local staging="${1:-false}"

    log_info "Setting up Let's Encrypt SSL certificate..."
    log_info "Domain: $DOMAIN, Email: $EMAIL"

    # Check if certbot is installed
    if ! command -v certbot >/dev/null 2>&1; then
        log_error "Certbot not found. Installing..."

        if command -v apt-get >/dev/null 2>&1; then
            sudo apt-get update
            sudo apt-get install -y certbot
        elif command -v yum >/dev/null 2>&1; then
            sudo yum install -y certbot
        else
            log_error "Please install certbot manually: https://certbot.eff.org/"
            exit 1
        fi
    fi

    # Stop web server if running (for standalone mode)
    if sudo systemctl is-active --quiet armoricore; then
        log_info "Stopping Armoricore service for certificate generation..."
        sudo systemctl stop armoricore
    fi

    # Generate certificate
    local certbot_cmd="sudo certbot certonly --standalone"

    if [ "$staging" = "true" ]; then
        certbot_cmd="$certbot_cmd --staging"
        log_info "Using Let's Encrypt staging environment (for testing)"
    fi

    certbot_cmd="$certbot_cmd -d $DOMAIN --email $EMAIL --agree-tos --non-interactive"

    log_info "Running: $certbot_cmd"
    if eval "$certbot_cmd"; then
        # Create symlinks
        sudo ln -sf "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" "$SSL_DIR/cert.pem"
        sudo ln -sf "/etc/letsencrypt/live/$DOMAIN/privkey.pem" "$SSL_DIR/key.pem"

        # Copy CA bundle if available
        if [ -f "/etc/letsencrypt/live/$DOMAIN/chain.pem" ]; then
            sudo ln -sf "/etc/letsencrypt/live/$DOMAIN/chain.pem" "$SSL_DIR/ca-bundle.crt"
        fi

        log_success "Let's Encrypt SSL certificate installed"
        log_info "Certificate will auto-renew before expiration"

        # Set up renewal hook
        setup_lets_encrypt_renewal
    else
        log_error "Let's Encrypt certificate generation failed"
        exit 1
    fi

    # Restart web server
    if sudo systemctl is-active --quiet armoricore; then
        sudo systemctl start armoricore
    fi
}

# Setup Let's Encrypt renewal
setup_lets_encrypt_renewal() {
    log_info "Setting up Let's Encrypt certificate renewal..."

    # Create renewal hook
    sudo mkdir -p /etc/letsencrypt/renewal-hooks/deploy

    sudo tee "/etc/letsencrypt/renewal-hooks/deploy/armoricore" > /dev/null << EOF
#!/bin/bash
# Armoricore SSL certificate renewal hook
# Reloads Armoricore service after certificate renewal

logger -t armoricore-ssl "SSL certificate renewed, reloading service"
sudo systemctl reload armoricore || sudo systemctl restart armoricore

# Send notification (if configured)
if command -v curl >/dev/null 2>&1 && [ -n "\$NOTIFICATION_WEBHOOK" ]; then
    curl -X POST -H 'Content-type: application/json' \
        --data '{"text":"Armoricore SSL certificate renewed for $DOMAIN"}' \
        "\$NOTIFICATION_WEBHOOK" 2>/dev/null || true
fi
EOF

    sudo chmod +x "/etc/letsencrypt/renewal-hooks/deploy/armoricore"

    # Test renewal
    log_info "Testing certificate renewal..."
    sudo certbot renew --dry-run

    log_success "Let's Encrypt renewal configured"
}

# Setup commercial certificates
setup_commercial() {
    local cert_path="${1:-/tmp/cert.pem}"
    local key_path="${2:-/tmp/key.pem}"
    local ca_path="${3:-}"

    log_info "Setting up commercial SSL certificate..."
    log_info "Certificate: $cert_path"
    log_info "Private Key: $key_path"
    if [ -n "$ca_path" ]; then
        log_info "CA Bundle: $ca_path"
    fi

    # Validate certificate files
    if [ ! -f "$cert_path" ]; then
        log_error "Certificate file not found: $cert_path"
        exit 1
    fi

    if [ ! -f "$key_path" ]; then
        log_error "Private key file not found: $key_path"
        exit 1
    fi

    # Validate certificate and key match
    if command -v openssl >/dev/null 2>&1; then
        local cert_modulus
        local key_modulus

        cert_modulus=$(openssl x509 -noout -modulus -in "$cert_path" 2>/dev/null | openssl md5)
        key_modulus=$(openssl rsa -noout -modulus -in "$key_path" 2>/dev/null | openssl md5)

        if [ "$cert_modulus" != "$key_modulus" ]; then
            log_error "Certificate and private key do not match!"
            exit 1
        fi

        log_success "Certificate and private key validation passed"
    fi

    # Copy certificates
    sudo cp "$cert_path" "$SSL_DIR/cert.pem"
    sudo cp "$key_path" "$SSL_DIR/key.pem"

    if [ -n "$ca_path" ] && [ -f "$ca_path" ]; then
        sudo cp "$ca_path" "$SSL_DIR/ca-bundle.crt"
    fi

    # Set permissions
    sudo chown root:root "$SSL_DIR"/*
    sudo chmod 600 "$SSL_DIR/key.pem"
    sudo chmod 644 "$SSL_DIR/cert.pem"
    if [ -f "$SSL_DIR/ca-bundle.crt" ]; then
        sudo chmod 644 "$SSL_DIR/ca-bundle.crt"
    fi

    log_success "Commercial SSL certificate installed"
    log_warning "📅 Commercial certificates require manual renewal"
    log_warning "   Set up calendar reminders for certificate expiration"
}

# Renew Let's Encrypt certificates
renew_lets_encrypt() {
    log_info "Renewing Let's Encrypt SSL certificates..."

    if ! sudo certbot renew; then
        log_error "Certificate renewal failed"
        exit 1
    fi

    log_success "SSL certificates renewed successfully"
}

# Backup certificates
backup_certificates() {
    local backup_dir="${1:-/opt/armoricore/ssl-backups}"
    local timestamp
    timestamp=$(date +%Y%m%d_%H%M%S)

    log_info "Backing up SSL certificates to $backup_dir..."

    sudo mkdir -p "$backup_dir"
    sudo cp -r "$SSL_DIR" "$backup_dir/backup_$timestamp"

    # Create backup manifest
    sudo tee "$backup_dir/backup_$timestamp/manifest.txt" > /dev/null << EOF
SSL Certificate Backup
Created: $(date)
Source: $SSL_DIR
Certificate: $(openssl x509 -in "$SSL_DIR/cert.pem" -subject -noout 2>/dev/null || echo 'Unknown')
Expires: $(openssl x509 -in "$SSL_DIR/cert.pem" -enddate -noout 2>/dev/null || echo 'Unknown')
EOF

    log_success "SSL certificates backed up to $backup_dir/backup_$timestamp"
}

# Show usage information
show_usage() {
    cat << EOF
Armoricore SSL Certificate Management Script

USAGE:
    $0 [COMMAND] [OPTIONS]

COMMANDS:
    status              Show current SSL certificate status
    self-signed         Generate and install self-signed certificate
        [--type rsa|ecdsa] [--days DAYS] [--key-size SIZE]

    lets-encrypt        Obtain and install Let's Encrypt certificate
        [--staging]     Use Let's Encrypt staging environment

    commercial          Install commercial SSL certificate
        CERT_FILE KEY_FILE [CA_FILE]

    renew               Renew Let's Encrypt certificates
    backup [DIR]        Backup current certificates to directory

CONFIGURATION:
    Set these environment variables:
    DOMAIN=yourdomain.com          # Domain name for certificates
    EMAIL=admin@yourdomain.com     # Email for Let's Encrypt
    SSL_DIR=/etc/armoricore/ssl   # SSL certificate directory

EXAMPLES:
    # Check certificate status
    $0 status

    # Generate self-signed certificate for development
    $0 self-signed

    # Get Let's Encrypt certificate for production
    DOMAIN=armoricore.com EMAIL=admin@armoricore.com $0 lets-encrypt

    # Install commercial certificate
    $0 commercial /path/to/cert.pem /path/to/key.pem /path/to/ca-bundle.crt

    # Renew Let's Encrypt certificates
    $0 renew

    # Backup certificates
    $0 backup /opt/armoricore/ssl-backups

NOTES:
    - Self-signed certificates are for development only
    - Let's Encrypt certificates auto-renew
    - Commercial certificates require manual renewal
    - Run as root or with sudo for certificate installation
EOF
}

# Main script logic
main() {
    check_permissions
    create_ssl_directory

    case "${1:-status}" in
        "status")
            show_certificate_status
            ;;
        "self-signed")
            shift
            local cert_type="rsa"
            local days="365"
            local key_size="2048"

            while [[ $# -gt 0 ]]; do
                case $1 in
                    --type)
                        cert_type="$2"
                        shift 2
                        ;;
                    --days)
                        days="$2"
                        shift 2
                        ;;
                    --key-size)
                        key_size="$2"
                        shift 2
                        ;;
                    *)
                        log_error "Unknown option: $1"
                        show_usage
                        exit 1
                        ;;
                esac
            done

            setup_self_signed "$cert_type" "$days" "$key_size"
            ;;
        "lets-encrypt")
            shift
            local staging="false"

            while [[ $# -gt 0 ]]; do
                case $1 in
                    --staging)
                        staging="true"
                        shift
                        ;;
                    *)
                        log_error "Unknown option: $1"
                        show_usage
                        exit 1
                        ;;
                esac
            done

            setup_lets_encrypt "$staging"
            ;;
        "commercial")
            if [ $# -lt 3 ]; then
                log_error "Commercial certificate setup requires certificate and key files"
                show_usage
                exit 1
            fi
            setup_commercial "$2" "$3" "$4"
            ;;
        "renew")
            renew_lets_encrypt
            ;;
        "backup")
            backup_certificates "$2"
            ;;
        "help"|"-h"|"--help")
            show_usage
            ;;
        *)
            log_error "Unknown command: $1"
            show_usage
            exit 1
            ;;
    esac
}

# Run main function
main "$@"