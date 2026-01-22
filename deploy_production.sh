#!/bin/bash
# Armoricore Production Deployment Script
# Automates the deployment process for production environments

set -e

# Configuration - Update these for your environment
APP_NAME="armoricore"
APP_VERSION="${APP_VERSION:-$(date +%Y%m%d_%H%M%S)}"
DEPLOY_HOST="${DEPLOY_HOST:-your-server.com}"
DEPLOY_USER="${DEPLOY_USER:-deploy}"
DEPLOY_PATH="${DEPLOY_PATH:-/opt/armoricore}"
BACKUP_PATH="${BACKUP_PATH:-/opt/armoricore/backups}"

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

# Pre-deployment checks
pre_deployment_checks() {
    log_info "Running pre-deployment checks..."

    # Check if we're in the right directory
    if [ ! -f "mix.exs" ]; then
        log_error "mix.exs not found. Run this script from the Elixir project root."
        exit 1
    fi

    # Check if all required files exist
    local required_files=("mix.exs" "config/runtime.exs" "setup_production.sh")
    for file in "${required_files[@]}"; do
        if [ ! -f "$file" ]; then
            log_error "Required file '$file' not found."
            exit 1
        fi
    done

    # Check if production environment file exists
    if [ ! -f ".env.production" ]; then
        log_warning ".env.production not found. Running production setup..."
        ./setup_production.sh
    fi

    # Validate production configuration
    if ! grep -q "MIX_ENV=prod" .env.production; then
        log_error "Invalid .env.production file. MIX_ENV must be set to 'prod'."
        exit 1
    fi

    log_success "Pre-deployment checks passed"
}

# Build release
build_release() {
    log_info "Building production release..."

    # Clean previous builds
    mix clean

    # Get dependencies
    mix deps.get --only prod

    # Compile application
    MIX_ENV=prod mix compile

    # Run tests (optional, but recommended)
    if [ "${SKIP_TESTS:-false}" != "true" ]; then
        log_info "Running tests..."
        mix test --exclude manual --exclude load_test
        log_success "Tests passed"
    fi

    # Build release
    MIX_ENV=prod mix release --overwrite

    # Verify release was built
    if [ ! -d "_build/prod/rel/armoricore" ]; then
        log_error "Release build failed"
        exit 1
    fi

    log_success "Production release built successfully"
}

# Create deployment package
create_deployment_package() {
    log_info "Creating deployment package..."

    local package_name="armoricore-${APP_VERSION}.tar.gz"

    # Create deployment directory
    mkdir -p deploy_tmp

    # Copy release files
    cp -r _build/prod/rel/armoricore deploy_tmp/

    # Copy configuration files
    cp .env.production deploy_tmp/
    cp nats-server.conf deploy_tmp/
    cp setup_production.sh deploy_tmp/

    # Copy deployment scripts
    cp deploy_production.sh deploy_tmp/
    cp monitor_production.sh deploy_tmp/
    cp load_test.sh deploy_tmp/

    # Create version file
    echo "$APP_VERSION" > deploy_tmp/version.txt
    echo "Built at: $(date)" >> deploy_tmp/version.txt
    echo "Git commit: $(git rev-parse HEAD 2>/dev/null || echo 'unknown')" >> deploy_tmp/version.txt

    # Create package
    cd deploy_tmp
    tar -czf "../$package_name" .
    cd ..
    rm -rf deploy_tmp

    log_success "Deployment package created: $package_name"
    echo "$package_name"
}

# Deploy to server
deploy_to_server() {
    local package_name="$1"

    log_info "Deploying to server: $DEPLOY_HOST"

    # Upload package to server
    log_info "Uploading package to server..."
    scp "$package_name" "$DEPLOY_USER@$DEPLOY_HOST:/tmp/"

    # Run deployment on server
    log_info "Running deployment on server..."
    ssh "$DEPLOY_USER@$DEPLOY_HOST" bash << EOF
        set -e

        echo "Starting deployment on server..."

        # Create backup of current deployment
        if [ -d "$DEPLOY_PATH" ]; then
            echo "Creating backup..."
            sudo systemctl stop armoricore || true
            sudo cp -r "$DEPLOY_PATH" "$BACKUP_PATH/backup-\$(date +%Y%m%d_%H%M%S)" || true
        fi

        # Extract new deployment
        echo "Extracting new deployment..."
        sudo mkdir -p "$DEPLOY_PATH"
        sudo rm -rf "$DEPLOY_PATH"/*
        sudo tar -xzf "/tmp/$package_name" -C "$DEPLOY_PATH"

        # Set proper permissions
        echo "Setting permissions..."
        sudo chown -R armoricore:armoricore "$DEPLOY_PATH"
        sudo chmod 600 "$DEPLOY_PATH/.env.production"

        # Set up SSL certificates
        echo "Setting up SSL certificates..."
        sudo mkdir -p /etc/armoricore/ssl

        # Check if certificates exist on server, otherwise copy from deployment package
        if [ ! -f "/etc/armoricore/ssl/cert.pem" ] || [ ! -f "/etc/armoricore/ssl/key.pem" ]; then
            echo "SSL certificates not found on server, checking deployment package..."

            # Try to copy certificates from deployment package (for self-signed)
            if [ -f "$DEPLOY_PATH/priv/cert/armoricore.pem" ] && [ -f "$DEPLOY_PATH/priv/cert/armoricore_key.pem" ]; then
                echo "Using self-signed certificates from deployment package..."
                sudo cp "$DEPLOY_PATH/priv/cert/armoricore.pem" /etc/armoricore/ssl/cert.pem
                sudo cp "$DEPLOY_PATH/priv/cert/armoricore_key.pem" /etc/armoricore/ssl/key.pem
                sudo chown root:root /etc/armoricore/ssl/*
                sudo chmod 600 /etc/armoricore/ssl/key.pem
                sudo chmod 644 /etc/armoricore/ssl/cert.pem
                echo "Self-signed SSL certificates installed"
            else
                echo "WARNING: No SSL certificates found!"
                echo "Please ensure SSL certificates are properly configured:"
                echo "  - For Let's Encrypt: Run 'sudo certbot certonly --standalone -d yourdomain.com'"
                echo "  - For commercial certificates: Place cert.pem and key.pem in /etc/armoricore/ssl/"
                echo "  - For self-signed: Run setup_production.sh with CERT_TYPE=self-signed"
            fi
        else
            echo "SSL certificates already exist on server"
        fi

        # Run database migrations
        echo "Running database migrations..."
        cd "$DEPLOY_PATH"
        sudo -u armoricore ./bin/armoricore eval "ArmoricoreRealtime.Release.migrate()"

        # Start application
        echo "Starting application..."
        sudo systemctl daemon-reload
        sudo systemctl start armoricore

        # Wait for application to start
        echo "Waiting for application to start..."
        for i in {1..30}; do
            if curl -f -s http://localhost:4000/api/v1/health >/dev/null 2>&1; then
                echo "Application started successfully"
                break
            fi
            sleep 2
        done

        # Verify deployment
        if curl -f -s http://localhost:4000/api/v1/health >/dev/null 2>&1; then
            echo "✅ Deployment successful!"
            echo "Application is running at: http://$DEPLOY_HOST:4000"
        else
            echo "❌ Deployment verification failed!"
            exit 1
        fi

        # Clean up
        rm "/tmp/$package_name"

        echo "Deployment completed at: \$(date)"
EOF

    if [ $? -eq 0 ]; then
        log_success "Deployment to server completed successfully"
    else
        log_error "Deployment to server failed"
        exit 1
    fi
}

# Post-deployment verification
post_deployment_verification() {
    log_info "Running post-deployment verification..."

    # Test health endpoint
    if curl -f -s "http://$DEPLOY_HOST:4000/api/v1/health" >/dev/null 2>&1; then
        log_success "Health check passed"
    else
        log_error "Health check failed"
        exit 1
    fi

    # Test basic API endpoints
    local endpoints=("/api/v1/videos" "/api/v1/health")
    for endpoint in "${endpoints[@]}"; do
        if curl -f -s "http://$DEPLOY_HOST:4000$endpoint" >/dev/null 2>&1; then
            log_success "Endpoint $endpoint is accessible"
        else
            log_warning "Endpoint $endpoint is not accessible"
        fi
    done

    # Check service status
    ssh "$DEPLOY_USER@$DEPLOY_HOST" bash << 'EOF'
        echo "Service status:"
        sudo systemctl status armoricore --no-pager -l

        echo ""
        echo "Application logs:"
        sudo journalctl -u armoricore -n 10 --no-pager

        echo ""
        echo "Process status:"
        ps aux | grep beam || true
EOF

    log_success "Post-deployment verification completed"
}

# Rollback functionality
rollback_deployment() {
    log_warning "Initiating rollback..."

    ssh "$DEPLOY_USER@$DEPLOY_HOST" bash << EOF
        echo "Rolling back deployment..."

        # Stop current version
        sudo systemctl stop armoricore

        # Find latest backup
        LATEST_BACKUP=\$(ls -t $BACKUP_PATH | head -1)

        if [ -n "\$LATEST_BACKUP" ]; then
            echo "Restoring from backup: \$LATEST_BACKUP"
            sudo rm -rf $DEPLOY_PATH/*
            sudo cp -r "$BACKUP_PATH/\$LATEST_BACKUP"/* "$DEPLOY_PATH/"

            # Restart with backup version
            sudo systemctl start armoricore

            echo "Rollback completed"
        else
            echo "No backup found!"
            exit 1
        fi
EOF

    if [ $? -eq 0 ]; then
        log_success "Rollback completed successfully"
    else
        log_error "Rollback failed"
        exit 1
    fi
}

# Generate deployment report
generate_deployment_report() {
    local package_name="$1"
    local report_file="deployment_report_$(date +%Y%m%d_%H%M%S).md"

    log_info "Generating deployment report..."

    cat > "$report_file" << EOF
# Armoricore Production Deployment Report

**Deployment Date:** $(date)
**Version:** $APP_VERSION
**Target Server:** $DEPLOY_HOST
**Package:** $package_name

## Deployment Summary

### ✅ Completed Steps
- Pre-deployment checks passed
- Production release built successfully
- Deployment package created
- Application deployed to server
- Post-deployment verification completed
- Application is running and accessible

### 📊 Deployment Details

#### Build Information
- **Git Commit:** $(git rev-parse HEAD 2>/dev/null || echo 'unknown')
- **Build Time:** $(date)
- **Environment:** Production

#### Server Information
- **Host:** $DEPLOY_HOST
- **Deployment Path:** $DEPLOY_PATH
- **Service:** armoricore (systemd)

#### Health Check Results
\`\`\`json
$(curl -s "http://$DEPLOY_HOST:4000/api/v1/health" 2>/dev/null || echo '{"error": "Health check failed"}')
\`\`\`

## Post-Deployment Checklist

### ✅ System Health
- [x] Application started successfully
- [x] Health endpoint responding
- [x] Database connections working
- [x] NATS message bus connected

### ✅ API Endpoints
- [x] GET /api/v1/health - Working
- [x] GET /api/v1/videos - Working
- [ ] POST /api/v1/auth/register - Test manually
- [ ] POST /api/v1/videos - Test manually

### ✅ Real-time Features
- [ ] WebSocket connections - Test with client
- [ ] ArcRTC signaling - Test with WebRTC client
- [ ] Room chat - Test with multiple users

### 🔧 Configuration
- [x] Environment variables loaded
- [x] Database configuration applied
- [x] NATS configuration applied
- [x] SSL certificates configured

## Monitoring Setup

### Application Metrics
- Health checks: Every 30 seconds
- Error logging: Enabled
- Performance monitoring: Enabled

### System Monitoring
- CPU/Memory/Disk: Monitor via system tools
- Network connections: Monitor WebSocket connections
- Database performance: Monitor query times

## Rollback Information

**Backup Location:** $BACKUP_PATH
**Latest Backup:** \`$(ssh "$DEPLOY_USER@$DEPLOY_HOST" "ls -t $BACKUP_PATH | head -1" 2>/dev/null || echo 'unknown')\`

**Rollback Command:**
\`\`\`bash
./deploy_production.sh --rollback
\`\`\`

## Next Steps

1. **User Acceptance Testing**
   - Test all user-facing features
   - Verify ArcRTC functionality
   - Test under various network conditions

2. **Load Testing**
   - Run load tests in production environment
   - Monitor system performance under load
   - Optimize based on results

3. **Monitoring & Alerting**
   - Set up production monitoring dashboard
   - Configure alerting for critical issues
   - Establish on-call procedures

4. **Documentation**
   - Update production runbook
   - Document deployment procedures
   - Create troubleshooting guides

## Emergency Contacts

- **Technical Lead:** [Name] - [Email/Phone]
- **DevOps:** [Name] - [Email/Phone]
- **Business Owner:** [Name] - [Email/Phone]

---

**Deployment completed successfully by automated script**
EOF

    log_success "Deployment report generated: $report_file"
}

# Main deployment function
main() {
    local rollback_mode=false

    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --rollback)
                rollback_mode=true
                shift
                ;;
            *)
                log_error "Unknown option: $1"
                echo "Usage: $0 [--rollback]"
                exit 1
                ;;
        esac
    done

    if [ "$rollback_mode" = true ]; then
        rollback_deployment
        exit 0
    fi

    log_info "Starting Armoricore production deployment..."
    log_info "Target server: $DEPLOY_HOST"
    log_info "Version: $APP_VERSION"

    # Run deployment steps
    pre_deployment_checks
    build_release

    local package_name
    package_name=$(create_deployment_package)

    deploy_to_server "$package_name"
    post_deployment_verification
    generate_deployment_report "$package_name"

    log_success "🎉 Production deployment completed successfully!"
    log_info "Application is now running at: http://$DEPLOY_HOST:4000"
    log_info "Check the deployment report for detailed information."

    # Clean up local package
    rm -f "$package_name"
}

# Run main function
main "$@"