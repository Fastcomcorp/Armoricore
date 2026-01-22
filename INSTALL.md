# Armoricore Installation Guide

This guide provides comprehensive installation instructions for Armoricore on Linux distributions, specifically targeting Debian, Red Hat (RHEL/CentOS/Fedora), and Ubuntu systems.

## Table of Contents

- [System Requirements](#system-requirements)
- [Quick Start](#quick-start)
- [Debian Installation](#debian-installation)
- [Ubuntu Installation](#ubuntu-installation)
- [Red Hat/CentOS/Fedora Installation](#red-hatcentosfedora-installation)
- [Environment Configuration](#environment-configuration)
- [Database Setup](#database-setup)
- [Application Startup](#application-startup)
- [Verification](#verification)
- [Troubleshooting](#troubleshooting)
- [Production Deployment](#production-deployment)

## System Requirements

### Minimum Requirements
- **CPU**: 2 cores (4+ recommended)
- **RAM**: 4GB (8GB+ recommended)
- **Storage**: 20GB free space
- **Network**: 100Mbps connection

### Software Dependencies
- **Elixir**: 1.15+
- **Erlang/OTP**: 25+
- **PostgreSQL**: 13+
- **Rust**: 1.70+ (for media services)
- **Node.js**: 18+ (for assets)
- **FFmpeg**: 4.0+ (for media processing)

## Quick Start

For experienced users, here's the condensed version:

```bash
# 1. Install system dependencies
# Follow distro-specific instructions below

# 2. Clone and setup
git clone https://github.com/Fastcomcorp/Armoricore.git
cd armoricore

# 3. Setup Elixir environment
cd elixir_realtime
mix deps.get

# 4. Configure environment
cp ../.env.example ../.env
# Edit .env with your database URL

# 5. Setup database
mix ecto.setup

# 6. Start application
mix phx.server
```

Visit `http://localhost:4000` to access Armoricore.

## Debian Installation

### Step 1: Update System
```bash
sudo apt update && sudo apt upgrade -y
```

### Step 2: Install Erlang and Elixir
```bash
# Add Erlang repository
wget -O- https://packages.erlang-solutions.com/ubuntu/erlang_solutions.asc | sudo apt-key add -
echo "deb https://packages.erlang-solutions.com/ubuntu focal contrib" | sudo tee /etc/apt/sources.list.d/erlang.list

# Update and install Erlang/Elixir
sudo apt update
sudo apt install -y erlang elixir

# Verify installation
elixir --version
erl -eval 'erlang:display(erlang:system_info(otp_release)), halt().' -noshell
```

### Step 3: Install PostgreSQL
```bash
# Install PostgreSQL
sudo apt install -y postgresql postgresql-contrib

# Start and enable PostgreSQL
sudo systemctl start postgresql
sudo systemctl enable postgresql

# Create database user (replace 'armoricore' with your desired password)
sudo -u postgres psql -c "CREATE USER armoricore WITH PASSWORD 'armoricore_password';"
sudo -u postgres psql -c "CREATE DATABASE armoricore_realtime_dev OWNER armoricore;"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE armoricore_realtime_dev TO armoricore;"
```

### Step 4: Install Rust
```bash
# Install Rust using rustup
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source $HOME/.cargo/env

# Add Rust to PATH permanently
echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc

# Verify installation
cargo --version
```

### Step 5: Install Node.js
```bash
# Install Node.js 18.x
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs

# Verify installation
node --version
npm --version
```

### Step 6: Install FFmpeg
```bash
sudo apt install -y ffmpeg

# Verify installation
ffmpeg -version
```

### Step 7: Install Build Dependencies
```bash
sudo apt install -y build-essential git curl wget
```

## Ubuntu Installation

Ubuntu installation is very similar to Debian since Ubuntu is based on Debian.

### Step 1: Update System
```bash
sudo apt update && sudo apt upgrade -y
```

### Step 2: Install Erlang and Elixir
```bash
# Add Erlang repository
wget -O- https://packages.erlang-solutions.com/ubuntu/erlang_solutions.asc | sudo apt-key add -
echo "deb https://packages.erlang-solutions.com/ubuntu jammy contrib" | sudo tee /etc/apt/sources.list.d/erlang.list

# Update and install Erlang/Elixir
sudo apt update
sudo apt install -y erlang elixir

# Verify installation
elixir --version
erl -eval 'erlang:display(erlang:system_info(otp_release)), halt().' -noshell
```

### Step 3: Install PostgreSQL
```bash
# Install PostgreSQL
sudo apt install -y postgresql postgresql-contrib

# Start and enable PostgreSQL
sudo systemctl start postgresql
sudo systemctl enable postgresql

# Create database user
sudo -u postgres psql -c "CREATE USER armoricore WITH PASSWORD 'armoricore_password';"
sudo -u postgres psql -c "CREATE DATABASE armoricore_realtime_dev OWNER armoricore;"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE armoricore_realtime_dev TO armoricore;"
```

### Step 4: Install Rust
```bash
# Install Rust using rustup
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source $HOME/.cargo/env

# Add Rust to PATH permanently
echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc

# Verify installation
cargo --version
```

### Step 5: Install Node.js
```bash
# Install Node.js 18.x
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs

# Verify installation
node --version
npm --version
```

### Step 6: Install FFmpeg
```bash
sudo apt install -y ffmpeg

# Verify installation
ffmpeg -version
```

### Step 7: Install Build Dependencies
```bash
sudo apt install -y build-essential git curl wget
```

## Red Hat/CentOS/Fedora Installation

### Step 1: Update System
```bash
# For CentOS/RHEL
sudo yum update -y
# OR for Fedora
sudo dnf update -y
```

### Step 2: Install Erlang and Elixir
```bash
# Install Erlang
# For CentOS/RHEL 8+
sudo yum install -y epel-release
sudo yum install -y erlang

# For Fedora
sudo dnf install -y erlang

# Install Elixir
# Download and install from source or use package manager
cd /tmp
wget https://github.com/elixir-lang/elixir/releases/download/v1.15.7/elixir-1.15.7.zip
unzip elixir-1.15.7.zip
sudo mv elixir-1.15.7 /usr/local/elixir

# Add Elixir to PATH
echo 'export PATH="$PATH:/usr/local/elixir/bin"' >> ~/.bashrc
source ~/.bashrc

# Verify installation
elixir --version
```

### Step 3: Install PostgreSQL
```bash
# For CentOS/RHEL
sudo yum install -y postgresql-server postgresql-contrib
sudo postgresql-setup initdb
sudo systemctl start postgresql
sudo systemctl enable postgresql

# For Fedora
sudo dnf install -y postgresql-server postgresql-contrib
sudo postgresql-setup --initdb
sudo systemctl start postgresql
sudo systemctl enable postgresql

# Create database user
sudo -u postgres psql -c "CREATE USER armoricore WITH PASSWORD 'armoricore_password';"
sudo -u postgres psql -c "CREATE DATABASE armoricore_realtime_dev OWNER armoricore;"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE armoricore_realtime_dev TO armoricore;"
```

### Step 4: Install Rust
```bash
# Install Rust using rustup
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source $HOME/.cargo/env

# Add Rust to PATH permanently
echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc

# Verify installation
cargo --version
```

### Step 5: Install Node.js
```bash
# For CentOS/RHEL 8+
curl -fsSL https://rpm.nodesource.com/setup_18.x | sudo bash -
sudo yum install -y nodejs

# For Fedora
sudo dnf install -y nodejs npm

# Verify installation
node --version
npm --version
```

### Step 6: Install FFmpeg
```bash
# For CentOS/RHEL
sudo yum install -y ffmpeg ffmpeg-devel

# For Fedora
sudo dnf install -y ffmpeg ffmpeg-devel

# Verify installation
ffmpeg -version
```

### Step 7: Install Build Dependencies
```bash
# For CentOS/RHEL
sudo yum groupinstall -y "Development Tools"
sudo yum install -y git curl wget

# For Fedora
sudo dnf groupinstall -y "Development Tools"
sudo dnf install -y git curl wget
```

## Environment Configuration

### Step 1: Clone Repository
```bash
git clone https://github.com/Fastcomcorp/Armoricore.git
cd armoricore
```

### Step 2: Configure Environment Variables
```bash
# Copy example environment file
cp .env.example .env

# Edit the .env file with your configuration
nano .env
```

Example `.env` configuration:
```bash
# Database Configuration
DATABASE_URL=postgresql://armoricore:armoricore_password@localhost:5432/armoricore_realtime_dev

# Message Bus
MESSAGE_BUS_URL=nats://localhost:4222

# JWT Secret (generate a secure random string)
JWT_SECRET=your-super-secure-jwt-secret-here

# Phoenix Host (change for production)
PHX_HOST=localhost

# Optional: Redis for caching (if available)
# REDIS_URL=redis://localhost:6379

# Optional: Object storage (if using external storage)
# OBJECT_STORAGE_ENDPOINT=https://your-storage-endpoint.com
# OBJECT_STORAGE_ACCESS_KEY=your-access-key
# OBJECT_STORAGE_SECRET_KEY=your-secret-key
# OBJECT_STORAGE_BUCKET=your-bucket-name
```

### Step 3: Generate Secure Secrets
```bash
# Generate a secure JWT secret
openssl rand -base64 32

# Generate a secure Phoenix secret key base (for production)
mix phx.gen.secret
```

## Database Setup

### Step 1: Navigate to Application Directory
```bash
cd elixir_realtime
```

### Step 2: Install Elixir Dependencies
```bash
mix deps.get
```

### Step 3: Create and Migrate Database
```bash
# Create database (if not already created)
mix ecto.create

# Run migrations
mix ecto.migrate

# (Optional) Seed database with sample data
mix run priv/repo/seeds.exs
```

## Application Startup

### Development Mode
```bash
# Start Phoenix server in development mode
mix phx.server
```

The application will be available at:
- **Web Interface**: http://localhost:4000
- **API Explorer**: http://localhost:4000/api-explorer
- **Developer Portal**: http://localhost:4000/dev-portal
- **Admin Dashboard**: http://localhost:4000/admin

### Production Mode
```bash
# Build for production
MIX_ENV=prod mix compile

# Create release
MIX_ENV=prod mix release

# Start production release
_build/prod/rel/armoricore_realtime/bin/armoricore_realtime start
```

## Verification

### Step 1: Check Application Health
```bash
# Check if Phoenix is running
curl http://localhost:4000/health

# Should return: {"status": "ok"}
```

### Step 2: Test Database Connection
```bash
# From elixir_realtime directory
mix run -e "ArmoricoreRealtime.Repo.query('SELECT 1')"
```

### Step 3: Verify API Endpoints
```bash
# Test API endpoints
curl http://localhost:4000/api/v1/health

# Test with authentication (if configured)
curl -H "Authorization: Bearer your-jwt-token" \
     http://localhost:4000/api/v1/videos
```

### Step 4: Check System Resources
```bash
# Monitor system resources
htop
# OR
top

# Check PostgreSQL
sudo -u postgres psql -c "SELECT version();"

# Check Erlang processes
ps aux | grep beam
```

## Troubleshooting

### Common Issues

#### 1. Elixir Compilation Errors
```bash
# Clean dependencies and try again
mix deps.clean --all
mix deps.get
mix compile
```

#### 2. Database Connection Issues
```bash
# Check PostgreSQL status
sudo systemctl status postgresql

# Check database connectivity
psql -h localhost -U armoricore -d armoricore_realtime_dev

# Reset database
mix ecto.reset
```

#### 3. Port Already in Use
```bash
# Find process using port 4000
lsof -i :4000

# Kill process (replace PID)
kill -9 <PID>

# Or use different port
PORT=4001 mix phx.server
```

#### 4. Rust Compilation Issues
```bash
# Clean Rust build
cd rust-services
cargo clean
cargo build --release
```

#### 5. Node.js Asset Compilation Issues
```bash
# Clear node modules and reinstall
cd elixir_realtime/assets
rm -rf node_modules
npm install
```

### Logs and Debugging

#### Application Logs
```bash
# Phoenix logs (in development)
tail -f elixir_realtime/_build/dev/lib/armoricore_realtime/logs/*.log

# System logs
journalctl -u postgresql
journalctl -u nginx  # if using reverse proxy
```

#### Debug Mode
```bash
# Enable debug logging
export LOG_LEVEL=debug
mix phx.server

# Enable Phoenix Live Dashboard (if configured)
# Visit: http://localhost:4000/dashboard
```

### Performance Tuning

#### Database Optimization
```sql
-- Analyze query performance
EXPLAIN ANALYZE SELECT * FROM users LIMIT 10;

-- Check index usage
SELECT schemaname, tablename, indexname, idx_scan, idx_tup_read, idx_tup_fetch
FROM pg_stat_user_indexes;
```

#### System Monitoring
```bash
# Monitor Erlang VM
:observer.start()  # In Elixir shell

# Check memory usage
ps aux --sort=-%mem | head

# Network connections
netstat -tlnp | grep :4000
```

## Production Deployment

### Using Docker
```bash
# Build and run with Docker Compose
docker-compose up -d

# Or build custom image
docker build -t armoricore .
docker run -p 4000:4000 armoricore
```

### Using Systemd
```bash
# Create systemd service file
sudo nano /etc/systemd/system/armoricore.service
```

Example systemd service:
```ini
[Unit]
Description=Armoricore Real-time Platform
After=network.target postgresql.service

[Service]
Type=simple
User=armoricore
WorkingDirectory=/opt/armoricore/elixir_realtime
Environment=MIX_ENV=prod
Environment=PORT=4000
ExecStart=/usr/local/bin/mix phx.server
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
# Enable and start service
sudo systemctl enable armoricore
sudo systemctl start armoricore
sudo systemctl status armoricore
```

### Using Nginx Reverse Proxy
```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://localhost:4000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # WebSocket support
    location /socket {
        proxy_pass http://localhost:4000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

### SSL Configuration
```bash
# Get SSL certificate (Let's Encrypt example)
sudo certbot --nginx -d your-domain.com

# Or configure manual SSL
ssl_certificate /path/to/cert.pem;
ssl_certificate_key /path/to/key.pem;
```

## Support and Community

- **Documentation**: https://docs.armoricore.com
- **Community Forum**: https://community.armoricore.com
- **GitHub Issues**: https://github.com/Fastcomcorp/Armoricore/issues
- **Security Issues**: security@armoricore.com

## Next Steps

Once installed, you can:

1. **Explore the Developer Portal**: Visit `/dev-portal` to get started
2. **Test APIs**: Use the API Explorer at `/api-explorer`
3. **Monitor System**: Check the Admin Dashboard at `/admin`
4. **Configure Security**: Set up proper secrets and certificates
5. **Scale Deployment**: Configure load balancing and clustering

For advanced configuration and production deployment, refer to the [Deployment Guide](DEPLOYMENT_READINESS_CHECKLIST.md).