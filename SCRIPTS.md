# Armoricore Scripts Reference

This document describes all available scripts for installing, running, and managing Armoricore.

## Quick Start

```bash
# Install all dependencies and set up the project
./install.sh

# Start for development (recommended)
./start_dev.sh

# Or start all services including Rust
./start_all.sh

# Stop all services
./stop_all.sh
```

## Installation Scripts

### `install.sh`

Full installation script that sets up Armoricore from scratch.

```bash
# Full installation
./install.sh

# Skip dependency installation (if already installed)
./install.sh --skip-deps

# Skip Rust build (faster for Elixir-only development)
./install.sh --skip-rust

# Verify installation only
./install.sh --verify
```

**What it does:**
- Detects your operating system (macOS, Debian, RedHat, Arch)
- Installs required dependencies (Elixir, Rust, NATS, FFmpeg)
- Sets up Elixir project dependencies
- Builds Rust services
- Creates `.env` configuration file

### `setup_production.sh`

Production environment setup script.

```bash
# Default setup with self-signed certificates
./setup_production.sh

# With Let's Encrypt certificates
CERT_TYPE=lets-encrypt DOMAIN=yourdomain.com ./setup_production.sh

# With commercial certificates
CERT_TYPE=commercial CERT_PATH=/path/to/cert.crt KEY_PATH=/path/to/key.key ./setup_production.sh
```

**What it does:**
- Installs and configures NATS server
- Generates production secrets
- Sets up SSL certificates
- Creates systemd service file
- Configures log rotation

## Startup Scripts

### `start_dev.sh` (Recommended for Development)

Quick development startup with minimal overhead.

```bash
# Background mode
./start_dev.sh

# Interactive mode (with iex console)
./start_dev.sh -i
./start_dev.sh --interactive
```

**What it starts:**
- NATS server (if not running)
- Phoenix server in development mode

**Skips:**
- Rust services (optional for most development)
- Production builds

### `start_all.sh`

Full startup including all services.

```bash
# Start all services
./start_all.sh

# Stop all services
./start_all.sh stop

# Check status
./start_all.sh status

# Restart all services
./start_all.sh restart
```

**What it starts:**
- NATS server
- Rust services (media-processor, ai-workers)
- Phoenix server

### `start_all_skip_rust.sh`

Start everything except Rust services (faster startup).

```bash
./start_all_skip_rust.sh
```

**Use when:**
- You don't need media processing
- Rust build is taking too long
- Quick testing of Elixir features

## Stop Scripts

### `stop_all.sh`

Stop all running Armoricore services.

```bash
# Stop all services
./stop_all.sh

# Stop only Phoenix
./stop_all.sh phoenix

# Stop only NATS
./stop_all.sh nats

# Stop only Rust services
./stop_all.sh rust
```

## Deployment Scripts

### `deploy_production.sh`

Deploy Armoricore to a production server.

```bash
./deploy_production.sh
```

### `ssl_setup.sh`

Configure SSL certificates.

```bash
# Self-signed (development)
./ssl_setup.sh self-signed

# Let's Encrypt
./ssl_setup.sh lets-encrypt

# Commercial certificates
./ssl_setup.sh commercial
```

## Testing Scripts

### `test_system.sh`

Run comprehensive system tests.

```bash
./test_system.sh
```

### `test_end_to_end.sh`

Run end-to-end integration tests.

```bash
./test_end_to_end.sh
```

### `security_test.sh`

Run security vulnerability tests.

```bash
./security_test.sh
```

### `quick_security_test.sh`

Quick security scan.

```bash
./quick_security_test.sh
```

### `load_test.sh`

Run load/performance tests.

```bash
./load_test.sh
```

## Monitoring Scripts

### `monitor_production.sh`

Monitor production server status.

```bash
./monitor_production.sh
```

### `monitor_db_connectivity.sh`

Monitor database connection health.

```bash
./monitor_db_connectivity.sh
```

### `verify_db_connection.sh`

Verify database connection works.

```bash
./verify_db_connection.sh
```

## Utility Scripts

### `check_license_requirements.sh`

Check license compliance for dependencies.

```bash
./check_license_requirements.sh
```

### `verify_watermarks.sh`

Verify code watermarks are in place.

```bash
./verify_watermarks.sh
```

### `watermark_all_files.sh`

Apply watermarks to all source files.

```bash
./watermark_all_files.sh
```

## Directory Structure

```
Armoricore/
├── logs/                    # Log files
│   ├── phoenix.log
│   ├── nats.log
│   ├── rust-build.log
│   └── install.log
├── pids/                    # PID files for running services
│   ├── nats.pid
│   ├── phoenix.pid
│   └── media-processor.pid
└── .env                     # Environment configuration
```

## Environment Variables

Key environment variables used by the scripts:

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | None (required) |
| `NATS_URL` | NATS server URL | `nats://localhost:4222` |
| `REDIS_URL` | Redis connection string | None (optional) |
| `MIX_ENV` | Elixir environment | `dev` |
| `PORT` | Phoenix server port | `4000` |
| `SECRET_KEY_BASE` | Phoenix secret key | Generated |

## Troubleshooting

### Phoenix won't start

```bash
# Check if port 4000 is in use
lsof -i :4000

# Check logs
tail -f logs/phoenix.log

# Try stopping first
./stop_all.sh
```

### NATS won't start

```bash
# Check if port 4222 is in use
lsof -i :4222

# Check logs
tail -f logs/nats.log

# Install NATS if missing
brew install nats-server  # macOS
```

### Database connection fails

```bash
# Verify DATABASE_URL is set
echo $DATABASE_URL

# Test connection
./verify_db_connection.sh

# Check .env file
cat .env | grep DATABASE_URL
```

### Rust build fails

```bash
# Check Rust is installed
rustc --version
cargo --version

# Clean and rebuild
cd rust-services
cargo clean
cargo build --release

# Check build logs
cat logs/rust-build.log
```

## Service Ports

| Service | Port | Description |
|---------|------|-------------|
| Phoenix API | 4000 | HTTP REST API |
| Phoenix WebSocket | 4000 | WebSocket connections |
| NATS | 4222 | Message bus |
| NATS Monitor | 8222 | NATS monitoring UI |
| gRPC Media Engine | 50051 | Media engine gRPC |
| PostgreSQL | 5432 | Database (default) |
| Redis | 6379 | Cache (optional) |

---

*Powered by Fastcomcorp, LLC - Enterprise Security Solutions*
