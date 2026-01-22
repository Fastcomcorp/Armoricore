# Armoricore Configuration Guide

This guide explains how to configure all credentials and connection strings for Armoricore.

## 🔐 Security Notice

**NEVER commit real credentials to version control!**

All credentials should be:
- Stored in environment variables
- Or stored in `.env` files (which are gitignored)
- Or stored in a secure key management system

---

## 📋 Required Configuration

### 1. PostgreSQL Database

#### For Elixir Phoenix (Required)

**Environment Variable:** `DATABASE_URL`

**Format:**
```
postgresql://username:password@host:port/database_name
```

**Examples:**

**Local Development:**
```bash
export DATABASE_URL="postgresql://postgres:postgres@localhost:5432/armoricore_realtime_dev"
```

**Production (with SSL):**
```bash
export DATABASE_URL="postgresql://armoricore:your-secure-password@db.example.com:5432/armoricore_realtime?sslmode=require"
```

**Cloud Database (Aiven, AWS RDS, etc.):**
```bash
export DATABASE_URL="postgresql://user:password@host.example.com:5432/database?sslmode=require"
```

#### Configuration Files

**Development (`elixir_realtime/config/dev.exs`):**
```elixir
config :armoricore_realtime, ArmoricoreRealtime.Repo,
  username: "postgres",
  password: "postgres",  # Change this for your local setup
  hostname: "localhost",
  database: "armoricore_realtime_dev",
  pool_size: 10
```

**Production (`elixir_realtime/config/runtime.exs`):**
- Uses `DATABASE_URL` environment variable (required)
- Automatically detects SSL requirements

**Test (`elixir_realtime/config/test.exs`):**
```elixir
config :armoricore_realtime, ArmoricoreRealtime.Repo,
  username: "postgres",
  password: "postgres",  # Change this for your test database
  hostname: "localhost",
  database: "armoricore_realtime_test",
  pool_size: 10
```

#### For Rust Notification Worker (Optional)

**Environment Variable:** `DATABASE_URL`

Only needed if you want to store device tokens in PostgreSQL. If not set, device tokens must be provided in event payloads.

**Example:**
```bash
export DATABASE_URL="postgresql://user:password@localhost:5432/armoricore_realtime"
```

#### Setup Instructions

1. **Install PostgreSQL:**
   ```bash
   # macOS
   brew install postgresql
   brew services start postgresql
   
   # Linux
   sudo apt install postgresql postgresql-contrib
   sudo systemctl start postgresql
   ```

2. **Create Database:**
   ```bash
   # Connect to PostgreSQL
   psql postgres
   
   # Create user and database
   CREATE USER armoricore WITH PASSWORD 'your-secure-password';
   CREATE DATABASE armoricore_realtime;
   GRANT ALL PRIVILEGES ON DATABASE armoricore_realtime TO armoricore;
   \q
   ```

3. **Run Migrations:**
   ```bash
   cd elixir_realtime
   export DATABASE_URL="postgresql://armoricore:your-secure-password@localhost:5432/armoricore_realtime"
   mix ecto.create
   mix ecto.migrate
   ```

4. **Set Environment Variable:**
   ```bash
   # Add to your shell profile (~/.bashrc, ~/.zshrc, etc.)
   export DATABASE_URL="postgresql://armoricore:your-secure-password@localhost:5432/armoricore_realtime"
   ```

---

### 2. Akamai Object Storage (S3-Compatible)

#### Required Environment Variables

```bash
OBJECT_STORAGE_ENDPOINT=https://your-bucket.akamai.com
OBJECT_STORAGE_ACCESS_KEY=your-akamai-access-key
OBJECT_STORAGE_SECRET_KEY=your-akamai-secret-key
OBJECT_STORAGE_BUCKET=your-bucket-name
OBJECT_STORAGE_REGION=akamai  # Optional, defaults to "akamai"
```

#### Endpoint Formats

The system supports multiple endpoint formats:

1. **Full HTTPS URL (Recommended):**
   ```bash
   OBJECT_STORAGE_ENDPOINT=https://your-bucket.akamai.com
   ```

2. **S3-style URL (Auto-converted):**
   ```bash
   OBJECT_STORAGE_ENDPOINT=s3://your-bucket
   ```
   Will be converted to: `https://your-bucket.akamai.com`

3. **Bucket name only (Auto-converted):**
   ```bash
   OBJECT_STORAGE_ENDPOINT=your-bucket
   ```
   Will be converted to: `https://your-bucket.akamai.com`

#### Setup Instructions

1. **Create Akamai Object Storage Account:**
   - Log in to your Akamai/Linode Object Storage console
   - Create a new bucket
   - Generate access keys (Access Key ID and Secret Access Key)

2. **Set Environment Variables:**
   ```bash
   # Add to your shell profile or .env file
   export OBJECT_STORAGE_ENDPOINT="https://your-bucket.akamai.com"
   export OBJECT_STORAGE_ACCESS_KEY="your-access-key-id"
   export OBJECT_STORAGE_SECRET_KEY="your-secret-access-key"
   export OBJECT_STORAGE_BUCKET="your-bucket-name"
   export OBJECT_STORAGE_REGION="akamai"
   ```

3. **Alternative: Use Key Store:**
   The system can also store credentials in the encrypted key store:
   ```bash
   # Credentials will be automatically migrated from environment variables
   # or you can use the migration scripts
   ```

#### Testing Connection

```bash
# Test with a simple upload
curl -X PUT \
  -H "Authorization: AWS your-access-key:your-secret-key" \
  https://your-bucket.akamai.com/test.txt \
  --data "test content"
```

---

## 🔧 Configuration Methods

### Method 1: Environment Variables (Recommended)

**Create `.env` files (gitignored):**

**`rust-services/.env`:**
```bash
# Message Bus
MESSAGE_BUS_URL=nats://localhost:4222

# Object Storage (Akamai S3-compatible)
OBJECT_STORAGE_ENDPOINT=https://your-bucket.akamai.com
OBJECT_STORAGE_ACCESS_KEY=your-akamai-access-key
OBJECT_STORAGE_SECRET_KEY=your-akamai-secret-key
OBJECT_STORAGE_BUCKET=your-bucket-name
OBJECT_STORAGE_REGION=akamai

# Logging
LOG_LEVEL=info
```

**`elixir_realtime/.env`:**
```bash
# Message Bus
MESSAGE_BUS_URL=nats://localhost:4222

# Database
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/armoricore_realtime_dev

# JWT
JWT_SECRET=your-jwt-secret-key-change-in-production

# Phoenix
SECRET_KEY_BASE=your-secret-key-base-generate-with-mix-phx-gen-secret
PHX_HOST=localhost
PORT=4000
```

### Method 2: System Environment Variables

**Set in your shell profile (`~/.bashrc`, `~/.zshrc`, etc.):**
```bash
export DATABASE_URL="postgresql://user:password@localhost:5432/armoricore_realtime"
export OBJECT_STORAGE_ENDPOINT="https://your-bucket.akamai.com"
export OBJECT_STORAGE_ACCESS_KEY="your-access-key"
export OBJECT_STORAGE_SECRET_KEY="your-secret-key"
export OBJECT_STORAGE_BUCKET="your-bucket-name"
```

### Method 3: Key Store (Encrypted Storage)

The system includes a key management service that can store credentials encrypted:

```bash
# Credentials are automatically migrated from environment variables
# Or use migration scripts:
cd scripts
./migrate_keys_to_key_store.sh
```

---

### 3. Redis (Optional - Distributed Rate Limiting)

Redis is optional but recommended for production deployments with multiple nodes.
If not configured, the application falls back to ETS-based rate limiting (single-node only).

#### Environment Variable

```bash
REDIS_URL=redis://localhost:6379
# Or with authentication:
REDIS_URL=redis://user:password@host:6379
# Or with TLS:
REDIS_URL=rediss://user:password@host:6379
```

#### Setup Instructions

1. **Install Redis:**
   ```bash
   # macOS
   brew install redis
   brew services start redis
   
   # Linux
   sudo apt install redis-server
   sudo systemctl start redis
   ```

2. **Test Connection:**
   ```bash
   redis-cli ping
   # Should return: PONG
   ```

3. **Set Environment Variable:**
   ```bash
   export REDIS_URL="redis://localhost:6379"
   ```

4. **For Production (with password):**
   ```bash
   # Edit redis.conf to set a password
   # Then use:
   export REDIS_URL="redis://:your-secure-password@localhost:6379"
   ```

#### Cloud Redis Options

- **Aiven Redis**: Fully managed, use provided connection string
- **AWS ElastiCache**: Use endpoint URL
- **Redis Enterprise Cloud**: Use provided URL

#### Rate Limiting Without Redis

If `REDIS_URL` is not set, the application uses ETS-based rate limiting:
- Works on single nodes only
- Rate limits are not shared across nodes
- Suitable for development and single-server deployments

---

## 📝 Configuration Checklist

### Before First Run

- [ ] PostgreSQL installed and running
- [ ] Database created (`armoricore_realtime`)
- [ ] `DATABASE_URL` environment variable set
- [ ] Database migrations run (`mix ecto.migrate`)
- [ ] Object Storage account created (Akamai/Linode)
- [ ] Object Storage access keys generated
- [ ] `OBJECT_STORAGE_*` environment variables set
- [ ] NATS server running
- [ ] `MESSAGE_BUS_URL` set (default: `nats://localhost:4222`)
- [ ] (Optional) Redis installed for distributed rate limiting

### Production Checklist

- [ ] All credentials use strong passwords/keys
- [ ] `DATABASE_URL` uses SSL (`sslmode=require`)
- [ ] `SECRET_KEY_BASE` generated (`mix phx.gen.secret`)
- [ ] `JWT_SECRET` is a secure random string
- [ ] Object Storage credentials are production keys
- [ ] All `.env` files are in `.gitignore`
- [ ] No credentials committed to version control
- [ ] Key store initialized for encrypted storage
- [ ] Environment variables set in production environment
- [ ] Redis configured with `REDIS_URL` for multi-node deployments

---

## 🔒 Security Best Practices

1. **Never Commit Credentials:**
   - Use `.env` files (already in `.gitignore`)
   - Or use environment variables
   - Or use encrypted key store

2. **Use Strong Passwords:**
   - Database passwords: 20+ characters, mixed case, numbers, symbols
   - Access keys: Use provider-generated keys
   - Secret keys: Use `mix phx.gen.secret` for Phoenix

3. **Rotate Credentials Regularly:**
   - Database passwords: Every 90 days
   - Object Storage keys: Every 180 days
   - JWT secrets: When compromised

4. **Use SSL/TLS:**
   - Database connections: Always use SSL in production
   - Object Storage: Always use HTTPS endpoints

5. **Limit Access:**
   - Database: Use least-privilege user accounts
   - Object Storage: Use IAM policies to limit permissions
   - Key Store: Protect master key with strong password

---

## 🧪 Testing Configuration

### Test Database Connection

```bash
# Elixir
cd elixir_realtime
export DATABASE_URL="postgresql://user:password@localhost:5432/armoricore_realtime"
mix ecto.create
mix ecto.migrate
mix test
```

### Test Object Storage

```bash
# Set environment variables
export OBJECT_STORAGE_ENDPOINT="https://your-bucket.akamai.com"
export OBJECT_STORAGE_ACCESS_KEY="your-access-key"
export OBJECT_STORAGE_SECRET_KEY="your-secret-key"
export OBJECT_STORAGE_BUCKET="your-bucket-name"

# Run media processor (will test connection on first upload)
cd rust-services
cargo run --release --bin media-processor
```

### Test Message Bus

```bash
# Start NATS
nats-server -js

# Test connection
nats pub 'test' '{"message": "test"}'
```

---

## 📚 Additional Resources

- [Quick Start Guide](./QUICK_START.md) - 5-minute setup
- [Startup Guide](./README_STARTUP.md) - Detailed startup instructions
- [Linux Server Installation](./LINUX_SERVER_INSTALLATION.md) - Production deployment
- [Akamai Integration](./rust-services/media-processor/AKAMAI_INTEGRATION.md) - Object storage details

---

## ❓ Troubleshooting

### "DATABASE_URL is missing"

**Solution:**
```bash
export DATABASE_URL="postgresql://user:password@localhost:5432/armoricore_realtime"
```

### "Object storage configuration is required"

**Solution:**
```bash
export OBJECT_STORAGE_ENDPOINT="https://your-bucket.akamai.com"
export OBJECT_STORAGE_ACCESS_KEY="your-access-key"
export OBJECT_STORAGE_SECRET_KEY="your-secret-key"
export OBJECT_STORAGE_BUCKET="your-bucket-name"
```

### "PostgreSQL connection failed"

**Solutions:**
1. Ensure PostgreSQL is running: `psql -l`
2. Check credentials in `DATABASE_URL`
3. Verify database exists: `psql -l | grep armoricore`
4. Check firewall/network access

### "Object Storage upload failed"

**Solutions:**
1. Verify access keys are correct
2. Check bucket name matches
3. Verify endpoint URL is correct
4. Check network connectivity
5. Verify bucket permissions allow uploads

---

## 🔄 Updating Credentials

### Change Database Password

1. Update password in PostgreSQL:
   ```sql
   ALTER USER armoricore WITH PASSWORD 'new-password';
   ```

2. Update `DATABASE_URL`:
   ```bash
   export DATABASE_URL="postgresql://armoricore:new-password@localhost:5432/armoricore_realtime"
   ```

3. Restart services

### Rotate Object Storage Keys

1. Generate new keys in Akamai/Linode console
2. Update environment variables:
   ```bash
   export OBJECT_STORAGE_ACCESS_KEY="new-access-key"
   export OBJECT_STORAGE_SECRET_KEY="new-secret-key"
   ```
3. Test connection
4. Delete old keys after verification

---

## 📞 Support

For configuration issues:
- Check logs: `tail -f logs/*.log`
- Review [Troubleshooting](#-troubleshooting) section
- Open an issue on GitHub

