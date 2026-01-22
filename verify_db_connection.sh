#!/bin/bash

# Database Connection Verification Script
# Usage: DATABASE_URL="postgres://user:pass@host:port/db" ./verify_db_connection.sh

echo "🔍 Verifying PostgreSQL Database Connection"
echo "============================================"

# Check if DATABASE_URL is set
if [ -z "$DATABASE_URL" ]; then
    echo "❌ DATABASE_URL environment variable is not set"
    echo ""
    echo "Usage:"
    echo "  export DATABASE_URL='postgres://user:password@host:port/database?sslmode=require'"
    echo "  ./verify_db_connection.sh"
    echo ""
    echo "Or:"
    echo "  DATABASE_URL='postgres://...' ./verify_db_connection.sh"
    exit 1
fi

# Parse DATABASE_URL to extract host and port
DB_HOST=$(echo "$DATABASE_URL" | sed -E 's|.*@([^:/]+).*|\1|')
DB_PORT=$(echo "$DATABASE_URL" | sed -E 's|.*:([0-9]+)/.*|\1|')

echo "📋 Configuration:"
echo "  Host: $DB_HOST"
echo "  Port: $DB_PORT"
echo ""

echo "🌐 Testing DNS Resolution..."
if nslookup "$DB_HOST" > /dev/null 2>&1; then
    echo "✅ DNS resolution successful"
else
    echo "❌ DNS resolution failed"
    echo "   Possible issues:"
    echo "   - Network connectivity problems"
    echo "   - Database server is paused/stopped"
    echo "   - Firewall blocking DNS queries"
    exit 1
fi

echo ""
echo "🔗 Testing Network Connectivity..."
if nc -z "$DB_HOST" "$DB_PORT" 2>/dev/null; then
    echo "✅ Network connectivity successful"
else
    echo "❌ Network connectivity failed"
    echo "   Possible issues:"
    echo "   - Firewall blocking port $DB_PORT"
    echo "   - Database server is not running"
    exit 1
fi

echo ""
echo "🗄️  Testing Database Connection..."

# Export DATABASE_URL for Elixir
export DATABASE_URL="$DATABASE_URL"

cd "$(dirname "$0")/elixir_realtime" || exit 1

# Test database connection using mix
if mix run -e "IO.puts('Testing database connection...'); case ArmoricoreRealtime.Repo.query('SELECT 1 as test') do {:ok, _} -> IO.puts('✅ Database connection successful!'); {:error, error} -> IO.puts('❌ Database connection failed: #{inspect(error)}'); exit(1) end" 2>/dev/null; then
    echo "✅ Database connection successful!"
else
    echo "❌ Database connection failed"
    echo "   Possible issues:"
    echo "   - Invalid credentials"
    echo "   - SSL certificate issues"
    echo "   - Database permissions"
    exit 1
fi

echo ""
echo "📊 Testing Database Operations..."

# Test basic operations
if mix run -e "
  IO.puts('Testing basic queries...')

  # Test version query
  case ArmoricoreRealtime.Repo.query('SELECT version()') do
    {:ok, %{rows: [[version]]}} ->
      IO.puts('✅ PostgreSQL version: #{String.slice(version, 0, 50)}...')
    {:error, error} ->
      IO.puts('❌ Version query failed: #{inspect(error)}')
      exit(1)
  end

  # Test table existence
  case ArmoricoreRealtime.Repo.query(\"SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' LIMIT 5\") do
    {:ok, %{rows: rows}} ->
      IO.puts('✅ Found #{length(rows)} tables in database')
    {:error, error} ->
      IO.puts('❌ Table query failed: #{inspect(error)}')
      exit(1)
  end

  IO.puts('✅ All database operations successful!')
" 2>/dev/null; then
    echo "✅ All database operations successful!"
else
    echo "❌ Some database operations failed"
    exit 1
fi

echo ""
echo "🎉 Database connection verification complete!"
echo "   The application is properly configured to connect to PostgreSQL."
echo ""
echo "🚀 Next steps:"
echo "   1. Run migrations: mix ecto.migrate"
echo "   2. Run tests: mix test"
echo "   3. Start server: mix phx.server"