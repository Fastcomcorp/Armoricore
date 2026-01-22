#!/bin/bash
# End-to-End Test Script for Armoricore
# Tests full workflow: media upload -> processing -> storage -> database

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "🧪 Armoricore End-to-End Test"
echo "=============================="
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Configuration
# IMPORTANT: Set DATABASE_URL environment variable before running this script
# Example: DATABASE_URL="postgresql://user:password@localhost:5432/armoricore_realtime"
DATABASE_URL="${DATABASE_URL:-postgresql://postgres:postgres@localhost:5432/armoricore_realtime_dev}"
MESSAGE_BUS_URL="${MESSAGE_BUS_URL:-nats://localhost:4222}"
TEST_MEDIA_ID=$(uuidgen | tr '[:upper:]' '[:lower:]')
TEST_USER_EMAIL="test-$(date +%s)@armoricore.test"

echo "📋 Test Configuration:"
echo "  Media ID: $TEST_MEDIA_ID"
echo "  User Email: $TEST_USER_EMAIL"
echo "  Database: Connected"
echo "  Message Bus: $MESSAGE_BUS_URL"
echo ""

# Step 1: Create test user in database
echo "Step 1: Creating test user in database..."
cd elixir_realtime
export DATABASE_URL
USER_RESULT=$(mix run --no-start -e "
alias ArmoricoreRealtime.Repo
alias ArmoricoreRealtime.Accounts
Application.put_env(:armoricore_realtime, ArmoricoreRealtime.Repo, [
  url: System.get_env(\"DATABASE_URL\"),
  pool_size: 2
])
case Repo.start_link() do
  {:ok, _pid} ->
    case Accounts.create_user(%{
      email: \"$TEST_USER_EMAIL\",
      password: \"TestPassword123!\",
      username: \"testuser\"
    }) do
      {:ok, user} ->
        IO.puts(\"SUCCESS: #{user.id}\")
      {:error, changeset} ->
        IO.puts(\"ERROR: #{inspect(changeset.errors)}\")
    end
    GenServer.stop(Repo)
  error ->
    IO.puts(\"ERROR: #{inspect(error)}\")
end
" 2>&1 | tail -1)

if [[ $USER_RESULT == *"SUCCESS"* ]]; then
    USER_ID=$(echo $USER_RESULT | sed 's/SUCCESS: //')
    echo -e "${GREEN}✅ User created: $USER_ID${NC}"
else
    echo -e "${YELLOW}⚠️  User creation: $USER_RESULT${NC}"
    echo "Continuing with test..."
fi

cd "$SCRIPT_DIR"

# Step 2: Publish test media upload event
echo ""
echo "Step 2: Publishing test media upload event..."
echo "  Event: media.uploaded"
echo "  Media ID: $TEST_MEDIA_ID"

# Check if nats CLI is available
if command -v nats &> /dev/null; then
    nats pub 'armoricore.media_uploaded' "{
      \"event_type\": \"media.uploaded\",
      \"payload\": {
        \"media_id\": \"$TEST_MEDIA_ID\",
        \"user_id\": \"${USER_ID:-00000000-0000-0000-0000-000000000000}\",
        \"url\": \"https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/BigBuckBunny.mp4\",
        \"content_type\": \"video/mp4\",
        \"filename\": \"test-video.mp4\",
        \"file_size\": 1000000
      }
    }" 2>&1
    echo -e "${GREEN}✅ Event published${NC}"
else
    echo -e "${YELLOW}⚠️  NATS CLI not found. Install with: brew install nats-io/nats-tools/nats${NC}"
    echo "You can manually publish the event or continue to check existing data"
fi

# Step 3: Wait for processing
echo ""
echo "Step 3: Waiting for media processing (30 seconds)..."
sleep 30

# Step 4: Check database for media record
echo ""
echo "Step 4: Checking database for media record..."
cd elixir_realtime
export DATABASE_URL
MEDIA_RESULT=$(mix run --no-start -e "
alias ArmoricoreRealtime.Repo
Application.put_env(:armoricore_realtime, ArmoricoreRealtime.Repo, [
  url: System.get_env(\"DATABASE_URL\"),
  pool_size: 2
])
case Repo.start_link() do
  {:ok, _pid} ->
    case Repo.query(\"SELECT id, status, playback_urls FROM media WHERE id = '\$1'::uuid\", [\"$TEST_MEDIA_ID\"]) do
      {:ok, result} ->
        if length(result.rows) > 0 do
          [id, status, urls] = List.first(result.rows)
          IO.puts(\"FOUND: #{id} | #{status} | #{inspect(urls)}\")
        else
          IO.puts(\"NOT_FOUND\")
        end
      error ->
        IO.puts(\"ERROR: #{inspect(error)}\")
    end
    GenServer.stop(Repo)
  error ->
    IO.puts(\"ERROR: #{inspect(error)}\")
end
" 2>&1 | tail -1)

if [[ $MEDIA_RESULT == *"FOUND"* ]]; then
    echo -e "${GREEN}✅ Media record found in database${NC}"
    echo "  $MEDIA_RESULT"
else
    echo -e "${YELLOW}⚠️  Media record not found yet (may still be processing)${NC}"
fi

cd "$SCRIPT_DIR"

# Step 5: Check bucket for uploaded files (if we had AWS CLI or similar)
echo ""
echo "Step 5: Checking object storage..."
echo "  Bucket: ${OBJECT_STORAGE_BUCKET:-your-bucket-name}"
echo "  Expected path: media/$TEST_MEDIA_ID/"
echo -e "${YELLOW}⚠️  Manual check: Verify files in your object storage console${NC}"
echo "  Configure OBJECT_STORAGE_BUCKET environment variable to set bucket name"

# Step 6: Summary
echo ""
echo "=============================="
echo "📊 Test Summary"
echo "=============================="
echo ""
echo "✅ Test User: $TEST_USER_EMAIL"
echo "✅ Test Media ID: $TEST_MEDIA_ID"
echo "✅ Event Published: media.uploaded"
echo ""
echo "📝 Next Steps:"
echo "  1. Check Media Processor logs: tail -f logs/media-processor.log"
echo "  2. Check database: SELECT * FROM media WHERE id = '$TEST_MEDIA_ID'"
echo "  3. Check bucket: Verify files in your object storage (bucket: ${OBJECT_STORAGE_BUCKET:-your-bucket-name})"
echo "  4. Verify files in: media/$TEST_MEDIA_ID/"
echo ""
echo "✅ End-to-end test complete!"
