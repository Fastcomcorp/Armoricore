#!/bin/bash
# Armoricore Load Testing Script
# Tests system performance under various load conditions
# Run this script to validate production readiness

set -e

# Configuration
BASE_URL="${BASE_URL:-http://localhost:4000}"
API_URL="${BASE_URL}/api/v1"
WS_URL="${WS_URL:-ws://localhost:4000/socket}"
DURATION="${DURATION:-60}"  # Test duration in seconds
CONCURRENT_USERS="${CONCURRENT_USERS:-100}"
RAMP_UP_TIME="${RAMP_UP_TIME:-10}"  # Ramp up time in seconds

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Results directory
RESULTS_DIR="load_test_results_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$RESULTS_DIR"

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] $1" >> "$RESULTS_DIR/load_test.log"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [SUCCESS] $1" >> "$RESULTS_DIR/load_test.log"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [WARNING] $1" >> "$RESULTS_DIR/load_test.log"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] $1" >> "$RESULTS_DIR/load_test.log"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."

    local missing_tools=()

    # Check for required tools
    command -v curl >/dev/null 2>&1 || missing_tools+=("curl")
    command -v jq >/dev/null 2>&1 || missing_tools+=("jq")
    command -v ab >/dev/null 2>&1 || missing_tools+=("apache2-utils (ab)")
    command -v node >/dev/null 2>&1 || missing_tools+=("node")
    command -v npm >/dev/null 2>&1 || missing_tools+=("npm")

    if [ ${#missing_tools[@]} -ne 0 ]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        log_error "Please install them and try again."
        exit 1
    fi

    # Check if test files exist
    if [ ! -f "test_video.mp4" ]; then
        log_warning "test_video.mp4 not found. Creating a dummy file for testing."
        dd if=/dev/zero of=test_video.mp4 bs=1024 count=1024 2>/dev/null
    fi

    log_success "Prerequisites check passed"
}

# Health check
health_check() {
    log_info "Performing health check..."

    local response
    response=$(curl -s -w "\n%{http_code}" "$API_URL/health" 2>/dev/null)
    local body=$(echo "$response" | head -n -1)
    local status_code=$(echo "$response" | tail -n 1)

    if [ "$status_code" -eq 200 ]; then
        log_success "Health check passed"
        echo "$body" > "$RESULTS_DIR/health_response.json"
        return 0
    else
        log_error "Health check failed with status $status_code"
        echo "$body" > "$RESULTS_DIR/health_response.json"
        return 1
    fi
}

# Create test users
create_test_users() {
    local num_users="$1"
    log_info "Creating $num_users test users..."

    local created=0
    local failed=0

    for i in $(seq 1 "$num_users"); do
        local email="loadtest$i-$(date +%s)@example.com"
        local username="loaduser$i"
        local password="TestPass123!"

        local response
        response=$(curl -s -w "\n%{http_code}" \
            -X POST "$API_URL/auth/register" \
            -H "Content-Type: application/json" \
            -d "{\"email\":\"$email\",\"password\":\"$password\",\"password_confirmation\":\"$password\",\"username\":\"$username\"}" \
            2>/dev/null)

        local status_code=$(echo "$response" | tail -n 1)

        if [ "$status_code" -eq 201 ]; then
            ((created++))
            echo "$email:$password" >> "$RESULTS_DIR/test_users.txt"
        else
            ((failed++))
        fi

        # Progress indicator
        if [ $((i % 10)) -eq 0 ]; then
            log_info "Created $created users, failed $failed..."
        fi
    done

    log_success "Created $created test users, $failed failed"
    echo "$created" > "$RESULTS_DIR/created_users_count.txt"
}

# API load testing
test_api_endpoints() {
    log_info "Testing API endpoints with load..."

    local test_user_file="$RESULTS_DIR/test_users.txt"
    local auth_token=""

    # Get auth token from first test user if available
    if [ -f "$test_user_file" ] && [ -s "$test_user_file" ]; then
        local first_user=$(head -n 1 "$test_user_file")
        local email=$(echo "$first_user" | cut -d: -f1)
        local password=$(echo "$first_user" | cut -d: -f2)

        auth_token=$(curl -s \
            -X POST "$API_URL/auth/login" \
            -H "Content-Type: application/json" \
            -d "{\"email\":\"$email\",\"password\":\"$password\"}" \
            2>/dev/null | jq -r '.token // empty')

        if [ -n "$auth_token" ]; then
            log_success "Obtained auth token for API testing"
        else
            log_warning "Failed to get auth token, proceeding without authentication"
        fi
    fi

    # Test public endpoints
    log_info "Testing public API endpoints..."

    # Health check load test
    ab -n 1000 -c 50 -g "$RESULTS_DIR/health_load.tsv" \
        -H "Accept: application/json" \
        "$API_URL/health" 2>/dev/null

    # Videos listing
    ab -n 500 -c 25 -g "$RESULTS_DIR/videos_load.tsv" \
        -H "Accept: application/json" \
        "$API_URL/videos" 2>/dev/null

    if [ -n "$auth_token" ]; then
        log_info "Testing authenticated API endpoints..."

        # User videos (authenticated)
        ab -n 200 -c 10 -g "$RESULTS_DIR/user_videos_load.tsv" \
            -H "Accept: application/json" \
            -H "Authorization: Bearer $auth_token" \
            "$API_URL/videos/my" 2>/dev/null
    fi

    log_success "API load testing completed"
}

# Video upload testing
test_video_upload() {
    log_info "Testing video upload performance..."

    local test_user_file="$RESULTS_DIR/test_users.txt"
    local upload_results="$RESULTS_DIR/upload_results.txt"

    if [ ! -f "$test_user_file" ] || [ ! -s "$test_user_file" ]; then
        log_warning "No test users available for video upload testing"
        return 0
    fi

    local first_user=$(head -n 1 "$test_user_file")
    local email=$(echo "$first_user" | cut -d: -f1)
    local password=$(echo "$first_user" | cut -d: -f2)

    local auth_token=$(curl -s \
        -X POST "$API_URL/auth/login" \
        -H "Content-Type: application/json" \
        -d "{\"email\":\"$email\",\"password\":\"$password\"}" \
        2>/dev/null | jq -r '.token // empty')

    if [ -z "$auth_token" ]; then
        log_warning "No auth token available for video upload testing"
        return 0
    fi

    log_info "Performing video upload load test..."

    # Create a script for parallel uploads
    cat > "$RESULTS_DIR/upload_test.js" << EOF
const fs = require('fs');
const http = require('http');
const https = require('https');

const authToken = '$auth_token';
const videoFile = 'test_video.mp4';
const apiUrl = '$API_URL';

async function uploadVideo(iteration) {
  const startTime = Date.now();

  try {
    const stats = fs.statSync(videoFile);
    const fileStream = fs.createReadStream(videoFile);

    const boundary = '----FormBoundary' + Math.random().toString(36).substr(2);
    const postData = [
      '--' + boundary + '\\r\\n',
      'Content-Disposition: form-data; name="file"; filename="load_test_' + iteration + '.mp4"\\r\\n',
      'Content-Type: video/mp4\\r\\n\\r\\n',
    ].join('');

    const endData = '\\r\\n--' + boundary + '--\\r\\n';

    const options = {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + authToken,
        'Content-Type': 'multipart/form-data; boundary=' + boundary,
        'Transfer-Encoding': 'chunked'
      }
    };

    const url = new URL(apiUrl + '/videos');
    options.hostname = url.hostname;
    options.port = url.port || (url.protocol === 'https:' ? 443 : 80);
    options.path = url.pathname;

    const client = url.protocol === 'https:' ? https : http;

    return new Promise((resolve) => {
      const req = client.request(options, (res) => {
        let data = '';
        res.on('data', (chunk) => data += chunk);
        res.on('end', () => {
          const duration = Date.now() - startTime;
          resolve({
            status: res.statusCode,
            duration: duration,
            size: data.length
          });
        });
      });

      req.on('error', (err) => {
        const duration = Date.now() - startTime;
        resolve({
          status: 0,
          duration: duration,
          error: err.message
        });
      });

      req.write(postData);
      fileStream.pipe(req);
      fileStream.on('end', () => {
        req.end(endData);
      });
    });

  } catch (error) {
    return {
      status: 0,
      duration: Date.now() - startTime,
      error: error.message
    };
  }
}

async function runUploadTest() {
  const results = [];
  const concurrentUploads = 5;
  const totalUploads = 20;

  console.log(\`Starting upload test: \${totalUploads} uploads with \${concurrentUploads} concurrent\`);

  for (let batch = 0; batch < totalUploads; batch += concurrentUploads) {
    const promises = [];
    for (let i = 0; i < concurrentUploads && (batch + i) < totalUploads; i++) {
      promises.push(uploadVideo(batch + i + 1));
    }

    const batchResults = await Promise.all(promises);
    results.push(...batchResults);

    console.log(\`Completed batch \${Math.floor(batch/concurrentUploads) + 1}\`);
  }

  // Calculate statistics
  const successful = results.filter(r => r.status === 201);
  const avgDuration = results.reduce((sum, r) => sum + r.duration, 0) / results.length;

  console.log(\`Upload test completed:\`);
  console.log(\`- Total uploads: \${results.length}\`);
  console.log(\`- Successful: \${successful.length}\`);
  console.log(\`- Failed: \${results.length - successful.length}\`);
  console.log(\`- Average duration: \${Math.round(avgDuration)}ms\`);

  // Write results to file
  require('fs').writeFileSync('$RESULTS_DIR/upload_results.json',
    JSON.stringify({
      total: results.length,
      successful: successful.length,
      failed: results.length - successful.length,
      averageDuration: Math.round(avgDuration),
      results: results
    }, null, 2)
  );
}

runUploadTest().catch(console.error);
EOF

    # Run the upload test
    cd "$(dirname "$0")" && node "$RESULTS_DIR/upload_test.js"

    if [ -f "$RESULTS_DIR/upload_results.json" ]; then
        log_success "Video upload testing completed"
    else
        log_error "Video upload testing failed"
    fi
}

# WebSocket connection testing
test_websocket_connections() {
    log_info "Testing WebSocket connection scaling..."

    # Create WebSocket load test script
    cat > "$RESULTS_DIR/ws_test.js" << EOF
const WebSocket = require('ws');

const wsUrl = '$WS_URL';
const maxConnections = 500;
const testDuration = 30000; // 30 seconds

async function createWebSocketConnection(id) {
  return new Promise((resolve) => {
    const startTime = Date.now();

    try {
      const ws = new WebSocket(wsUrl + '/websocket?vsn=2.0.0');

      ws.on('open', () => {
        const connectTime = Date.now() - startTime;

        // Send a ping every 5 seconds
        const pingInterval = setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) {
            ws.ping();
          }
        }, 5000);

        // Close after test duration
        setTimeout(() => {
          clearInterval(pingInterval);
          if (ws.readyState === WebSocket.OPEN) {
            ws.close();
          }
        }, testDuration);

        resolve({ id, status: 'connected', connectTime });
      });

      ws.on('error', (error) => {
        const connectTime = Date.now() - startTime;
        resolve({ id, status: 'error', connectTime, error: error.message });
      });

      ws.on('close', () => {
        resolve({ id, status: 'closed', connectTime: Date.now() - startTime });
      });

    } catch (error) {
      resolve({ id, status: 'error', connectTime: Date.now() - startTime, error: error.message });
    }
  });
}

async function runWebSocketTest() {
  console.log(\`Creating \${maxConnections} WebSocket connections...\`);

  const connectionPromises = [];
  for (let i = 0; i < maxConnections; i++) {
    connectionPromises.push(createWebSocketConnection(i + 1));

    // Stagger connections to avoid overwhelming the server
    if (i % 50 === 0) {
      await new Promise(resolve => setTimeout(resolve, 100));
    }
  }

  const results = await Promise.all(connectionPromises);

  const connected = results.filter(r => r.status === 'connected').length;
  const errors = results.filter(r => r.status === 'error').length;
  const avgConnectTime = results.reduce((sum, r) => sum + (r.connectTime || 0), 0) / results.length;

  console.log(\`WebSocket test completed:\`);
  console.log(\`- Total connections attempted: \${maxConnections}\`);
  console.log(\`- Successfully connected: \${connected}\`);
  console.log(\`- Connection errors: \${errors}\`);
  console.log(\`- Average connection time: \${Math.round(avgConnectTime)}ms\`);

  // Write detailed results
  require('fs').writeFileSync('$RESULTS_DIR/websocket_results.json',
    JSON.stringify({
      total: maxConnections,
      connected: connected,
      errors: errors,
      averageConnectTime: Math.round(avgConnectTime),
      results: results.slice(0, 100) // Sample of first 100 results
    }, null, 2)
  );

  // Wait for all connections to close
  await new Promise(resolve => setTimeout(resolve, testDuration + 5000));
}

runWebSocketTest().catch(console.error);
EOF

    # Install ws package if needed
    if ! npm list ws >/dev/null 2>&1; then
        log_info "Installing ws package for WebSocket testing..."
        npm install ws
    fi

    # Run WebSocket test
    node "$RESULTS_DIR/ws_test.js"

    if [ -f "$RESULTS_DIR/websocket_results.json" ]; then
        log_success "WebSocket connection testing completed"
    else
        log_error "WebSocket connection testing failed"
    fi
}

# Database performance testing
test_database_performance() {
    log_info "Testing database performance..."

    # Create database load test script
    cat > "$RESULTS_DIR/db_test.sql" << 'EOF'
-- Database performance test
-- Run with: psql -f db_test.sql -h localhost -U armoricore armoricore_prod

-- Test 1: Simple SELECT performance
EXPLAIN ANALYZE SELECT COUNT(*) FROM videos WHERE deleted_at IS NULL;

-- Test 2: Complex query with JOIN
EXPLAIN ANALYZE
SELECT v.id, v.title, u.username, COUNT(c.id) as comment_count
FROM videos v
LEFT JOIN users u ON v.user_id = u.id
LEFT JOIN comments c ON v.id = c.video_id
WHERE v.deleted_at IS NULL
GROUP BY v.id, v.title, u.username
ORDER BY v.created_at DESC
LIMIT 20;

-- Test 3: Search performance
EXPLAIN ANALYZE
SELECT * FROM videos
WHERE to_tsvector('english', title || ' ' || description) @@ plainto_tsquery('performance test')
AND deleted_at IS NULL;

-- Test 4: User activity query
EXPLAIN ANALYZE
SELECT u.username, COUNT(v.id) as video_count, COUNT(c.id) as comment_count
FROM users u
LEFT JOIN videos v ON u.id = v.user_id AND v.deleted_at IS NULL
LEFT JOIN comments c ON u.id = c.user_id
WHERE u.inserted_at > NOW() - INTERVAL '30 days'
GROUP BY u.id, u.username
HAVING COUNT(v.id) > 0
ORDER BY video_count DESC
LIMIT 50;

-- Test 5: Real-time features performance
EXPLAIN ANALYZE
SELECT r.id, r.name, COUNT(rm.id) as member_count, COUNT(m.id) as message_count
FROM rooms r
LEFT JOIN room_memberships rm ON r.id = rm.room_id
LEFT JOIN messages m ON r.id = m.room_id AND m.inserted_at > NOW() - INTERVAL '1 hour'
WHERE r.is_private = false
GROUP BY r.id, r.name
ORDER BY member_count DESC
LIMIT 10;
EOF

    log_info "Database performance test queries created in $RESULTS_DIR/db_test.sql"
    log_info "Run with: psql -f $RESULTS_DIR/db_test.sql -h <host> -U <user> <database>"
    log_success "Database performance testing setup completed"
}

# Generate report
generate_report() {
    log_info "Generating load test report..."

    local report_file="$RESULTS_DIR/load_test_report.md"

    cat > "$report_file" << EOF
# Armoricore Load Test Report
**Test Date:** $(date)
**Duration:** ${DURATION}s
**Concurrent Users:** ${CONCURRENT_USERS}
**Environment:** ${BASE_URL}

## Executive Summary

Load testing completed for Armoricore platform with focus on:
- API endpoint performance
- Video upload capabilities
- WebSocket connection scaling
- Database query performance

## Test Results

### Health Check Performance
\`\`\`
$(if [ -f "$RESULTS_DIR/health_load.tsv" ]; then
    echo "Requests completed: $(wc -l < "$RESULTS_DIR/health_load.tsv")"
    echo "Average response time: $(awk 'NR>1 {sum+=$5} END {print sum/(NR-1) "ms"}' "$RESULTS_DIR/health_load.tsv")"
    echo "95th percentile: $(sort -n -k5 "$RESULTS_DIR/health_load.tsv" | awk 'BEGIN{i=0} {a[i++]=$$5} END{print a[int((i-1)*0.95)] "ms"}')"
else
    echo "Health load test data not available"
fi)
\`\`\`

### API Performance
\`\`\`
$(if [ -f "$RESULTS_DIR/videos_load.tsv" ]; then
    echo "Videos API - Requests: $(wc -l < "$RESULTS_DIR/videos_load.tsv")"
    echo "Videos API - Avg response: $(awk 'NR>1 {sum+=$5} END {print sum/(NR-1) "ms"}' "$RESULTS_DIR/videos_load.tsv")"
else
    echo "API load test data not available"
fi)
\`\`\`

### Video Upload Performance
\`\`\`
$(if [ -f "$RESULTS_DIR/upload_results.json" ]; then
    jq -r '"Upload tests: \(.total) total, \(.successful) successful, \(.failed) failed, average \(.averageDuration)ms"' "$RESULTS_DIR/upload_results.json"
else
    echo "Upload test data not available"
fi)
\`\`\`

### WebSocket Connections
\`\`\`
$(if [ -f "$RESULTS_DIR/websocket_results.json" ]; then
    jq -r '"WebSocket tests: \(.total) attempted, \(.connected) connected, \(.errors) errors, average \(.averageConnectTime)ms connect time"' "$RESULTS_DIR/websocket_results.json"
else
    echo "WebSocket test data not available"
fi)
\`\`\`

### User Creation
$(if [ -f "$RESULTS_DIR/created_users_count.txt" ]; then
    echo "- Created $(cat "$RESULTS_DIR/created_users_count.txt") test users"
else
    echo "- No test users created"
fi)

## Recommendations

### Performance Optimizations
1. **Database Indexing**: Ensure all recommended indexes are in place
2. **Connection Pooling**: Verify database connection pool size is adequate
3. **Caching**: Implement Redis caching for frequently accessed data
4. **CDN**: Configure CDN for static asset delivery

### Scalability Improvements
1. **Load Balancing**: Implement load balancer for multiple app instances
2. **Database Sharding**: Consider database sharding for high-volume deployments
3. **Background Processing**: Ensure background jobs are properly queued
4. **Monitoring**: Set up comprehensive monitoring and alerting

### Security Considerations
1. **Rate Limiting**: Verify rate limiting is working effectively
2. **SSL/TLS**: Ensure all connections use HTTPS
3. **API Authentication**: Confirm API keys and JWT tokens are validated
4. **Input Validation**: Verify all user inputs are properly sanitized

## Files Generated
$(find "$RESULTS_DIR" -type f -name "*.json" -o -name "*.tsv" -o -name "*.txt" | sort)

## Next Steps
1. Address any performance issues identified
2. Implement recommended optimizations
3. Set up production monitoring
4. Plan capacity for expected user load
5. Prepare rollback procedures

---
*Generated by Armoricore Load Testing Script*
EOF

    log_success "Load test report generated: $report_file"
}

# Main execution
main() {
    log_info "Starting Armoricore load testing..."
    log_info "Results will be saved to: $RESULTS_DIR"

    # Run all tests
    check_prerequisites
    health_check
    create_test_users 10
    test_api_endpoints
    test_video_upload
    test_websocket_connections
    test_database_performance
    generate_report

    log_success "Load testing completed successfully!"
    log_info "Check $RESULTS_DIR for detailed results and reports"
}

# Run main function
main "$@"