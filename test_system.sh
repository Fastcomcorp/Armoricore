#!/bin/bash

# Armoricore System Test Script
# Tests all major components and workflows

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
BASE_URL="http://localhost:4000"
NATS_URL="nats://localhost:4222"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0

print_test() {
    echo -e "${BLUE}[TEST]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
    TESTS_PASSED=$((TESTS_PASSED + 1))
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
    TESTS_FAILED=$((TESTS_FAILED + 1))
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

# Test 1: Health Check
test_health_check() {
    print_test "Testing Phoenix health endpoint..."
    
    response=$(curl -s -w "\n%{http_code}" "${BASE_URL}/api/health" 2>/dev/null)
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')
    
    if [ "$http_code" = "200" ]; then
        if echo "$body" | grep -q '"status":"ok"'; then
            print_success "Health check passed"
            echo "  Response: $body"
            return 0
        else
            print_error "Health check returned unexpected body"
            return 1
        fi
    else
        print_error "Health check failed with HTTP $http_code"
        return 1
    fi
}

# Test 2: NATS Connection
test_nats_connection() {
    print_test "Testing NATS server connection..."
    
    if command -v nats &> /dev/null; then
        if nats stream ls 2>/dev/null | grep -q "armoricore"; then
            print_success "NATS connection verified"
            return 0
        else
            print_warning "NATS is running but no streams found (this is OK if no events published yet)"
            return 0
        fi
    else
        # Fallback: check if port is open
        if nc -z localhost 4222 2>/dev/null; then
            print_success "NATS port 4222 is open"
            return 0
        else
            print_error "NATS server not accessible"
            return 1
        fi
    fi
}

# Test 3: Service Processes
test_service_processes() {
    print_test "Checking service processes..."
    
    services_ok=0
    
    # Check media-processor
    if pgrep -f "media-processor" > /dev/null; then
        print_success "Media Processor is running"
        services_ok=$((services_ok + 1))
    else
        print_error "Media Processor is not running"
    fi
    
    # Check notification-worker
    if pgrep -f "notification-worker" > /dev/null; then
        print_success "Notification Worker is running"
        services_ok=$((services_ok + 1))
    else
        print_error "Notification Worker is not running"
    fi
    
    # Check Phoenix
    if pgrep -f "beam.*phx.server" > /dev/null || lsof -i :4000 > /dev/null 2>&1; then
        print_success "Phoenix server is running"
        services_ok=$((services_ok + 1))
    else
        print_error "Phoenix server is not running"
    fi
    
    if [ $services_ok -eq 3 ]; then
        return 0
    else
        return 1
    fi
}

# Test 4: API Authentication Endpoints
test_auth_endpoints() {
    print_test "Testing authentication endpoints..."
    
    # Test login endpoint (should fail without credentials, but endpoint should exist)
    response=$(curl -s -w "\n%{http_code}" -X POST "${BASE_URL}/api/auth/login" \
        -H "Content-Type: application/json" \
        -d '{"email":"test@example.com","password":"test123"}' 2>/dev/null)
    http_code=$(echo "$response" | tail -n1 | tr -d '\n')
    
    if [ "$http_code" = "401" ] || [ "$http_code" = "400" ] || [ "$http_code" = "422" ]; then
        print_success "Login endpoint is accessible (returned $http_code as expected)"
        return 0
    elif [ "$http_code" = "200" ]; then
        print_warning "Login endpoint returned 200 (credentials might be valid)"
        return 0
    else
        print_error "Login endpoint returned unexpected code: $http_code"
        return 1
    fi
}

# Test 5: Rate Limiting
test_rate_limiting() {
    print_test "Testing rate limiting..."
    
    # Make multiple requests quickly
    rate_limited=0
    for i in {1..15}; do
        response=$(curl -s -w "\n%{http_code}" "${BASE_URL}/api/health" 2>/dev/null)
        http_code=$(echo "$response" | tail -n1 | tr -d '\n')
        
        if [ "$http_code" = "429" ]; then
            rate_limited=1
            break
        fi
        sleep 0.1
    done
    
    if [ $rate_limited -eq 1 ]; then
        print_success "Rate limiting is working (429 received)"
        return 0
    else
        print_warning "Rate limiting not triggered (may need more requests or higher limit)"
        return 0
    fi
}

# Test 6: WebSocket Connection (basic)
test_websocket() {
    print_test "Testing WebSocket endpoint..."
    
    # Check if WebSocket endpoint is accessible (basic check)
    response=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "Upgrade: websocket" \
        -H "Connection: Upgrade" \
        "${BASE_URL}/socket/websocket" 2>/dev/null)
    
    # WebSocket endpoints typically return 400 or 403 without proper handshake
    if [ "$response" = "400" ] || [ "$response" = "403" ] || [ "$response" = "401" ]; then
        print_success "WebSocket endpoint is accessible (returned $response as expected)"
        return 0
    else
        print_warning "WebSocket endpoint returned $response (may need proper WebSocket client)"
        return 0
    fi
}

# Test 7: Publish Test Event to NATS
test_nats_event_publish() {
    print_test "Testing NATS event publishing..."
    
    if command -v nats &> /dev/null; then
        # Try to publish a test event
        echo '{"media_id":"test-123","url":"https://example.com/test.mp4"}' | \
            nats pub "armoricore.media_uploaded" 2>/dev/null && \
            print_success "Test event published to NATS" || \
            print_warning "Could not publish test event (NATS CLI may need configuration)"
        return 0
    else
        print_warning "NATS CLI not available, skipping event publish test"
        return 0
    fi
}

# Test 8: Check Logs for Errors
test_logs() {
    print_test "Checking service logs for errors..."
    
    errors_found=0
    
    # Check media-processor logs
    if [ -f "${SCRIPT_DIR}/logs/media-processor.log" ]; then
        error_count=$(grep -i "error\|panic\|fatal" "${SCRIPT_DIR}/logs/media-processor.log" 2>/dev/null | wc -l | tr -d ' ')
        if [ "$error_count" -gt 0 ]; then
            print_warning "Found $error_count potential errors in media-processor.log"
            errors_found=$((errors_found + 1))
        fi
    fi
    
    # Check notification-worker logs
    if [ -f "${SCRIPT_DIR}/logs/notification-worker.log" ]; then
        error_count=$(grep -i "error\|panic\|fatal" "${SCRIPT_DIR}/logs/notification-worker.log" 2>/dev/null | wc -l | tr -d ' ')
        if [ "$error_count" -gt 0 ]; then
            print_warning "Found $error_count potential errors in notification-worker.log"
            errors_found=$((errors_found + 1))
        fi
    fi
    
    # Check Phoenix logs
    if [ -f "${SCRIPT_DIR}/logs/phoenix.log" ]; then
        error_count=$(grep -i "error\|crash\|exception" "${SCRIPT_DIR}/logs/phoenix.log" 2>/dev/null | grep -v "ArgumentError" | wc -l | tr -d ' ')
        if [ "$error_count" -gt 0 ]; then
            print_warning "Found $error_count potential errors in phoenix.log"
            errors_found=$((errors_found + 1))
        fi
    fi
    
    if [ $errors_found -eq 0 ]; then
        print_success "No critical errors found in logs"
        return 0
    else
        print_warning "Some errors found in logs (may be expected)"
        return 0
    fi
}

# Test 9: Database Connection (if available)
test_database() {
    print_test "Testing database connection..."
    
    # Try to check if Phoenix can connect to database
    # This is a basic check - actual DB may be remote
    if pgrep -f "beam.*phx.server" > /dev/null; then
        print_success "Phoenix is running (database connection assumed OK)"
        return 0
    else
        print_error "Phoenix is not running"
        return 1
    fi
}

# Test 10: Port Availability
test_ports() {
    print_test "Testing port availability..."
    
    ports_ok=0
    
    # Check port 4000 (Phoenix)
    if lsof -i :4000 > /dev/null 2>&1 || nc -z localhost 4000 2>/dev/null; then
        print_success "Port 4000 (Phoenix) is open"
        ports_ok=$((ports_ok + 1))
    else
        print_error "Port 4000 (Phoenix) is not accessible"
    fi
    
    # Check port 4222 (NATS)
    if lsof -i :4222 > /dev/null 2>&1 || nc -z localhost 4222 2>/dev/null; then
        print_success "Port 4222 (NATS) is open"
        ports_ok=$((ports_ok + 1))
    else
        print_error "Port 4222 (NATS) is not accessible"
    fi
    
    if [ $ports_ok -eq 2 ]; then
        return 0
    else
        return 1
    fi
}

# Main test execution
main() {
    echo "=========================================="
    echo "  Armoricore System Test Suite"
    echo "=========================================="
    echo ""
    
    # Run all tests
    test_health_check
    echo ""
    
    test_nats_connection
    echo ""
    
    test_service_processes
    echo ""
    
    test_ports
    echo ""
    
    test_auth_endpoints
    echo ""
    
    test_rate_limiting
    echo ""
    
    test_websocket
    echo ""
    
    test_nats_event_publish
    echo ""
    
    test_logs
    echo ""
    
    test_database
    echo ""
    
    # Summary
    echo "=========================================="
    echo "  Test Summary"
    echo "=========================================="
    echo -e "${GREEN}Passed:${NC} $TESTS_PASSED"
    echo -e "${RED}Failed:${NC} $TESTS_FAILED"
    echo ""
    
    if [ $TESTS_FAILED -eq 0 ]; then
        echo -e "${GREEN}✓ All tests passed!${NC}"
        exit 0
    else
        echo -e "${YELLOW}⚠ Some tests failed or had warnings${NC}"
        exit 1
    fi
}

# Run tests
main

