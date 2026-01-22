#!/bin/bash
# Copyright 2025 Francisco F. Pinochet
# Copyright 2026 Fastcomcorp, LLC
#
# Quick Security Test for Armoricore
# Focused on critical security checks

BASE_URL="${BASE_URL:-http://localhost:4000}"
API_URL="${BASE_URL}/api/v1"

echo "🛡️ Quick Armoricore Security Test"
echo "================================="

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

vulnerabilities=0
warnings=0

log_success() { echo -e "${GREEN}[PASS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARN]${NC} $1"; ((warnings++)); }
log_error() { echo -e "${RED}[FAIL]${NC} $1"; ((vulnerabilities++)); }

echo "Testing basic endpoints..."

# Test health endpoint
health=$(curl -s -w "%{http_code}" "$API_URL/health" 2>/dev/null | tail -1)
if [ "$health" = "200" ]; then
    log_success "Health endpoint accessible"
else
    log_error "Health endpoint failed (status: $health)"
fi

# Test SQL injection
sql_test=$(curl -s -w "%{http_code}" \
    -X POST "$API_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"email":"admin@test.com","password":"'\'' OR '\''1'\''='\''1"}' \
    2>/dev/null | tail -1)

if [ "$sql_test" = "401" ]; then
    log_success "SQL injection properly rejected"
else
    log_error "Potential SQL injection vulnerability (status: $sql_test)"
fi

# Test XSS in search
xss_test=$(curl -s "$API_URL/videos/search?q=<script>alert(1)</script>" 2>/dev/null)
if echo "$xss_test" | grep -q "<script>"; then
    log_error "XSS payload reflected in search results"
else
    log_success "XSS payload not reflected in search"
fi

# Test rate limiting
echo "Testing rate limiting..."
rate_limited=false
headers_found=false

# First check if rate limiting headers are present
headers=$(curl -s -I "$API_URL/health" 2>/dev/null | grep -i ratelimit)
if echo "$headers" | grep -q "x-ratelimit-limit"; then
    headers_found=true
    log_success "Rate limiting headers present"
else
    log_warning "Rate limiting headers not found"
fi

# Test aggressive requests to trigger rate limit
for i in {1..120}; do
    status=$(curl -s -w "%{http_code}" "$API_URL/health" 2>/dev/null | tail -1)
    if [ "$status" = "429" ]; then
        rate_limited=true
        break
    fi
    # No sleep for aggressive testing
done

if [ "$rate_limited" = true ]; then
    log_success "Rate limiting triggered after $i requests"
elif [ "$headers_found" = true ]; then
    log_success "Rate limiting headers present (may need more requests to trigger)"
else
    log_warning "No rate limiting detected"
fi

# Test invalid auth tokens on protected endpoint
invalid_auth=$(curl -s -w "%{http_code}" \
    -H "Authorization: Bearer invalid.jwt.token" \
    -H "Content-Type: application/json" \
    -X POST "$API_URL/videos" \
    -d '{"video":{"title":"Test Video","description":"Test description"}}' \
    2>/dev/null | tail -1)

if [ "$invalid_auth" = "401" ] || [ "$invalid_auth" = "403" ]; then
    log_success "Invalid tokens properly rejected on protected endpoint"
else
    log_error "Invalid tokens accepted on protected endpoint (status: $invalid_auth)"
fi

# Test path traversal
traversal_test=$(curl -s "$API_URL/videos/search?q=../../../etc/passwd" 2>/dev/null)
if echo "$traversal_test" | grep -q "root:"; then
    log_error "Path traversal vulnerability detected"
else
    log_success "Path traversal properly blocked"
fi

# Test security headers
headers=$(curl -s -I "$BASE_URL/" 2>/dev/null)
if echo "$headers" | grep -q "content-security-policy"; then
    log_success "Content Security Policy header present"
else
    log_warning "Content Security Policy header missing"
fi

if echo "$headers" | grep -q "x-frame-options.*DENY"; then
    log_success "X-Frame-Options properly set to DENY"
else
    log_warning "X-Frame-Options not set or not DENY"
fi

if echo "$headers" | grep -q "x-content-type-options.*nosniff"; then
    log_success "X-Content-Type-Options properly set"
else
    log_warning "X-Content-Type-Options not set"
fi

echo ""
echo "Security Test Summary:"
echo "Vulnerabilities: $vulnerabilities"
echo "Warnings: $warnings"

if [ "$vulnerabilities" -eq 0 ]; then
    echo -e "${GREEN}✅ No critical vulnerabilities detected${NC}"
else
    echo -e "${RED}⚠️  $vulnerabilities vulnerabilities found${NC}"
fi