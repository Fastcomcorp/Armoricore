#!/bin/bash

# Verify No Secrets in Source Code
# This script checks for hardcoded credentials before release

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║         ARMORICORE SECRET VERIFICATION SCAN                  ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

ISSUES_FOUND=0

# Function to check for patterns
check_pattern() {
    local pattern=$1
    local description=$2
    local exclude_pattern=$3
    
    echo -e "${BLUE}Checking:${NC} $description"
    
    if [ -n "$exclude_pattern" ]; then
        matches=$(grep -r "$pattern" . \
            --include="*.ex" \
            --include="*.exs" \
            --include="*.rs" \
            --include="*.sh" \
            --include="*.toml" \
            --exclude-dir=".git" \
            --exclude-dir="deps" \
            --exclude-dir="_build" \
            --exclude-dir="target" \
            --exclude-dir="node_modules" \
            2>/dev/null | grep -v "$exclude_pattern" || true)
    else
        matches=$(grep -r "$pattern" . \
            --include="*.ex" \
            --include="*.exs" \
            --include="*.rs" \
            --include="*.sh" \
            --include="*.toml" \
            --exclude-dir=".git" \
            --exclude-dir="deps" \
            --exclude-dir="_build" \
            --exclude-dir="target" \
            --exclude-dir="node_modules" \
            2>/dev/null || true)
    fi
    
    if [ -z "$matches" ]; then
        echo -e "  ${GREEN}✅ No issues found${NC}"
    else
        echo -e "  ${RED}❌ Potential issues found:${NC}"
        echo "$matches" | head -5
        if [ $(echo "$matches" | wc -l) -gt 5 ]; then
            echo "  ... and $(( $(echo "$matches" | wc -l) - 5 )) more"
        fi
        ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
    echo ""
}

# Check for database URLs with credentials
echo "1. Database Credentials"
echo "   ────────────────────"
check_pattern "postgres://[^:]+:[^@]+@[^/]+" "PostgreSQL URLs with credentials" \
    "localhost\|example.com\|test\|placeholder\|System.get_env\|DATABASE_URL"

# Check for hardcoded API keys
echo "2. API Keys"
echo "   ────────"
check_pattern 'api_key.*=.*["'"'"'][a-zA-Z0-9_-]{20,}["'"'"']' "Hardcoded API keys" \
    "test\|example\|placeholder\|System.get_env\|env::var"

# Check for hardcoded passwords (excluding test files)
echo "3. Passwords"
echo "   ─────────"
check_pattern 'password.*=.*["'"'"'][^"'"'"']{8,}["'"'"']' "Hardcoded passwords" \
    "test\|example\|placeholder\|secure_password\|TestPass\|password123\|System.get_env"

# Check for AWS-style access keys
echo "4. Access Keys"
echo "   ───────────"
check_pattern 'AKIA[0-9A-Z]{16}' "AWS-style access keys" ""

# Check for private keys
echo "5. Private Keys"
echo "   ────────────"
check_pattern 'BEGIN.*PRIVATE.*KEY' "Private key markers" "example\|test"

# Check for JWT secrets
echo "6. JWT Secrets"
echo "   ───────────"
check_pattern 'jwt_secret.*=.*["'"'"'][a-zA-Z0-9_-]{32,}["'"'"']' "Hardcoded JWT secrets" \
    "System.get_env\|env::var\|default-secret"

# Check for specific Aiven credentials (should be removed)
echo "7. Cloud Provider Credentials"
echo "   ───────────────────────────"
if grep -r "aivencloud.com" . \
    --include="*.ex" \
    --include="*.exs" \
    --include="*.rs" \
    --exclude="*.sh" \
    --exclude-dir=".git" \
    --exclude-dir="deps" \
    --exclude-dir="_build" \
    2>/dev/null | grep -v "example\|test\|comment" > /dev/null; then
    echo -e "  ${RED}❌ Found cloud provider credential references:${NC}"
    grep -r "aivencloud.com" . \
        --include="*.ex" \
        --include="*.exs" \
        --include="*.rs" \
        --exclude="*.sh" \
        --exclude-dir=".git" \
        --exclude-dir="deps" \
        --exclude-dir="_build" \
        2>/dev/null | grep -v "example\|test\|comment" | head -5
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
else
    echo -e "  ${GREEN}✅ No cloud provider credentials found${NC}"
fi
echo ""

# Check .gitignore
echo "8. Gitignore Check"
echo "   ───────────────"
if grep -q "\.env" .gitignore && grep -q "credentials" .gitignore 2>/dev/null || grep -q "\.env" .gitignore; then
    echo -e "  ${GREEN}✅ .gitignore properly configured${NC}"
else
    echo -e "  ${RED}❌ .gitignore may need updates${NC}"
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
fi
echo ""

# Summary
echo "╔══════════════════════════════════════════════════════════════╗"
if [ $ISSUES_FOUND -eq 0 ]; then
    echo "║              ✅ ALL CHECKS PASSED                            ║"
    echo "║                                                              ║"
    echo "║          No hardcoded secrets detected!                      ║"
    echo "║          Source code is clean for release.                   ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    exit 0
else
    echo "║              ❌ ISSUES FOUND: $ISSUES_FOUND                              ║"
    echo "║                                                              ║"
    echo "║          Please review and fix the issues above              ║"
    echo "║          before releasing to production.                     ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
    echo "Recommendations:"
    echo "  1. Replace hardcoded credentials with environment variables"
    echo "  2. Use System.get_env() in Elixir or env::var() in Rust"
    echo "  3. Add sensitive files to .gitignore"
    echo "  4. Review SECURITY_CHECKLIST.md for best practices"
    echo ""
    exit 1
fi
