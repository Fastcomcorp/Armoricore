#!/bin/bash

# Fastcomcorp Armoricore Copyright Header Application Script
# Applies copyright headers to all source files for legal protection

set -e

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║     FASTCOMCORP ARMORICORE COPYRIGHT PROTECTION              ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Copyright headers
ELIXIR_HEADER="# Copyright 2025 Francisco F. Pinochet
# Copyright 2026 Fastcomcorp, LLC
#
# Licensed under the Apache License, Version 2.0 (the \"License\");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an \"AS IS\" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License."

RUST_HEADER="// Copyright 2025 Francisco F. Pinochet
// Copyright 2026 Fastcomcorp, LLC
//
// Licensed under the Apache License, Version 2.0 (the \"License\");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an \"AS IS\" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License."

# Check if file already has copyright
has_copyright() {
    local file=$1
    grep -q "Copyright.*Fastcomcorp" "$file" 2>/dev/null
}

# Process Elixir files
process_elixir_file() {
    local file=$1
    
    if has_copyright "$file"; then
        echo "  ✓ $file (already has copyright)"
        return 0
    fi
    
    # Create temp file with header
    {
        echo "$ELIXIR_HEADER"
        echo ""
        cat "$file"
    } > "$file.tmp"
    
    mv "$file.tmp" "$file"
    echo "  ✅ $file"
}

# Process Rust files
process_rust_file() {
    local file=$1
    
    if has_copyright "$file"; then
        echo "  ✓ $file (already has copyright)"
        return 0
    fi
    
    # Create temp file with header
    {
        echo "$RUST_HEADER"
        echo ""
        cat "$file"
    } > "$file.tmp"
    
    mv "$file.tmp" "$file"
    echo "  ✅ $file"
}

# Main processing
main() {
    local elixir_files=0
    local rust_files=0
    local skipped=0
    local added=0
    
    log_info "Processing Elixir files..."
    while IFS= read -r -d '' file; do
        if has_copyright "$file"; then
            skipped=$((skipped + 1))
        else
            process_elixir_file "$file"
            added=$((added + 1))
        fi
        elixir_files=$((elixir_files + 1))
    done < <(find . \( -name "*.ex" -o -name "*.exs" \) \
        -not -path "*/deps/*" \
        -not -path "*/_build/*" \
        -not -path "*/node_modules/*" \
        -not -path "*/.git/*" \
        -type f -print0)
    
    echo ""
    log_info "Processing Rust files..."
    while IFS= read -r -d '' file; do
        if has_copyright "$file"; then
            skipped=$((skipped + 1))
        else
            process_rust_file "$file"
            added=$((added + 1))
        fi
        rust_files=$((rust_files + 1))
    done < <(find ./rust-services -name "*.rs" \
        -not -path "*/target/*" \
        -not -path "*/.git/*" \
        -type f -print0)
    
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                    SUMMARY                                   ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
    log_info "Total files processed: $((elixir_files + rust_files))"
    log_info "  - Elixir files: $elixir_files"
    log_info "  - Rust files: $rust_files"
    log_success "Copyright headers added: $added"
    log_info "Already had copyright: $skipped"
    echo ""
    log_success "✅ Source code copyright protection complete!"
    echo ""
}

main "$@"
