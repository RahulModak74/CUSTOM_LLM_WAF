#!/bin/bash

# Traffic-Prism WAF Run Script
# Enhanced with OWASP CRS loading

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

# Load environment variables
load_env() {
    if [ -f ".env" ]; then
        export $(grep -v '^#' .env | xargs)
        print_status "Environment variables loaded from .env"
    else
        print_warning ".env file not found, using defaults"
        export WAF_PORT=8080
        export WAF_DEBUG=false
        export BACKEND_URL=http://localhost:3000
    fi
}

# Pre-flight checks
preflight_checks() {
    print_info "Running pre-flight checks..."
    
    # Check Python
    if ! command -v python3 &> /dev/null; then
        print_error "Python 3 not found"
        exit 1
    fi
    
    # Check main.py exists
    if [ ! -f "main.py" ]; then
        print_error "main.py not found in current directory"
        exit 1
    fi
    
    # Check security modules
    if [ ! -d "security_modules" ]; then
        print_error "security_modules directory not found"
        exit 1
    fi
    
    # Test imports
    python3 -c "
import sys
try:
    from security_modules.waf_engine import WAFEngine
    print('✅ Security modules OK')
except ImportError as e:
    print(f'❌ Import error: {e}')
    sys.exit(1)
" || exit 1
    
    print_status "Pre-flight checks passed"
}

# Load OWASP CRS rules if available
load_crs_rules() {
    if [ -n "$OWASP_CRS_PATH" ] && [ -d "$OWASP_CRS_PATH" ]; then
        print_info "OWASP CRS path found: $OWASP_CRS_PATH"
        
        # Count available rule files
        RULE_FILES=$(find "$OWASP_CRS_PATH" -name "*.conf" 2>/dev/null | wc -l)
        if [ "$RULE_FILES" -gt 0 ]; then
            print_status "Found $RULE_FILES CRS rule files"
            
            # Test
