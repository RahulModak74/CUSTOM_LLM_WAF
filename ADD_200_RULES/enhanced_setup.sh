#!/bin/bash

# Traffic-Prism WAF Setup Script
# Enhanced with OWASP CRS support

set -e

echo "🛡️  Traffic-Prism WAF Setup"
echo "=" * 50

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

# Check Python version
check_python() {
    print_info "Checking Python version..."
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 --version | cut -d' ' -f2 | cut -d'.' -f1,2)
        print_status "Python 3 found: $(python3 --version)"
        
        # Check if version is 3.8 or higher
        if [[ $(echo "$PYTHON_VERSION >= 3.8" | bc -l) -eq 1 ]]; then
            print_status "Python version is compatible"
        else
            print_error "Python 3.8+ required, found $PYTHON_VERSION"
            exit 1
        fi
    else
        print_error "Python 3 not found. Please install Python 3.8+"
        exit 1
    fi
}

# Install dependencies
install_dependencies() {
    print_info "Installing Python dependencies..."
    
    # Check if pip is available
    if ! command -v pip3 &> /dev/null; then
        print_error "pip3 not found. Please install pip3"
        exit 1
    fi
    
    # Install requirements
    if [ -f "requirements.txt" ]; then
        pip3 install -r requirements.txt
        print_status "Dependencies installed from requirements.txt"
    else
        print_info "Installing core dependencies manually..."
        pip3 install sanic>=23.0.0 sanic-cors>=2.0.0 aiohttp>=3.8.0 aiosqlite>=0.19.0 pydantic>=2.0.0
        print_status "Core dependencies installed"
    fi
}

# Setup directories
setup_directories() {
    print_info "Setting up directories..."
    
    # Create logs directory
    mkdir -p logs
    mkdir -p data
    mkdir -p rules
    
    print_status "Directories created: logs/, data/, rules/"
}

# Download OWASP CRS (optional enhancement)
download_owasp_crs() {
    print_info "OWASP Core Rule Set (CRS) Enhancement"
    echo "This will download 200+ industry-standard WAF rules"
    
    read -p "Download OWASP CRS rules? (y/n): " -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        print_info "Downloading OWASP CRS..."
        
        CRS_VERSION="v3.3.5"
        CRS_URL="https://github.com/coreruleset/coreruleset/archive/${CRS_VERSION}.tar.gz"
        CRS_DIR="rules/owasp-crs"
        
        # Create rules directory
        mkdir -p rules
        
        # Download and extract
        if command -v wget &> /dev/null; then
            wget -O "rules/crs-${CRS_VERSION}.tar.gz" "$CRS_URL"
        elif command -v curl &> /dev/null; then
            curl -L -o "rules/crs-${CRS_VERSION}.tar.gz" "$CRS_URL"
        else
            print_error "Neither wget nor curl found. Please install one of them."
            return 1
        fi
        
        # Extract
        tar -xzf "rules/crs-${CRS_VERSION}.tar.gz" -C rules/
        mv "rules/coreruleset-${CRS_VERSION#v}" "$CRS_DIR"
        rm "rules/crs-${CRS_VERSION}.tar.gz"
        
        print_status "OWASP CRS downloaded to: $CRS_DIR"
        print_info "Rules location: $CRS_DIR/rules/"
        
        # Count rules
        RULE_COUNT=$(find "$CRS_DIR/rules/" -name "*.conf" | wc -l)
        print_status "Available rule files: $RULE_COUNT"
        
        # Create environment variable
        echo "export OWASP_CRS_PATH=\"$(pwd)/$CRS_DIR/rules\"" >> .env
        print_status "CRS path added to .env file"
        
    else
        print_warning "Skipping OWASP CRS download"
        print_info "You can download later with: ./scripts/download_crs.sh"
    fi
}

# Create configuration files
create_config() {
    print_info "Creating configuration files..."
    
    # Create .env file if it doesn't exist
    if [ ! -f ".env" ]; then
        cat > .env << EOF
# Traffic-Prism WAF Configuration
WAF_PORT=8080
WAF_DEBUG=false
BACKEND_URL=http://localhost:3000

# OWASP CRS Path (if downloaded)
# OWASP_CRS_PATH=./rules/owasp-crs/rules/

# Database
DB_PATH=./data/sessions.db

# Logging
LOG_LEVEL=INFO
LOG_FILE=./logs/waf.log
EOF
        print_status "Created .env configuration file"
    else
        print_warning ".env file already exists, skipping creation"
    fi
    
    # Create example backend URL config
    print_info "📝 Configuration Notes:"
    echo "   • Edit .env to set your BACKEND_URL"
    echo "   • Current backend: http://localhost:3000"
    echo "   • WAF will run on port 8080"
}

# Create helper scripts
create_scripts() {
    print_info "Creating helper scripts..."
    
    mkdir -p scripts
    
    # Create download CRS script
    cat > scripts/download_crs.sh << 'EOF'
#!/bin/bash
# Download OWASP CRS separately

CRS_VERSION="v3.3.5"
CRS_URL="https://github.com/coreruleset/coreruleset/archive/${CRS_VERSION}.tar.gz"
CRS_DIR="rules/owasp-crs"

echo "🔄 Downloading OWASP CRS..."
mkdir -p rules

if command -v wget &> /dev/null; then
    wget -O "rules/crs-${CRS_VERSION}.tar.gz" "$CRS_URL"
elif command -v curl &> /dev/null; then
    curl -L -o "rules/crs-${CRS_VERSION}.tar.gz" "$CRS_URL"
else
    echo "❌ Neither wget nor curl found"
    exit 1
fi

tar -xzf "rules/crs-${CRS_VERSION}.tar.gz" -C rules/
mv "rules/coreruleset-${CRS_VERSION#v}" "$CRS_DIR"
rm "rules/crs-${CRS_VERSION}.tar.gz"

echo "✅ OWASP CRS downloaded to: $CRS_DIR"
echo "📁 Rules location: $CRS_DIR/rules/"
EOF
    
    chmod +x scripts/download_crs.sh
    
    # Create load CRS script
    cat > scripts/load_crs.py << 'EOF'
#!/usr/bin/env python3
"""
Load OWASP CRS rules into Traffic-Prism WAF
Usage: python3 scripts/load_crs.py [crs_rules_directory]
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from security_modules.modsec_parser import load_owasp_crs_rules

def main():
    if len(sys.argv) > 1:
        crs_dir = sys.argv[1]
    else:
        # Default path
        crs_dir = "./rules/owasp-crs/rules/"
    
    if not os.path.exists(crs_dir):
        print(f"❌ CRS directory not found: {crs_dir}")
        print("💡 Download first with: ./scripts/download_crs.sh")
        return 1
    
    print(f"🔄 Loading OWASP CRS rules from: {crs_dir}")
    rules = load_owasp_crs_rules(crs_dir)
    
    if rules:
        print(f"✅ Successfully loaded {len(rules)} OWASP CRS rules")
        print("🎯 Rules are ready to be imported into your WAF")
        
        # Show sample rules
        print("\n📋 Sample rules loaded:")
        for i, rule in enumerate(rules[:5]):
            print(f"   {rule.id}: {rule.message}")
        
        if len(rules) > 5:
            print(f"   ... and {len(rules) - 5} more rules")
    else:
        print("❌ No rules loaded")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
EOF
    
    chmod +x scripts/load_crs.py
    
    print_status "Helper scripts created in scripts/"
}

# Test WAF setup
test_setup() {
    print_info "Testing WAF setup..."
    
    # Test imports
    python3 -c "
import sys
try:
    from security_modules.waf_engine import WAFEngine
    from security_modules.session_analytics import SecurityAnalytics
    from security_modules.modsec_parser import ModSecurityParser
    print('✅ All security modules import successfully')
except ImportError as e:
    print(f'❌ Import error: {e}')
    sys.exit(1)
" || exit 1
    
    print_status "WAF modules test passed"
}

# Main setup function
main() {
    echo "🚀 Starting Traffic-Prism WAF setup..."
    echo
    
    # Run setup steps
    check_python
    install_dependencies
    setup_directories
    create_config
    create_scripts
    test_setup
    
    # Optional enhancement
    echo
    print_info "🎯 Optional Enhancement:"
    download_owasp_crs
    
    echo
    print_status "Setup completed successfully!"
    echo
    print_info "📋 Next Steps:"
    echo "   1. Edit .env file to configure your backend URL"
    echo "   2. Start WAF: python3 main.py remote-debug"
    echo "   3. Test health: curl http://localhost:8080/health"
    echo
    print_info "🔧 Enhancement Options:"
    echo "   • Load OWASP CRS: python3 scripts/load_crs.py"
    echo "   • Download CRS later: ./scripts/download_crs.sh"
    echo
    print_info "📚 Documentation:"
    echo "   • Check README.md for deployment guide"
    echo "   • Monitor logs in logs/ directory"
    echo "   • View status at http://localhost:8080/status"
}

# Run main function
main "$@"
