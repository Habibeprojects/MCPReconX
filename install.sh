#!/bin/bash
# MCPReconX Installation Script
# ==============================
# This script installs MCPReconX and its dependencies.
# Run with: chmod +x install.sh && ./install.sh

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
INSTALL_DIR="/usr/local/bin"
VENV_DIR="$HOME/.mcpreconx"
PYTHON_MIN_VERSION="3.9"

# Functions
print_banner() {
    echo -e "${BLUE}"
    cat << "EOF"
    ███╗   ███╗ ██████╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗
    ████╗ ████║██╔════╝██╔══██╗██╔════╝██╔═══██╗██╔══██╗████╗  ██║╚██╗██╔╝
    ██╔████╔██║██║     ██████╔╝█████╗  ██║   ██║██████╔╝██╔██╗ ██║ ╚███╔╝ 
    ██║╚██╔╝██║██║     ██╔══██╗██╔══╝  ██║   ██║██╔══██╗██║╚██╗██║ ██╔██╗ 
    ██║ ╚═╝ ██║╚██████╗██║  ██║██║     ╚██████╔╝██║  ██║██║ ╚████║██╔╝ ██╗
    ╚═╝     ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝
EOF
    echo -e "${NC}"
    echo -e "${BLUE}Model Context Protocol Security Scanner${NC}"
    echo -e "${BLUE}========================================${NC}\n"
}

print_status() {
    echo -e "${BLUE}[*]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[-]${NC} $1"
}

check_python() {
    print_status "Checking Python version..."
    
    if command -v python3 &> /dev/null; then
        PYTHON_CMD="python3"
    elif command -v python &> /dev/null; then
        PYTHON_CMD="python"
    else
        print_error "Python is not installed. Please install Python $PYTHON_MIN_VERSION or higher."
        exit 1
    fi
    
    PYTHON_VERSION=$($PYTHON_CMD --version 2>&1 | awk '{print $2}')
    print_success "Found Python $PYTHON_VERSION"
    
    # Check version
    if ! $PYTHON_CMD -c "import sys; exit(0 if sys.version_info >= (3, 9) else 1)" 2>/dev/null; then
        print_error "Python $PYTHON_MIN_VERSION or higher is required."
        exit 1
    fi
}

create_virtualenv() {
    print_status "Creating virtual environment..."
    
    if [ -d "$VENV_DIR" ]; then
        print_warning "Virtual environment already exists at $VENV_DIR"
        read -p "Remove and recreate? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            rm -rf "$VENV_DIR"
        fi
    fi
    
    $PYTHON_CMD -m venv "$VENV_DIR"
    print_success "Virtual environment created at $VENV_DIR"
}

install_dependencies() {
    print_status "Installing dependencies..."
    
    source "$VENV_DIR/bin/activate"
    
    # Upgrade pip
    pip install --upgrade pip
    
    # Install requirements
    if [ -f "requirements.txt" ]; then
        pip install -r requirements.txt
    else
        print_warning "requirements.txt not found. Installing core dependencies..."
        pip install aiohttp websockets pydantic pyyaml
    fi
    
    print_success "Dependencies installed"
}

create_launcher() {
    print_status "Creating launcher script..."
    
    LAUNCHER="$INSTALL_DIR/mcpreconx"
    
    if [ -w "$INSTALL_DIR" ]; then
        cat > "$LAUNCHER" << EOF
#!/bin/bash
# MCPReconX Launcher
source "$VENV_DIR/bin/activate"
python "$VENV_DIR/mcpreconx/main.py" "\$@"
EOF
        chmod +x "$LAUNCHER"
        print_success "Launcher created at $LAUNCHER"
    else
        print_warning "Cannot write to $INSTALL_DIR. Creating local launcher..."
        LAUNCHER="$HOME/.local/bin/mcpreconx"
        mkdir -p "$HOME/.local/bin"
        cat > "$LAUNCHER" << EOF
#!/bin/bash
# MCPReconX Launcher
source "$VENV_DIR/bin/activate"
python "$VENV_DIR/mcpreconx/main.py" "\$@"
EOF
        chmod +x "$LAUNCHER"
        print_success "Launcher created at $LAUNCHER"
        print_warning "Add $HOME/.local/bin to your PATH to use 'mcpreconx' command globally"
    fi
}

copy_files() {
    print_status "Copying MCPReconX files..."
    
    # Create directory structure
    mkdir -p "$VENV_DIR/mcpreconx"
    mkdir -p "$VENV_DIR/mcpreconx/modules"
    mkdir -p "$VENV_DIR/mcpreconx/exploits"
    mkdir -p "$VENV_DIR/mcpreconx/logs"
    mkdir -p "$VENV_DIR/mcpreconx/reports"
    mkdir -p "$VENV_DIR/mcpreconx/tampers"
    
    # Copy main files
    if [ -f "main.py" ]; then
        cp main.py "$VENV_DIR/mcpreconx/"
    fi
    
    if [ -f "config.yaml" ]; then
        cp config.yaml "$VENV_DIR/mcpreconx/"
    fi
    
    # Copy modules
    if [ -d "modules" ]; then
        cp -r modules/* "$VENV_DIR/mcpreconx/modules/" 2>/dev/null || true
    fi
    
    # Copy other files
    if [ -d "exploits" ]; then
        cp -r exploits/* "$VENV_DIR/mcpreconx/exploits/" 2>/dev/null || true
    fi
    
    if [ -d "tampers" ]; then
        cp -r tampers/* "$VENV_DIR/mcpreconx/tampers/" 2>/dev/null || true
    fi
    
    print_success "Files copied to $VENV_DIR/mcpreconx"
}

setup_directories() {
    print_status "Setting up directory structure..."
    
    # Create logs and reports directories in current location
    mkdir -p logs
    mkdir -p reports
    
    print_success "Directory structure created"
}

print_completion() {
    echo
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}  MCPReconX Installation Complete!${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo
    echo -e "Usage:"
    echo -e "  ${YELLOW}mcpreconx --target <mcp-url>${NC}"
    echo -e "  ${YELLOW}python main.py --target http://localhost:3000/sse${NC}"
    echo
    echo -e "Examples:"
    echo -e "  ${YELLOW}mcpreconx -t http://localhost:3000/sse --safe${NC}"
    echo -e "  ${YELLOW}mcpreconx -t ws://target.com:8080 --fingerprint-only${NC}"
    echo -e "  ${YELLOW}mcpreconx -t http://target.com/mcp -v --json${NC}"
    echo
    echo -e "For help: ${YELLOW}mcpreconx --help${NC}"
    echo
    echo -e "${RED}⚠️  IMPORTANT: Use only on systems you have permission to test!${NC}"
    echo
}

# Main installation flow
main() {
    print_banner
    
    print_status "Starting MCPReconX installation..."
    
    check_python
    create_virtualenv
    copy_files
    install_dependencies
    setup_directories
    create_launcher
    
    print_completion
}

# Handle command line arguments
case "${1:-}" in
    --uninstall)
        print_status "Uninstalling MCPReconX..."
        rm -rf "$VENV_DIR"
        rm -f "$INSTALL_DIR/mcpreconx"
        rm -f "$HOME/.local/bin/mcpreconx"
        print_success "MCPReconX uninstalled"
        exit 0
        ;;
    --help|-h)
        echo "MCPReconX Installation Script"
        echo "Usage: $0 [options]"
        echo ""
        echo "Options:"
        echo "  --uninstall    Remove MCPReconX"
        echo "  --help, -h     Show this help message"
        exit 0
        ;;
esac

# Run main installation
main
