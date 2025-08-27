#!/bin/bash

# PortScan-RS Installation Script
# Installs the port scanner to /usr/local/bin

set -e

CYAN='\033[0;36m'
GREEN='\033[0;32m'
RED='\033[0;31m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

echo -e "${PURPLE}"
echo "╔═══════════════════════════════════════════════════════════════════════════════╗"
echo "║  ██▓███   ▒█████   ██▀███  ▄▄▄█████▓  ██████  ▄████▄   ▄▄▄       ███▄    █    ║"
echo "║ ▓██░  ██▒▒██▒  ██▒▓██ ▒ ██▒▓  ██▒ ▓▒▒██    ▒ ▒██▀ ▀█  ▒████▄     ██ ▀█   █    ║"
echo "║ ▓██░ ██▓▒▒██░  ██▒▓██ ░▄█ ▒▒ ▓██░ ▒░░ ▓██▄   ▒▓█    ▄ ▒██  ▀█▄  ▓██  ▀█ ██▒   ║"
echo "║ ▒██▄█▓▒ ▒▒██   ██░▒██▀▀█▄  ░ ▓██▓ ░   ▒   ██▒▒▓▓▄ ▄██▒░██▄▄▄▄██ ▓██▒  ▐▌██▒   ║"
echo "║ ▒██▒ ░  ░░ ████▓▒░░██▓ ▒██▒  ▒██▒ ░ ▒██████▒▒▒ ▓███▀ ░ ▓█   ▓██▒▒██░   ▓██░   ║"
echo "║ ▒▓▒░ ░  ░░ ▒░▒░▒░ ░ ▒▓ ░▒▓░  ▒ ░░   ▒ ▒▓▒ ▒ ░░ ░▒ ▒  ░ ▒▒   ▓▒█░░ ▒░   ▒ ▒    ║"
echo "╠═══════════════════════════════════════════════════════════════════════════════╣"
echo "║                        ░▒ ▒  INSTALLER ▒▒ ░                        ║"
echo "╚═══════════════════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check if running as root for system-wide installation
if [[ $EUID -eq 0 ]]; then
   INSTALL_DIR="/usr/local/bin"
   echo -e "${CYAN}⟦STATUS⟧${NC} Installing system-wide to $INSTALL_DIR"
else
   # Install to user's local bin directory
   INSTALL_DIR="$HOME/.local/bin"
   echo -e "${CYAN}⟦STATUS⟧${NC} Installing for current user to $INSTALL_DIR"
   
   # Create directory if it doesn't exist
   mkdir -p "$INSTALL_DIR"
   
   # Check if directory is in PATH
   if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
      echo -e "${CYAN}⟦INFO⟧${NC} Add $INSTALL_DIR to your PATH by adding this to ~/.bashrc or ~/.zshrc:"
      echo -e "  export PATH=\"\$PATH:$INSTALL_DIR\""
   fi
fi

# Check if cargo is installed
if ! command -v cargo &> /dev/null; then
    echo -e "${RED}⟦ERROR⟧${NC} Cargo not found. Please install Rust first:"
    echo "  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    exit 1
fi

# Build the project in release mode
echo -e "${CYAN}⟦BUILD⟧${NC} Building release binary..."
cargo build --release

# Check if build was successful
if [ ! -f "target/release/portscan" ]; then
    echo -e "${RED}⟦ERROR⟧${NC} Build failed. Binary not found."
    exit 1
fi

# Copy binary to installation directory
echo -e "${CYAN}⟦INSTALL⟧${NC} Installing portscan to $INSTALL_DIR..."
cp target/release/portscan "$INSTALL_DIR/portscan"

# Make sure it's executable
chmod +x "$INSTALL_DIR/portscan"

# Verify installation
if [ -f "$INSTALL_DIR/portscan" ]; then
    echo -e "${GREEN}⟦SUCCESS⟧${NC} PortScan installed successfully!"
    echo -e "${CYAN}⟦INFO⟧${NC} Run 'portscan --help' to get started"
    
    # Show version
    "$INSTALL_DIR/portscan" --version
else
    echo -e "${RED}⟦ERROR⟧${NC} Installation failed."
    exit 1
fi

echo -e "${PURPLE}"
echo "╔═══════════════════════════════════════════════════════════════════════════════╗"
echo "║                     ⚡ INSTALLATION COMPLETE ⚡                      ║"
echo "╚═══════════════════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Provide usage examples
echo -e "${CYAN}⟦EXAMPLES⟧${NC}"
echo "  portscan --target 192.168.1.0/24 --ports common"
echo "  portscan --target google.com --ports 80,443"
echo "  portscan --target 10.0.0.1-10.0.0.100 --ports web --scan-type syn"
echo ""
echo -e "${CYAN}⟦NOTE⟧${NC} SYN scanning requires root privileges"