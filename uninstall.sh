#!/bin/bash

# PortScan-RS Uninstallation Script

set -e

CYAN='\033[0;36m'
GREEN='\033[0;32m'
RED='\033[0;31m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

echo -e "${PURPLE}"
echo "╔═══════════════════════════════════════════════════════════════════════════════╗"
echo "║                    PortScan-RS Uninstaller                         ║"
echo "╚═══════════════════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check common installation locations
LOCATIONS=("/usr/local/bin/portscan" "$HOME/.local/bin/portscan")
FOUND=0

for location in "${LOCATIONS[@]}"; do
    if [ -f "$location" ]; then
        echo -e "${CYAN}⟦FOUND⟧${NC} PortScan at: $location"
        
        # Check if we have permission to remove
        if [ -w "$location" ] || [ $EUID -eq 0 ]; then
            rm -f "$location"
            echo -e "${GREEN}⟦REMOVED⟧${NC} Successfully removed from $location"
            FOUND=1
        else
            echo -e "${RED}⟦ERROR⟧${NC} Permission denied. Try running with sudo:"
            echo "  sudo $0"
            exit 1
        fi
    fi
done

if [ $FOUND -eq 0 ]; then
    echo -e "${RED}⟦ERROR⟧${NC} PortScan not found in standard locations"
    exit 1
else
    echo -e "${GREEN}⟦SUCCESS⟧${NC} PortScan has been uninstalled"
fi