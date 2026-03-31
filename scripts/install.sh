#!/bin/bash
# Wormhole one-line installer
# Usage: curl -sSL https://install.wormhole.dev | sh

set -e

# Configuration
REPO="lucientong/wormhole"
BINARY_NAME="wormhole"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Detect OS and Architecture
detect_platform() {
    OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
    ARCH="$(uname -m)"

    case "$ARCH" in
        x86_64|amd64)
            ARCH="amd64"
            ;;
        aarch64|arm64)
            ARCH="arm64"
            ;;
        *)
            echo -e "${RED}Unsupported architecture: $ARCH${NC}"
            exit 1
            ;;
    esac

    case "$OS" in
        linux)
            OS="linux"
            ;;
        darwin)
            OS="darwin"
            ;;
        mingw*|msys*|cygwin*)
            OS="windows"
            ;;
        *)
            echo -e "${RED}Unsupported OS: $OS${NC}"
            exit 1
            ;;
    esac

    PLATFORM="${OS}-${ARCH}"
    echo -e "${GREEN}Detected platform: $PLATFORM${NC}"
}

# Get the latest release version
get_latest_version() {
    echo -e "${YELLOW}Fetching latest version...${NC}"
    VERSION=$(curl -sI "https://github.com/${REPO}/releases/latest" | grep -i "location:" | sed 's/.*tag\///' | tr -d '\r\n')
    
    if [ -z "$VERSION" ]; then
        echo -e "${RED}Failed to get latest version${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}Latest version: $VERSION${NC}"
}

# Download and install
install() {
    DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${BINARY_NAME}-${PLATFORM}"
    
    if [ "$OS" = "windows" ]; then
        DOWNLOAD_URL="${DOWNLOAD_URL}.exe"
        BINARY_NAME="${BINARY_NAME}.exe"
    fi

    echo -e "${YELLOW}Downloading from: $DOWNLOAD_URL${NC}"
    
    TMP_DIR=$(mktemp -d)
    TMP_FILE="$TMP_DIR/$BINARY_NAME"
    
    if command -v curl &> /dev/null; then
        curl -sL "$DOWNLOAD_URL" -o "$TMP_FILE"
    elif command -v wget &> /dev/null; then
        wget -q "$DOWNLOAD_URL" -O "$TMP_FILE"
    else
        echo -e "${RED}Neither curl nor wget found. Please install one of them.${NC}"
        exit 1
    fi

    # Verify download
    if [ ! -f "$TMP_FILE" ] || [ ! -s "$TMP_FILE" ]; then
        echo -e "${RED}Download failed${NC}"
        exit 1
    fi

    # Make executable
    chmod +x "$TMP_FILE"

    # Install
    echo -e "${YELLOW}Installing to $INSTALL_DIR...${NC}"
    
    if [ -w "$INSTALL_DIR" ]; then
        mv "$TMP_FILE" "$INSTALL_DIR/$BINARY_NAME"
    else
        echo -e "${YELLOW}Requesting sudo permission to install to $INSTALL_DIR${NC}"
        sudo mv "$TMP_FILE" "$INSTALL_DIR/$BINARY_NAME"
    fi

    # Cleanup
    rm -rf "$TMP_DIR"

    echo -e "${GREEN}✓ Wormhole $VERSION installed successfully!${NC}"
    echo ""
    echo "Get started:"
    echo "  wormhole --help           # Show help"
    echo "  wormhole 8080             # Expose local port 8080"
    echo "  wormhole server           # Start as server"
}

# Main
main() {
    echo ""
    echo "  🕳️  Wormhole Installer"
    echo ""
    
    detect_platform
    get_latest_version
    install
}

main "$@"
