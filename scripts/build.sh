#!/bin/bash
# Build script for Wormhole

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
DIST_DIR="$PROJECT_ROOT/dist"

# Build info
VERSION=${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo "dev")}
COMMIT=${COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")}
BUILD_TIME=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

LDFLAGS="-X github.com/wormhole-tunnel/wormhole/pkg/version.Version=$VERSION"
LDFLAGS="$LDFLAGS -X github.com/wormhole-tunnel/wormhole/pkg/version.Commit=$COMMIT"
LDFLAGS="$LDFLAGS -X github.com/wormhole-tunnel/wormhole/pkg/version.BuildTime=$BUILD_TIME"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

build() {
    local os=$1
    local arch=$2
    local output="$DIST_DIR/wormhole-${os}-${arch}"
    
    if [ "$os" = "windows" ]; then
        output="${output}.exe"
    fi

    echo -e "${YELLOW}Building for ${os}/${arch}...${NC}"
    GOOS=$os GOARCH=$arch go build -ldflags "$LDFLAGS" -o "$output" ./cmd/wormhole
    echo -e "${GREEN}  -> $output${NC}"
}

main() {
    echo ""
    echo "Building Wormhole $VERSION ($COMMIT)"
    echo ""

    mkdir -p "$DIST_DIR"

    # Build for all platforms
    build linux amd64
    build linux arm64
    build darwin amd64
    build darwin arm64
    build windows amd64

    echo ""
    echo -e "${GREEN}Build complete!${NC}"
    ls -la "$DIST_DIR"
}

main "$@"
