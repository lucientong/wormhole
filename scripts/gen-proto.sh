#!/bin/bash
# Generate protobuf Go files into the pb sub-package.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
PROTO_DIR="$PROJECT_ROOT/pkg/proto"
PB_DIR="$PROTO_DIR/pb"

echo "Generating protobuf files..."

# Check if protoc is installed
if ! command -v protoc &> /dev/null; then
    echo "Error: protoc is not installed"
    echo "Please install protobuf compiler:"
    echo "  macOS: brew install protobuf"
    echo "  Linux: apt-get install protobuf-compiler"
    exit 1
fi

# Check if protoc-gen-go is installed
if ! command -v protoc-gen-go &> /dev/null; then
    echo "Installing protoc-gen-go..."
    go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
fi

# Ensure output directory exists
mkdir -p "$PB_DIR"

# Generate Go files into pb sub-directory
cd "$PROTO_DIR"
for proto_file in *.proto; do
    if [ -f "$proto_file" ]; then
        echo "  Generating from $proto_file..."
        protoc --go_out="$PB_DIR" --go_opt=paths=source_relative "$proto_file"
    fi
done

echo "Done!"
