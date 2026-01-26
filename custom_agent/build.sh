#!/bin/bash

# Wazuh Custom Agent Build Script
# Supports multiple platforms

set -e

VERSION="1.0.0"
APP_NAME="wazuh-agent"
BUILD_DIR="build"

echo "Building Wazuh Custom Agent v${VERSION}"

# Create build directory
mkdir -p ${BUILD_DIR}

# Build for Linux (amd64)
echo "Building for Linux (amd64)..."
GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o ${BUILD_DIR}/${APP_NAME}-linux-amd64 main.go

# Build for Linux (arm64)
echo "Building for Linux (arm64)..."
GOOS=linux GOARCH=arm64 go build -ldflags="-w -s" -o ${BUILD_DIR}/${APP_NAME}-linux-arm64 main.go

# Build for Windows (amd64)
echo "Building for Windows (amd64)..."
GOOS=windows GOARCH=amd64 go build -ldflags="-w -s" -o ${BUILD_DIR}/${APP_NAME}-windows-amd64.exe main.go

# Build for macOS (amd64)
echo "Building for macOS (amd64)..."
GOOS=darwin GOARCH=amd64 go build -ldflags="-w -s" -o ${BUILD_DIR}/${APP_NAME}-darwin-amd64 main.go

# Build for macOS (arm64)
echo "Building for macOS (arm64/M1)..."
GOOS=darwin GOARCH=arm64 go build -ldflags="-w -s" -o ${BUILD_DIR}/${APP_NAME}-darwin-arm64 main.go

echo ""
echo "Build complete! Binaries are in the ${BUILD_DIR} directory:"
ls -lh ${BUILD_DIR}/

echo ""
echo "To run the agent:"
echo "  Linux/macOS: ./${BUILD_DIR}/${APP_NAME}-<platform> config.json"
echo "  Windows: .\\${BUILD_DIR}\\${APP_NAME}-windows-amd64.exe config.json"
