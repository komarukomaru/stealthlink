#!/bin/bash

set -e

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${CYAN}=== StealthLink Build ===${NC}"

BUILD_DIR="build"

if [ -d "$BUILD_DIR" ]; then
    rm -rf "$BUILD_DIR"
fi
mkdir -p "$BUILD_DIR"

cd protocol || { echo -e "${RED}Error: Directory 'protocol' not found!${NC}"; exit 1; }

echo -e "${GREEN}[1/5] Server (Linux/AMD64)...${NC}"
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o "../$BUILD_DIR/server-linux-amd64" ./cmd/server

echo -e "${GREEN}[2/5] Server (Windows/AMD64)...${NC}"
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -trimpath -o "../$BUILD_DIR/server-windows-amd64.exe" ./cmd/server

echo -e "${GREEN}[3/5] Client (Windows/AMD64)...${NC}"
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -trimpath -o "../$BUILD_DIR/client-windows-amd64.exe" ./cmd/client

echo -e "${GREEN}[4/5] Client (Linux/AMD64)...${NC}"
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -trimpath -o "../$BUILD_DIR/client-linux-amd64" ./cmd/client

echo -e "${GREEN}[5/5] Client (Android/ARM64)...${NC}"
GOOS=android GOARCH=arm64 go build -ldflags="-s -w" -trimpath -o "../$BUILD_DIR/client-android-arm64" ./cmd/client

cd ..

echo ""
echo -e "${CYAN}=== Build Complete ===${NC}"
echo -e "${YELLOW}Artifacts in '$BUILD_DIR':${NC}"

ls -lh "$BUILD_DIR" | awk '{print "  " $9 " (" $5 ")"}' | grep -v "^  ("

echo ""
echo -e "${YELLOW}Usage:${NC}"
echo "  Server: ./server-linux-amd64 -config config.json"
echo "  Client: ./client-windows-amd64.exe -server host:443 -psk YOUR_KEY -sni host"
echo "  Client: ./client-windows-amd64.exe -sub 'stealthlink://...'"