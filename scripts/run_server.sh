#!/bin/bash
set -e
DEFAULT_CONFIG="./config/server.yaml"
CONFIG_PATH="${1:-$DEFAULT_CONFIG}"
echo "Using config: $CONFIG_PATH"
go run cmd/server/main.go -config "$CONFIG_PATH"