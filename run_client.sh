#!/bin/bash
# 客户端启动脚本
set -e

DEFAULT_CONFIG="./client/configs/clients.yaml"
CONFIG_PATH="${1:-$DEFAULT_CONFIG}"

if [ ! -f "$CONFIG_PATH" ]; then
    echo "Error: Config file '$CONFIG_PATH' not found."
    exit 1
fi

echo "Using config: $CONFIG_PATH"

# 切换到脚本所在目录（项目根目录）
cd "$(dirname "$0")"

# 编译并运行（先清理旧二进制）
echo "Building and running Threshold client..."
go run cmd/client/main.go -config "$CONFIG_PATH"