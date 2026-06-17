#!/bin/bash
# 客户端启动脚本
set -e

# 默认配置文件路径
DEFAULT_CONFIG="./client/configs/clients.yaml"
CONFIG_PATH="${1:-$DEFAULT_CONFIG}"

if [ ! -f "$CONFIG_PATH" ]; then
    echo "Error: Config file '$CONFIG_PATH' not found."
    exit 1
fi

echo "Using config: $CONFIG_PATH"

# 编译并运行客户端
go run cmd/client/main.go -config "$CONFIG_PATH"