#!/bin/bash
# 生成 protobuf Go 代码

set -e

# 获取脚本所在目录的绝对路径
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# 项目根目录是脚本目录的上一级
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

PROTO_DIR="$PROJECT_ROOT/pkg/proto"
OUT_DIR="$PROJECT_ROOT/pkg/proto/pb"

mkdir -p "$OUT_DIR"

echo "Project root: $PROJECT_ROOT"
echo "Proto dir: $PROTO_DIR"

if [ ! -d "$PROTO_DIR" ]; then
    echo "Error: Proto directory not found: $PROTO_DIR"
    exit 1
fi

# 使用 find 查找所有 .proto 文件（仅当前目录，不递归子目录）
PROTO_FILES=$(find "$PROTO_DIR" -maxdepth 1 -name "*.proto" -type f)
if [ -z "$PROTO_FILES" ]; then
    echo "Error: No .proto files found in $PROTO_DIR"
    exit 1
fi
echo "Found proto files:"
echo "$PROTO_FILES"

# 生成代码，--proto_path 必须指向项目根目录
protoc \
    --proto_path="$PROJECT_ROOT" \
    --go_out="$OUT_DIR" --go_opt=paths=source_relative \
    --go-grpc_out="$OUT_DIR" --go-grpc_opt=paths=source_relative \
    $PROTO_FILES

echo "Proto generation completed. Files generated in $OUT_DIR"