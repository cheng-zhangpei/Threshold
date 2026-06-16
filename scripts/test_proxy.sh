#!/bin/bash
# test_socks5.sh - 测试 SOCKS5 代理是否接收请求（不依赖服务端）

set -e

SOCKS5_PROXY="127.0.0.1:1080"
COLOR_GREEN='\033[0;32m'
COLOR_RED='\033[0;31m'
COLOR_YELLOW='\033[1;33m'
COLOR_NC='\033[0m'

check_client() {
    if ! nc -z 127.0.0.1 1080 2>/dev/null; then
        echo -e "${COLOR_RED}[ERROR] SOCKS5 proxy not running on $SOCKS5_PROXY${COLOR_NC}"
        echo "Please start the client first:"
        echo "  ./testClient.sh"
        exit 1
    fi
}

print_separator() {
    echo -e "\n${COLOR_YELLOW}========================================${COLOR_NC}"
    echo -e "${COLOR_YELLOW}  $1${COLOR_NC}"
    echo -e "${COLOR_YELLOW}========================================${COLOR_NC}\n"
}

test_http() {
    print_separator "场景 1: HTTP 请求 (curl)"
    echo "→ curl --socks5-hostname $SOCKS5_PROXY http://httpbin.org/get"
    # 不管输出，只抓取连接信息，显示代理日志
    curl -v --socks5-hostname "$SOCKS5_PROXY" --connect-timeout 2 http://httpbin.org/get 2>&1 | head -10
    echo -e "${COLOR_GREEN}✓ HTTP 请求已发送（代理应收到请求）${COLOR_NC}"
}

test_https() {
    print_separator "场景 2: HTTPS 请求 (curl via SOCKS5)"
    echo "→ curl --socks5-hostname $SOCKS5_PROXY https://httpbin.org/get"
    curl -v --socks5-hostname "$SOCKS5_PROXY" --connect-timeout 2 https://httpbin.org/get 2>&1 | head -10
    echo -e "${COLOR_GREEN}✓ HTTPS 请求已发送（代理应收到请求）${COLOR_NC}"
}

test_tcp() {
    print_separator "场景 3: 纯 TCP 连接 (nc via SOCKS5)"
    TARGET="httpbin.org"
    PORT="80"
    echo "→ nc -X 5 -x $SOCKS5_PROXY $TARGET $PORT"
    echo -e "HEAD / HTTP/1.0\r\nHost: $TARGET\r\n\r\n" | nc -X 5 -x "$SOCKS5_PROXY" "$TARGET" "$PORT" -v 2>&1 | head -5
    echo -e "${COLOR_GREEN}✓ 纯 TCP 连接已发送（代理应收到连接）${COLOR_NC}"
}

main() {
    echo -e "${COLOR_YELLOW}Threshold SOCKS5 代理接收测试${COLOR_NC}"
    echo "代理地址: $SOCKS5_PROXY"
    echo "注意：本测试只验证代理能否收到请求，不依赖服务端响应"

    check_client
    echo -e "${COLOR_GREEN}✓ 客户端代理运行中${COLOR_NC}"

    test_http
    test_https
    if command -v nc &> /dev/null; then
        test_tcp
    else
        echo -e "${COLOR_YELLOW}跳过纯 TCP 测试 (nc 未安装)${COLOR_NC}"
    fi

    print_separator "测试完成"
    echo -e "请检查客户端日志 (./logs/client.log) 确认代理是否收到了上述请求。"
    echo -e "${COLOR_GREEN}如果日志中有 '[SOCKS5] target: ...' 则说明代理正常工作。${COLOR_NC}"
}

main "$@"