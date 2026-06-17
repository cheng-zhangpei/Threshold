curl -v --socks5-hostname 127.0.0.1:1080 http://localhost:8080/api/test?foo=bar

# POST 请求
curl -v --socks5-hostname 127.0.0.1:1080 -X POST http://localhost:8080/api/data \
  -H "Content-Type: application/json" \
  -d '{"name":"test","value":123}'

# 带自定义 Header
curl -v --socks5-hostname 127.0.0.1:1080 \
  -H "X-Custom-Header: hello" \
  http://localhost:8080/api/test

# httpbin.org
curl -v --socks5-hostname 127.0.0.1:1080 http://httpbin.org/get

# 通过代理获取公网 IP
curl -s --socks5-hostname 127.0.0.1:1080 http://httpbin.org/ip | jq