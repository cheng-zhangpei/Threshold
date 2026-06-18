#!/bin/bash
# 生成测试用的自签名证书
# 用法: cd certs && bash generate.sh

set -e

echo "=== Generating CA key and cert ==="
openssl genrsa -out ca.key 2048
openssl req -new -x509 -days 365 -key ca.key -out ca.crt \
    -subj "/C=CN/ST=Test/L=Test/O=Threshold/CN=Threshold-CA"

echo "=== Generating server key and cert ==="
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr \
    -subj "/C=CN/ST=Test/L=Test/O=Threshold/CN=localhost"

# 添加 SAN (Subject Alternative Name)，让 TLS 验证通过
cat > server_ext.cnf <<EOF
[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
EOF

openssl x509 -req -days 365 -in server.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out server.crt -extfile server_ext.cnf -extensions v3_req

echo "=== Done ==="
echo "  CA cert:     certs/ca.crt"
echo "  Server cert: certs/server.crt"
echo "  Server key:  certs/server.key"
echo ""
echo "Client uses ca.crt to verify server."
echo "Server uses server.crt + server.key."
#!/bin/bash
# 生成测试用的自签名证书
# 用法: cd certs && bash generate.sh

set -e

echo "=== Generating CA key and cert ==="
openssl genrsa -out ca.key 2048
openssl req -new -x509 -days 365 -key ca.key -out ca.crt \
    -subj "/C=CN/ST=Test/L=Test/O=Threshold/CN=Threshold-CA"

echo "=== Generating server key and cert ==="
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr \
    -subj "/C=CN/ST=Test/L=Test/O=Threshold/CN=localhost"

# 添加 SAN (Subject Alternative Name)，让 TLS 验证通过
cat > server_ext.cnf <<EOF
[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
EOF

openssl x509 -req -days 365 -in server.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out server.crt -extfile server_ext.cnf -extensions v3_req

echo "=== Done ==="
echo "  CA cert:     certs/ca.crt"
echo "  Server cert: certs/server.crt"
echo "  Server key:  certs/server.key"
echo ""
echo "Client uses ca.crt to verify server."
echo "Server uses server.crt + server.key."