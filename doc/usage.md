# Threshold - 使用文档

## 1. 架构概览

Threshold 由三部分组成：

```
IDV Client -> Threshold Client -> Threshold Server
```

- IDV Client：用户终端上的原始应用，通过 gRPC 连接 Threshold Client
- Threshold Client：本地代理网关，附加设备指纹、记录行为事件、转发到 Server
- Threshold Server：安全网关，指纹校验 + 风险分级 + 决策引擎 + 用户画像

## 2. 快速开始

### 前置条件

- Go 1.25+
- protoc (可选，proto 已预生成)

### 构建

```bash
cd Threshold
go build -o threshold-server ./cmd/server/
go build -o threshold-client ./cmd/client/
```

### 启动 Server

```bash
./threshold-server config/server.yaml
```

默认监听 :50051，读取 config/server.yaml 配置。

### 启动 Client

```bash
./threshold-client config/client.yaml
```

默认监听 :9090（供 IDV Client 连接），连接 Server localhost:50051。

### IDV Client 对接

IDV Client 通过 gRPC 连接到 Threshold Client（:9090）：

1. 调用 EstablishConnection 建立会话，传入 device_uuid、user_id、os_type
2. 调用 ProxyStream 双向流发送请求，Server 返回决策结果
3. 调用 CloseConnection 关闭会话

Proto 定义在 pkg/proto/proxy.proto，生成的 Go 代码在 pkg/proto/pb/。

## 3. 配置说明

### Server 配置 (config/server.yaml)

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| grpc.listen_addr | :50051 | gRPC 监听地址 |
| grpc.rate_limit | 1000 | 令牌桶速率（个/秒） |
| grpc.bucket_size | 2000 | 令牌桶容量 |
| fingerprint.db_path | data/fingerprint.db | 指纹数据库路径 |
| portrait.db_path | data/portrait.db | 画像数据库路径 |
| dispatch.min_workers | 2 | 最小 Worker 数 |
| dispatch.max_workers | 64 | 最大 Worker 数 |

### Client 配置 (config/client.yaml)

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| proxy.listen_addr | :9090 | 本地 gRPC 监听地址 |
| proxy.server_addr | localhost:50051 | Threshold Server 地址 |
| proxy.device_uuid | (空) | 设备唯一标识 |

## 4. 管理员接口

通过 gRPC 调用以下接口管理设备白名单：

| RPC | 说明 |
|-----|------|
| RegisterDevice | 注册新设备到白名单 |
| UnregisterDevice | 从白名单移除设备 |
| ListDevices | 列出已注册设备 |

## 5. 决策引擎

请求处理流水线：

1. 指纹校验：六层 Hash 树匹配，不匹配直接 BLOCKED
2. Router 分级：按 HTTP method+path 分为 L0/L1/L2/L3
3. L0 直接放行，L1+ 进入决策引擎
4. 决策引擎：12 条规则按严重程度排序，首次命中即停
5. 画像更新：连接关闭时提取摘要 + 聚合 UserProfile

详细规则说明见 doc/decision_model.md。

## 6. 测试

```bash
# 全量测试
go test ./... -count=1

# Client-Server 联调测试
go test ./cmd/client/ -v -count=1 -run TestClientProxy

# Server 端到端测试
go test ./cmd/server/ -v -count=1 -run TestIntegration
```
