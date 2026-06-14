# Threshold Client - 设计文档

## 1. 定位

Threshold Client 是一个本地代理网关进程，部署在用户终端设备上。
它作为 IDV Client 和 Threshold Server 之间的透明中间层：

```
IDV Client (用户终端应用)
    |
    | gRPC (insecure / TLS)
    v
Threshold Client (本地代理网关)
    | - 接收请求
    | - 附加设备指纹
    | - 记录行为事件
    | - 转发到 Server
    |
    | gRPC (mTLS)
    v
Threshold Server (安全网关)
```

核心原则：
- Client 不做任何安全决策，只负责透传和数据附加
- 所有决策逻辑在 Server 端完成
- Client 是无状态的（状态由 Server 维护）

## 2. 模块架构

Client 由三个模块组成：

```
client/proxy/proxy.go    - 代理核心（gRPC Server + gRPC Client）
client/collector/collector.go - 行为事件采集器
client/redirect/redirect.go  - 流量重定向工具（可选）
```

### 2.1 Proxy（代理核心）

LocalProxy 实现了 pb.SecurityProxyServer 接口，同时作为 gRPC Client 连接 Server。

| 职责 | 说明 |
|------|------|
| gRPC Server | 监听 :9090，接收 IDV Client 连接 |
| gRPC Client | 连接 Threshold Server，透传请求 |
| 连接管理 | 维护 per-connection 状态（collector 等） |
| RPC 转发 | EstablishConnection/ProxyStream/CloseConnection |
| 管理员转发 | RegisterDevice/UnregisterDevice/ListDevices |

### 2.2 Collector（行为采集器）

记录当前连接中的所有操作事件，用于后续画像分析。

| 方法 | 说明 |
|------|------|
| Record(method, path) | 记录一次操作事件 |
| Events() | 返回所有事件副本 |
| EventCount(opType) | 按操作类型统计次数 |
| TotalEvents() | 总事件数 |
| OpTag() | 生成行为摘要标签 |
| Reset() | 清空事件列表 |

OpTag 格式：`total:write:read:lastOp`
例如：`5:2:3:GET /api/vms/status`

### 2.3 Redirect（流量重定向）

可选模块，用于将 IDV Client 的流量重定向到本地代理。

| 方案 | 适用场景 | 说明 |
|------|----------|------|
| proxychains | 命令行工具 | LD_PRELOAD 劫持 socket，生成配置文件 |
| PAC 脚本 | 浏览器访问 | Proxy Auto-Config，按域名匹配重定向 |
| LD_LIBRARY_PATH | 自研应用 | 动态链接库替换（生产阶段） |

注意：在当前架构下（IDV Client 主动 gRPC 连接），Redirect 模块不是必须的。
仅在需要透明代理场景时使用。

## 3. 数据流

### 3.1 连接建立

```
IDV Client                  Threshold Client              Threshold Server
    |                            |                            |
    |-- EstablishConnection ---->|                            |
    |   (device_uuid, user_id,  |-- EstablishConnection ---->|
    |    os_type, ip)           |   (透传)                    |
    |                            |<-- ConnectionAck ----------|
    |<-- ConnectionAck ---------|   (conn_id, accepted)      |
    |   (conn_id)               |                            |
    |                            |-- 创建 connState          |
    |                            |   (connID, collector)      |
```

### 3.2 请求转发

```
IDV Client                  Threshold Client              Threshold Server
    |                            |                            |
    |-- ProxyStream.Send ------->|                            |
    |   (conn_id, raw_http)      |-- Record(collector)        |
    |                            |-- ProxyStream.Send ------>|
    |                            |   (透传请求)                |
    |                            |<-- ProxyStream.Recv -------|
    |                            |   (status, reason)         |
    |<-- ProxyStream.Send ------|                            |
    |   (status, reason)        |                            |
```

### 3.3 连接关闭

```
IDV Client                  Threshold Client              Threshold Server
    |                            |                            |
    |-- CloseConnection -------->|                            |
    |                            |-- 清理 connState           |
    |                            |-- CloseConnection -------->|
    |                            |   (透传)                    |
    |                            |<-- CloseAck ---------------|
    |<-- CloseAck --------------|                            |
```

## 4. Proto 接口

Client 复用 Server 的 SecurityProxy proto，实现相同的接口：

| RPC | Client 行为 |
|-----|-------------|
| EstablishConnection | 转发到 Server，存储 connState |
| ProxyStream | 记录事件到 collector，转发到 Server |
| CloseConnection | 清理 connState，转发到 Server |
| RegisterDevice | 转发到 Server（管理员接口） |
| UnregisterDevice | 转发到 Server（管理员接口） |
| ListDevices | 转发到 Server（管理员接口） |
| PullApproved | 未实现（下游消费者专用） |
| SubscribeNotify | 未实现（下游消费者专用） |

## 5. 设计决策

### 5.1 为什么选 gRPC Server 模式而不是透明代理

| 方案 | 优点 | 缺点 |
|------|------|------|
| 透明代理 (PAC/proxychains) | IDV Client 无需修改 | 需操作网络栈，部署复杂，跨平台兼容性差 |
| gRPC Server 模式 | 协议清晰，部署简单，无 OS 依赖 | IDV Client 需主动连接 |

选择 gRPC Server 模式的原因：
- 不需要操作宿主机网络栈（避免 TUN 设备、iptables 等）
- 用户态实现，部署和调试简单
- IDV Client 只需一个 gRPC 连接即可接入
- 未来可以同时支持两种模式（gRPC 为主，透明代理为可选）

### 5.2 Client 为什么不做安全决策

- 所有决策逻辑集中在 Server 端，保证一致性
- Client 是无状态的，可以水平扩展
- 避免 Client 被攻破后绕过安全策略
- 画像数据只在 Server 端聚合，避免 Client 间数据不同步

### 5.3 Collector 为什么是每个连接独立的

- 连接粒度的画像分析（一个连接 = 一个会话）
- 避免跨连接的事件混淆
- 连接关闭时 collector 数据随 connState 一起清理
- Server 端通过 PortraitStore 做跨连接的聚合分析

## 6. 配置

```yaml
# config/client.yaml
proxy:
  listen_addr: ":9090"      # IDV Client 连接地址
  server_addr: "localhost:50051"  # Threshold Server 地址
  device_uuid: ""            # 设备唯一标识

tls:
  enabled: false
  cert_file: ""
  key_file: ""
  ca_file: ""
```

## 7. 待完善项

| 项目 | 优先级 | 说明 |
|------|--------|------|
| 指纹字段注入 | 高 | 在 raw_http_request 中注入 X-Proxy-* header |
| TLS 支持 | 高 | Client-Server mTLS 双向认证 |
| PullApproved 转发 | 中 | 下游拉取功能透传 |
| SubscribeNotify 转发 | 中 | 通知推送功能透传 |
| 单元测试 | 高 | mock Server 验证透传逻辑 |
| 用户 ID 配置化 | 低 | 从 config 或环境变量读取 |
| 优雅关闭 | 低 | 等待进行中的请求处理完毕 |
