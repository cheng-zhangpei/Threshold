# 模式二（SOCKS5 转 gRPC）开发总结

## 一、概述

本次开发完成了 Threshold 安全代理的**模式二（SOCKS5 转 gRPC）** 全部核心功能，打通了从 SOCKS5 客户端 → 代理网关 → 安全服务端 → 后端服务器的完整数据链路，支持 HTTP 和 TCP 两种协议的透明代理。

------

## 二、已完成的模块

### 2.1 客户端（Threshold Client）

#### SOCKS5 网关（`client/socks5/`）

- ✅ SOCKS5 协议握手（支持无认证）
- ✅ CONNECT 命令解析（支持 IPv4、域名）
- ✅ 目标地址提取并传递到服务端
- ✅ 双向数据转发（TCP ↔ gRPC 流）
- ✅ 基于 gRPC 响应状态（OK/BLOCKED/RATE_LIMITED）的处理
- ✅ SOCKS5 错误响应（`repFailure`）返回

#### gRPC 代理（`client/proxy/`）

- ✅ 协议探测（HTTP 明文 / TCP 二进制）
- ✅ HTTP 请求自动注入 `X-Proxy-*` 指纹头
- ✅ TCP 流量不注入任何指纹（通过连接级认证）
- ✅ `EstablishConnection` 默认协议设为 `http`

#### 客户端启动（`client/main.go`）

- ✅ 支持多模式启动（gRPC 代理 / SOCKS5 网关）
- ✅ 配置文件驱动（`clients.yaml`）
- ✅ 设备信息自动采集（UUID / OS / IP）

### 2.2 服务端（Threshold Server）

#### gRPC 接入层（`server/grpc/`）

- ✅ `EstablishConnection` 保存设备指纹和协议类型
- ✅ `ProxyStream` 支持 HTTP 和 TCP 双协议分流
- ✅ 默认 `protocol = "http"` 向后兼容

#### 路由器 V2（`server/router_v2/`）

- ✅ 配置驱动规则引擎（YAML）
- ✅ 支持 `*` 通配符匹配（Method / Path）
- ✅ 优先级排序（`priority` 从高到低）
- ✅ HTTP 规则（Method + Path）和 TCP 规则（Method="TCP", Path=目标地址）
- ✅ L0 直传（直接放行到 OutputBuffer）
- ✅ 异步缓冲队列 + 消费者池

#### 输出缓冲 + Sender（`server/output/`）

- ✅ **多级队列**：每个 Worker 独占一个 channel，减少锁竞争
- ✅ **负载均衡**：Put 时选择任务数最少的队列写入
- ✅ **HTTP 转发**：支持 GET/POST/PUT/DELETE，自动注入 `X-Forwarded-For`
- ✅ **TCP 转发**：原始字节流透传（Dial + Write + Read）
- ✅ **响应回传**：通过 `waiter.Complete()` 将响应写回

#### 异步等待队列（`pkg/waiter/`）

- ✅ `reqID → responseCh` 映射管理
- ✅ 支持超时控制（默认 30 秒）
- ✅ 线程安全（读写锁）
- ✅ 解耦 `ProxyStream` 和 `Sender`

#### 设备指纹（`server/fingerprint/`）

- ✅ 六层 Hash 树匹配（UUID / OS / IP / Port / Protocol / Reserved）
- ✅ 设备注册 / 注销接口
- ✅ bbolt 持久化存储

#### 决策引擎（`server/decision/`）

- ✅ 声明式规则引擎（`DECISION_RULES`）
- ✅ 用户画像集成（`PortraitStore`）
- ✅ R10 规则（写操作比例 > 80% 触发告警）

#### 配置管理（`pkg/config/`）

- ✅ 服务端配置（`server.yaml`）
- ✅ 客户端配置（`clients.yaml`）
- ✅ 路由器规则（`router_rules.yaml`）

### 2.3 设备管理工具（`cmd/device-tool/`）

- ✅ 独立设备注册工具（`RegisterDevice`）
- ✅ 独立设备注销工具（`UnregisterDevice`）
- ✅ 支持命令行参数覆盖配置

------

## 三、完整数据链路

### HTTP 请求链路

text

```
curl --socks5 127.0.0.1:1080 http://localhost:8080/api/test
    │
    ▼
SOCKS5 Gateway (client)
    │ SOCKS5 握手 + CONNECT 解析
    │ targetAddr = "localhost:8080"
    ▼
EstablishConnection (gRPC)
    │ protocol="http", targetAddr="localhost:8080"
    ▼
ProxyStream (server/grpc)
    │ ParseProxyRequest → Method="GET", Path="/api/test"
    │ RouterV2.Classify → RiskLevel
    │ DecisionEngine.Evaluate → Decision
    │ (如果 BLOCK → alertQueue; 否则放行)
    ▼
OutputBuffer.Put(msg)
    │ msg.RequestID = "conn-xxx-123"
    │ 选择任务数最少的队列
    ▼
Sender Worker
    │ sendHTTP → http://localhost:8080/api/test
    │ 等待后端响应
    ▼
HTTP Test Server
    │ 返回 JSON 响应
    ▼
Waiter.Complete(reqID, respData)
    │ 写入 responseCh
    ▼
ProxyStream 收到响应
    │ stream.Send(ProxyResponse{RawHttpResponse: respData.Body})
    ▼
SOCKS5 Gateway
    │ conn.Write(respData.Body)
    ▼
curl 收到响应 ✅
```



### TCP 请求链路

text

```
echo "hello" | nc -X 5 -x 127.0.0.1:1080 localhost 9090
    │
    ▼
SOCKS5 Gateway (client)
    │ SOCKS5 握手 + CONNECT 解析
    │ targetAddr = "localhost:9090"
    ▼
EstablishConnection (gRPC)
    │ protocol="tcp", targetAddr="localhost:9090"
    ▼
ProxyStream (server/grpc)
    │ 构造 ParsedRequest: Method="TCP", Path="localhost:9090"
    │ RouterV2.Classify → RiskLevel
    │ DecisionEngine.Evaluate → Decision
    │ (如果 BLOCK → alertQueue; 否则放行)
    ▼
OutputBuffer.Put(msg)
    │ msg.RequestID = "conn-xxx-456"
    ▼
Sender Worker
    │ sendTCP → Dial("tcp", "localhost:9090")
    │ conn.Write("hello\n")
    │ conn.Read() → "Pong from TCP server..."
    ▼
Waiter.Complete(reqID, respData)
    │ 写入 responseCh
    ▼
ProxyStream 收到响应
    │ stream.Send(ProxyResponse{RawHttpResponse: respData.Body})
    ▼
SOCKS5 Gateway
    │ conn.Write(respData.Body)
    ▼
nc 收到 "Pong from TCP server..." ✅
```



------

## 四、已打通的功能

| 功能                          | 状态 |
| :---------------------------- | :--- |
| SOCKS5 握手 + CONNECT         | ✅    |
| HTTP 请求转发（本地）         | ✅    |
| HTTP 请求转发（外部 httpbin） | ✅    |
| TCP 原始数据转发（本地）      | ✅    |
| TCP 原始数据转发（外部）      | ✅    |
| 设备注册 / 注销               | ✅    |
| HTTP 指纹头注入（X-Proxy-*）  | ✅    |
| TCP 连接级认证                | ✅    |
| Router V2 规则匹配            | ✅    |
| 决策引擎（基础规则）          | ✅    |
| OutputBuffer 多级队列         | ✅    |
| Sender 响应回传               | ✅    |
| Waiter 超时控制               | ✅    |
| 配置文件驱动                  | ✅    |

------

## 五、当前限制

| 限制                      | 说明                                                       |
| :------------------------ | :--------------------------------------------------------- |
| 设备注册需手动执行        | `device-tool` 工具，或管理员 API                           |
| TCP 响应读取仅一次        | `sendTCP` 目前只读取一次响应，不适合长连接（如 WebSocket） |
| HTTP 响应不返回原始状态码 | 目前仅返回 200 OK，实际应用需透传状态码                    |
| 决策引擎规则较少          | 目前仅 R10（写比例）规则生效，需逐步完善                   |
| 长连接未支持              | 如 WebSocket、SSH、数据库连接等，需额外适配                |
| Sender 响应读取阻塞       | 目前是同步读，可能影响并发性能                             |

------

## 六、后续工作（决策引擎方向）

### 6.1 Router V2 规则完善

- 增加更多 HTTP 规则（按 Method + Path 匹配）
- 增加更多 TCP 规则（按目标端口 / 目标地址匹配）
- 规则热加载（无需重启服务）

### 6.2 决策引擎增强

- 补全所有规则（R01-R10）
- 规则配置化（YAML 驱动）
- 规则优先级排序
- 规则命中统计和审计日志

### 6.3 用户画像完善

- `PortraitStore` 历史行为持久化
- 跨设备关联分析
- 用户风险评分（0.0 ~ 1.0）

### 6.4 响应透传

- HTTP 响应状态码透传（200/404/500 等）
- HTTP 响应 Header 透传
- TCP 长连接支持（多次 Read/Write）

### 6.5 性能优化

- Sender 连接池（复用 HTTP 客户端连接）
- TCP 响应异步读取
- OutputBuffer 动态队列扩容

------

## 七、快速测试命令

### 注册设备

bash

```
go run cmd/device-tool/main.go -action register
```



### 注销设备

bash

```
go run cmd/device-tool/main.go -action unregister
```



### HTTP 测试（通过代理）

bash

```
curl -v --socks5-hostname 127.0.0.1:1080 http://localhost:8080/api/test
```



### TCP 测试（通过代理）

bash

```
echo "hello" | nc -X 5 -x 127.0.0.1:1080 localhost 9090
```



------

## 八、总结

当前版本已经实现了完整的 **模式二（SOCKS5 转 gRPC）** 核心功能，HTTP 和 TCP 两种协议的数据链路完全打通，并具备了基础的设备认证、路由匹配和决策能力。后续工作将聚焦于决策引擎的完善、规则配置化、性能优化和长连接支持。

