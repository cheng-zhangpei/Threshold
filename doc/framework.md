﻿# Threshold 安全代理 - Go 项目框架结构

## 1. 项目概述

Threshold 是一个安全代理系统，由 **Client（本地代理）** 和 **Server（安全网关）** 两部分组成，部署于用户终端设备与 OpenStack 云平台之间。

### 核心能力

| 能力 | 所属端 | 说明 |
|------|--------|------|
| 流量重定向 | Client | OS 网络栈层面将流量导向本地代理 |
| 设备指纹附加 | Client | 六维指纹（UUID/OS/IP/Port/Protocol/Reserved） |
| 行为事件采集 | Client | 记录操作事件，生成 OpTag |
| gRPC 加密传输 | Client↔Server | mTLS 双向认证通道 |
| 令牌桶限流 | Server | 全局流量闸门 |
| L0-L3 静态风险分级 | Server | 按操作类型判定风险等级 |
| 六层Hash树指纹匹配 | Server | 校验设备合法性 |
| 弹性伸缩 WorkerPool | Server | 按需调整并发处理能力 |
| 连接粒度用户画像 | Server | 行为历史记录 + 跨连接关联 |
| 声明式决策引擎 | Server | DECISION_RULES 命中即停匹配 |
| OutputBuffer | Server | 通过校验的消息暂存 + 通知下游拉取 |
| AlertQueue | Server | 告警暂存 + 设备拉黑 |
| 跨设备关联画像接口 | Server | 仅定义接口，算法后续迭代 |

### 不在本项目范围

| 项目 | 归属 | 说明 |
|------|------|------|
| 消息队列防打爆 | 基础设施层 | Router 前挂消息队列，运维配置 |
| 可观测性 | 运维 | Prometheus + Grafana，部署阶段配 |
| 分布式数据库替换 | 存储层 | PortraitStore 接口抽象，换后端实现即可 |
| 灰度发布 | 运维 | K8S 滚动部署，应用本身无状态 |
| 日志审计 | 后续迭代 | 上线后补 |
| 镜像沙箱扫描/修复 | CICD 模块 | 独立服务，安全代理只负责触发扫描通知 |
| 跨设备关联的具体算法 | 后续迭代 | 接口定义好，初期走简单规则 |

---

## 2. 目录结构

```
Threshold/
├── cmd/
│   ├── client/
│   │   └── main.go                     # 客户端入口：启动重定向、行为采集、本地代理
│   └── server/
│       └── main.go                     # 服务端入口：初始化所有组件，启动 gRPC server
│
├── pkg/                                # 公共包（Client/Server 共享）
│   ├── proto/                          # Protocol Buffers 定义 + 生成代码
│   │   ├── proxy.proto                 # SecurityProxy 服务、ProxyRequest/ProxyResponse
│   │   ├── connection.proto            # ConnectionInit/ConnectionAck/ConnectionClose/CloseAck
r
│   │   ├── notify.proto                # NotifyRequest/NotifyEvent
│   │   ├── pull.proto                  # PullRequest/ApprovedMessage
│   │   └── pb/                         # protoc 生成的 Go 代码
│   ├── types/                          # 公共类型定义
│   │   └── types.go                    # RiskLevel, Action, Decision, ConnectionSummary 等
r
│   └── config/                         # 公共配置结构
│       └── config.go                   # Config struct 定义 + 加载逻辑
│
├── client/                             # 客户端业务包
│   ├── redirect/                       # 重定向模块
│   │   ├── redirect.go                 # OS 网络栈流量重定向逻辑
│   │   └── redirect_test.go            # 单元测试
│   ├── collector/                      # 行为采集进程
│   │   ├── collector.go                # 事件记录、OpTag 生成
│   │   └── collector_test.go           # 单元测试
│   └── proxy/                          # 本地代理服务
│       ├── proxy.go                    # 请求截获、X-Proxy-* 字段附加、响应回传
│       └── proxy_test.go               # 单元测试
│
├── server/                             # 服务端业务包
│   ├── grpc/                           # gRPC 接入层
│   │   ├── server.go                   # gRPC server 启动配置（TLS/mTLS）
│   │   ├── handler.go                  # ProxyStream/EstablishConnection/CloseConnection 等 RPC 实现
│   │   ├── interceptor.go              # 限流拦截器、日志拦截器
r
│   │   ├── ratelimit.go                # TokenBucketLimiter 令牌桶限流
│   │   └── grpc_test.go               # 集成测试
│   ├── router/                         # Router 风险分级
│   │   ├── router.go                   # Router 核心逻辑：提取 op_key，查映射表，L0 穿透 / L1+ 入队
│   │   ├── operation_risk.go           # OperationRiskTable：静态映射表 + 通配符正则匹配

│   │   ├── risk_level.go               # L0/L1/L2/L3 常量定义
│   │   └── router_test.go             # 单元测试
│   ├── dispatch/                       # DispatchManager + WorkerPool
│   │   ├── manager.go                  # DispatchManager：入队、弹性伸缩
│   │   ├── worker.go                   # Worker：竞争消费、指纹匹配、画像加载、决策引擎
│   │   ├── policy.go                   # PoolPolicy 配置
│   │   └── dispatch_test.go           # 单元测试
│   ├── fingerprint/                    # 六层Hash树指纹匹配引擎
│   │   ├── tree.go                     # FingerprintTree：六层匹配逻辑
│   │   ├── backend.go                  # FingerprintBackend 接口
│   │   ├── backend_bolt.go             # bbolt 后端实现
│   │   └── fingerprint_test.go        # 单元测试
│   ├── portrait/                       # 用户画像与持久化
│   │   ├── store.go                    # PortraitStore：加载历史画像、序列化、拉黑
│   │   ├── context.go                  # ConnectionContext：连接内实时事件记录
│   │   ├── summary.go                  # ConnectionSummary：连接摘要数据结构
│   │   ├── backend.go                  # PortraitBackend 接口
│   │   ├── backend_bolt.go             # bbolt 后端实现
│   │   └── portrait_test.go           # 单元测试
│   ├── decision/                       # 决策引擎
│   │   ├── engine.go                   # evaluate_rules：遍历 DECISION_RULES，命中第一条即停
│   │   ├── rules.go                    # DECISION_RULES 定义（R01-R12）
│   │   ├── actions.go                  # Decision / Action 常量定义
│   │   ├── read_ops.go                 # READ_OPS 只读操作集合
│   │   └── decision_test.go           # 单元测试
│   ├── output/                         # OutputBuffer
│   │   ├── buffer.go                   # OutputBuffer：队列 + 订阅者通知 + 批量拉取
│   │   └── output_test.go            # 单元测试
│   ├── alert/                          # AlertQueue
│   │   ├── queue.go                    # AlertQueue：告警队列 + 推送
│   │   └── alert_test.go             # 单元测试
│   └── crossdevice/                    # 跨设备关联画像接口
│       └── correlator.go              # CrossDeviceCorrelator 接口定义（仅接口）
│
├── doc/
│   ├── arch2.md                        # 原始架构文档
│   └── framework.md                    # 本文档：项目框架结构
│
├── go.mod
└── go.sum
```

---

## 3. Client 与 Server 交互流程

```
┌─────────────────────────────────────┐
│         Client (用户终端)              │
│                                      │
│  ┌──────────┐  ┌──────────────────┐ │
│  │ Redirect │  │ Collector        │ │
│  │ 流量重定向 │  │ 行为事件采集     │ │
│  └────┬─────┘  └────────┬─────────┘ │
│       │                 │            │
│       └────────┬────────┘            │
│                ▼                     │
│       ┌────────────────┐             │
│       │ LocalProxy     │             │
│       │ 附加指纹字段    │             │
│       │ gRPC mTLS 加密  │             │
│       └───────┬────────┘             │
└───────────────┼──────────────────────┘
                │ gRPC Stream (mTLS)
                ▼
┌──────────────────────────────────────┐
│         Server (安全网关)              │
│                                       │
│  gRPC Layer → Router → DispatchManager│
│                          ↓            │
│                     WorkerPool        │
│                    ↙       ↘         │
│            指纹匹配    	 决策引擎      │
│                    ↘       ↙         │
│               OutputBuffer/AlertQueue │
│                    ↓            ↓    │
│              gRPC Notify    gRPC Alert│
└──────────────────────────────────────┘
                │            │
                ▼            ▼
┌──────────┐  ┌──────────────────────┐
│OpenStack │  │ 管理员监控端          │
└──────────┘  └──────────────────────┘
```

---

## 4. 模块职责与依赖关系

### 4.1 Client 端依赖

```
redirect/ → OS 网络栈 API
collector/ → 独立进程，IPC 与 proxy 通信
proxy/ → redirect/ + collector/ + pkg/proto/
```

### 4.2 Server 端依赖

```
grpc/ → router/ → dispatch/ → (fingerprint/, portrait/, decision/)
dispatch/ → output/, alert/
portrait/ → bbolt (持久化)
fingerprint/ → bbolt (持久化)
decision/ → portrait/ (读取历史画像)

所有包共享 pkg/proto/ 和 pkg/types/
```

### 4.3 全局依赖图

```
                    pkg/proto/ + pkg/types/ + pkg/config/
                         ▲              ▲
                        /              \
                       /                \
              client/*                server/*
                                          │
                                          │
        ┌─────────────────────────────────┤
        │                                 │
   server/grpc/                     server/router/
        │                                 │
        │                          server/dispatch/
        │                       ╱       │       ╲
        │              fingerprint/  portrait/  decision/
        │                  │            │           │
        │              bbolt          bbolt      portrait/
        │                                              
        └──→ server/output/   server/alert/            
```

---

## 5. 关键接口设计

### 5.1 gRPC 服务接口（proto）

```protobuf
service SecurityProxy {
    // 客户端代理发送请求的双向流
    rpc ProxyStream(stream ProxyRequest) returns (stream ProxyResponse);

    // 连接生命周期管理
    rpc EstablishConnection(ConnectionInit) returns (ConnectionAck);
    rpc CloseConnection(ConnectionClose) returns (CloseAck);

    // 下游拉取接口（OpenStack侧调用）
    rpc PullApproved(stream PullRequest) returns (stream ApprovedMessage);

    // 通知接口（安全代理主动推送）
    rpc SubscribeNotify(NotifyRequest) returns (stream NotifyEvent);
}
```

### 5.2 Client 端核心接口

```go
// 重定向模块
type Redirector interface {
    Start(localPort int) error
    Stop() error
}

// 行为采集器
type EventCollector interface {
    RecordEvent(opType string)
    GenerateOpTag() *OpTag
    Flush() []EventRecord
}

// 本地代理
type LocalProxy interface {
    Start(listenAddr string) error
    Stop() error
    // 拦截请求，附加指纹，通过 gRPC 转发
}
```

### 5.3 Server 端核心接口

```go
// 指纹匹配
type FingerprintTree interface {
    Match(fingerprint map[string]*string) bool
}

type FingerprintBackend interface {
    GetNode(level int, hash string) ([]byte, error)
    SetNode(level int, hash string, value []byte) error
}

// 用户画像存储
type PortraitBackend interface {
    GetSummaries(userID string, limit int) ([]*ConnectionSummary, error)
    AppendSummary(userID string, summary *ConnectionSummary) error
    IsBlacklisted(deviceUUID string) (bool, error)
    BlacklistDevice(deviceUUID string, reason string) error
}

// 决策引擎
type DecisionEngine interface {
    Evaluate(ctx *ConnectionContext, history []*ConnectionSummary,
        riskLevel RiskLevel, portraitStore PortraitStore) *Decision
}

// 跨设备关联（仅接口）
type CrossDeviceCorrelator interface {
    Correlate(userID string, currentDevice string,
        summaries []*ConnectionSummary) (*CorrelationResult, error)
}
```

---

## 6. 核心数据结构

```go
// ========= pkg/types/types.go =========

// 风险等级
type RiskLevel int

const (
    L0 RiskLevel = iota // 只读查询，直接穿透
    L1                   // 写操作，审计放行
    L2                   // 高风险操作，告警放行
    L3                   // 极高风险，阻断+拉黑
)

// 决策动作
type Action int

const (
    ALLOW               Action = iota // 放行
    AUDIT                            // 审计放行
    ALERT                            // 告警放行
    THROTTLE                         // 限速
    BLOCK                            // 阻断
    BLOCK_DEVICE                     // 设备阻断
    BLOCK_LOGIN                      // 登录阻断
    BLOCK_WRITE_OPS                  // 写操作阻断
    REQUIRE_2FA                      // 二次认证
    QUARANTINE_AND_ALERT             // 隔离告警
    BLACKLIST_DEVICE                 // 拉黑设备
)

// 决策结果
type Decision struct {
    Action Action
    Reason string
    RuleID string
}

// 设备指纹六维度
type DeviceFingerprint struct {
    UUID     *string // 设备唯一标识
    OS       *string // 操作系统类型
    IP       *string // 客户端 IP
    Port     *string // 源端口
    Protocol *string // 协议类型
    Reserved *string // 保留字段
}

// 事件记录
type EventRecord struct {
    OpType    string

    Timestamp time.Time
}

// 连接上下文（内存中维护）
type ConnectionContext struct {
    ConnectionID   string
    UserID         string
    DeviceUUID     string
    ConnectedAt    time.Time
    IP             string
    Events         []EventRecord
    TriggeredFlags []string
}

// 连接摘要（持久化）
type ConnectionSummary struct {
    ConnectionID   string
    UserID         string
    DeviceUUID     string
    ConnectedAt    time.Time
    EndedAt        time.Time
    DurationSec    float64
    IP             string
    EventCounts    map[string]int
    FlagsTriggered []string
    OffHoursWrites int
    TotalEvents    int
    WriteRatio     float64
}

// Worker 弹性伸缩策略
type PoolPolicy struct {
    MinWorkers             int
    MaxWorkers             int
    ScaleUpThreshold       int
    ScaleUpStep            int
    MaxQueueSize           int
    IdleTimeoutSec         int
    HealthCheckIntervalSec int
}
```

---

## 7. 八天开发计划

> 以下按工作日排列，每天目标明确、可交付可验收。不要求连续，根据实际情况灵活调整。

### Day 1 - 基础骨架 + Proto 定义

**目标**：项目能 `go build`，proto 能生成代码，公共类型就位。

| 任务 | 产出文件 |
|------|----------|
| 清理 main.go，搭建目录骨架 | 全目录空文件占位 |
| 编写 `proxy.proto` / `connection.proto` / `notify.proto` / `pull.proto` | `pkg/proto/*.proto` |
| protoc 生成 Go 代码 | `pkg/proto/pb/*.go` |
| 编写公共类型 `types.go`（RiskLevel, Action, Decision, Fingerprint, ConnectionContext, ConnectionSummary, PoolPolicy） | `pkg/types/types.go` |
| 编写公共配置结构 `config.go` | `pkg/config/config.go` |
| 编写 `cmd/server/main.go` 和 `cmd/client/main.go` 骨架（仅启动空 server） | `cmd/*/main.go` |
| **验收**：`go build ./...` 通过 |

---

### Day 2 - 指纹匹配引擎 + 画像存储

**目标**：六层 Hash 树能匹配，bbolt 能读写用户画像。

| 任务 | 产出文件 |
|------|----------|
| 指纹匹配引擎 `tree.go` + `backend.go` 接口 | `server/fingerprint/tree.go`, `backend.go` |
| bbolt 后端实现 `backend_bolt.go` | `server/fingerprint/backend_bolt.go` |
| 指纹匹配单元测试 | `server/fingerprint/fingerprint_test.go` |
| 用户画像 `context.go` + `summary.go` + `store.go` | `server/portrait/` |
| PortraitBackend 接口 + bbolt 实现 | `server/portrait/backend.go`, `backend_bolt.go` |
| 画像单元测试 | `server/portrait/portrait_test.go` |
| **验收**：`go test ./server/fingerprint/ ./server/portrait/` 通过 |

---

### Day 3 - 决策引擎

**目标**：规则引擎能根据上下文输出决策结果。

| 任务 | 产出文件 |
|------|----------|
| 决策引擎 `engine.go`：遍历规则、命中即停 | `server/decision/engine.go` |
| 规则定义 `rules.go`（R01-R12，含兜底 R99） | `server/decision/rules.go` |
| Action/Decision 常量 + READ_OPS | `server/decision/actions.go`, `read_ops.go` |
| 决策引擎单元测试（覆盖各条规则的命中场景） | `server/decision/decision_test.go` |
| **验收**：`go test ./server/decision/` 通过 |

---

### Day 4 - OutputBuffer + AlertQueue + Router

**目标**：消息缓冲和告警队列就绪，Router 能分级路由。

| 任务 | 产出文件 |
|------|----------|
| OutputBuffer `buffer.go`：队列 + 订阅者 + 批量拉取 | `server/output/buffer.go` |
| AlertQueue `queue.go`：告警队列 + 推送 | `server/alert/queue.go` |
| output/alert 单元测试 | `server/output/output_test.go`, `server/alert/alert_test.go` |
| Router `router.go` + `operation_risk.go` + `risk_level.go` | `server/router/` |
| OPERATION_RISK 静态映射表（含通配符） | `server/router/operation_risk.go` |
| Router 单元测试 | `server/router/router_test.go` |
| **验收**：`go test ./server/output/ ./server/alert/ ./server/router/` 通过 |

---

### Day 5 - DispatchManager + WorkerPool

**目标**：Worker 竞争消费，弹性伸缩工作正常。

| 任务 | 产出文件 |
|------|----------|
| PoolPolicy `policy.go` | `server/dispatch/policy.go` |
| DispatchManager `manager.go`：入队 + 弹性伸缩 + monitor_loop | `server/dispatch/manager.go` |
| Worker `worker.go`：竞争消费 + 指纹匹配 + 画像加载 + 决策引擎调用 | `server/dispatch/worker.go` |
| dispatch 单元测试（模拟入队、Worker 消费、伸缩触发） | `server/dispatch/dispatch_test.go` |
| **验收**：`go test ./server/dispatch/` 通过 |

---

### Day 6 - gRPC 接入层 + 跨设备接口

**目标**：gRPC server 能启动，拦截器链就绪，客户端能连上。

| 任务 | 产出文件 |
|------|----------|
| gRPC server 启动 `server.go`（TLS 配置） | `server/grpc/server.go` |
| RPC handler 实现 `handler.go` | `server/grpc/handler.go` |
| 令牌桶限流 `ratelimit.go` + 拦截器 `interceptor.go` | `server/grpc/` |
| gRPC 集成测试（启动 server，client 连接，发送请求） | `server/grpc/grpc_test.go` |
| 跨设备关联接口 `correlator.go`（仅接口定义） | `server/crossdevice/correlator.go` |
| **验收**：`go test ./server/grpc/` 通过，gRPC server 可启动 |

---

### Day 7 - Client 端实现

**目标**：客户端能重定向流量、采集事件、通过 gRPC 转发请求。

| 任务 | 产出文件 |
|------|----------|
| 重定向模块 `redirect.go` | `client/redirect/redirect.go` |
| 行为采集器 `collector.go` | `client/collector/collector.go` |
| 本地代理 `proxy.go`：请求截获 + 指纹附加 + gRPC 转发 | `client/proxy/proxy.go` |
| Client 单元测试 | `client/*/`_test.go |
| **验收**：`go test ./client/...` 通过 |

---

### Day 8 - 端到端集成 + 配置加载

**目标**：Client 和 Server 能跑通完整链路，配置文件驱动。

| 任务 | 产出文件 |
|------|----------|
| `cmd/server/main.go` 完整初始化：bbolt + gRPC + Router + Dispatch + Worker | `cmd/server/main.go` |
| `cmd/client/main.go` 完整初始化：重定向 + 采集 + 本地代理 + gRPC 连接 | `cmd/client/main.go` |
| YAML 配置文件 + 配置加载 | `config/config.yaml`, `pkg/config/config.go` |
| 端到端测试（client 发请求 → server 处理 → 返回决策） | `e2e_test.go` (或 `cmd/` 下集成测试) |
| 整理 doc/ 留痕文档 | `doc/framework.md` 更新 |
| **验收**：`go build ./...` + `go test ./...` 全部通过 |

---

## 8. 技术选型

| 组件 | 选型 | 说明 |
|------|------|------|
| 通信协议 | gRPC + Protobuf | 跨语言、版本管理、流式传输 |
| 持久化存储 | bbolt | 初期嵌入式 KV，接口抽象后可替换 |
| 加密通道 | mTLS (crypto/tls) | 原型单向 TLS，生产双向 |
| 并发模型 | goroutine + channel | Go 原生协程 |
| 配置管理 | YAML (gopkg.in/yaml.v3) | 初期文件配置，后续可接配置中心 |
| 令牌桶限流 | golang.org/x/time/rate | 标准库限流器 |
| 测试 | go test + testify | 标准测试框架 |
