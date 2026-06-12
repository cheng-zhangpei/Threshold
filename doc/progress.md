﻿# Threshold 安全代理 - 开发进度文档

## 项目概述

Threshold 是一个安全代理系统，由 Client（本地代理）和 Server（安全网关）两部分组成，
部署于用户终端设备（IDV 客户端）与 OpenStack 云平台之间，作为透明中间层提供设备指纹校验、
用户行为评估和访问控制决策。

### 核心能力

- 设备指纹六层 Hash 树匹配（白名单机制）
- L0-L3 静态风险分级
- 声明式决策引擎（10 条规则 + 兜底）
- 连接粒度用户画像
- mTLS 加密通道
- WAL 预写日志保证持久化一致性

### 技术选型

| 组件 | 选型 | 说明 |
|------|------|------|
| 语言 | Go 1.25 | 主力开发语言 |
| 通信协议 | gRPC + Protobuf | 跨语言、流式传输 |
| 持久化存储 | bbolt | 嵌入式 KV，接口可替换 |
| 加密通道 | mTLS (crypto/tls) | 原型单向 TLS，生产双向 |
| 并发模型 | goroutine + channel | Go 原生协程 |
| 配置管理 | YAML (gopkg.in/yaml.v3) | 文件配置 |
| 测试 | go test | 标准测试框架 |

---

## Day 1：基础骨架 + Proto 定义 + gRPC 骨架

### 目标

项目能 go build，proto 能生成代码，公共类型就位，gRPC server 能启动。

### 目录结构

    Threshold/
    +-- cmd/
    |   +-- client/main.go          # 客户端入口
    |   +-- server/main.go          # 服务端入口
    +-- pkg/
    |   +-- proto/                  # Proto 定义
    |   |   +-- proxy.proto         # 核心服务定义
    |   |   +-- pull.proto          # 拉取接口
    |   |   +-- notify.proto        # 通知接口
    |   |   +-- pb/                 # 生成的 Go 代码
    |   +-- types/types.go          # 公共类型
    |   +-- config/config.go        # 配置结构 + 加载
    +-- client/                     # 客户端业务包（后续 Day 7）
    +-- server/
    |   +-- grpc/                   # gRPC 接入层
    |   +-- fingerprint/            # 指纹匹配引擎
    |   +-- portrait/               # 用户画像存储
    |   +-- decision/               # 决策引擎
    |   +-- router/                 # Router（待实现）
    |   +-- dispatch/               # DispatchManager（待实现）
    |   +-- output/                 # OutputBuffer（待实现）
    |   +-- alert/                  # AlertQueue（待实现）
    |   +-- crossdevice/            # 跨设备关联接口（待实现）
    +-- config/
    |   +-- server.yaml
    |   +-- client.yaml
    +-- doc/
    +-- go.mod
    +-- go.sum

### 完成文件清单

| 文件 | 说明 |
|------|------|
| pkg/proto/proxy.proto | SecurityProxy 服务定义（5 个 RPC） |
| pkg/proto/pull.proto | PullRequest/ApprovedMessage 消息定义 |
| pkg/proto/notify.proto | NotifyRequest/NotifyEvent/EventType 定义 |
| pkg/proto/pb/*.go | protoc 生成的 4 个 Go 文件 |
| pkg/types/types.go | 全部核心类型 + ParseProxyRequest |
| pkg/types/types_test.go | ParseProxyRequest 3 个测试 |
| pkg/config/config.go | ServerConfig/ClientConfig + YAML 加载 + 默认配置 |
| config/server.yaml | 服务端默认配置 |
| config/client.yaml | 客户端默认配置 |
| cmd/server/main.go | 服务端入口（完整初始化流水线） |
| cmd/client/main.go | 客户端入口骨架 |

### gRPC 服务接口设计

    service SecurityProxy {
        // 客户端代理发送请求的双向流
        rpc ProxyStream(stream ProxyRequest) returns (stream ProxyResponse);
    
        // 连接生命周期管理
        rpc EstablishConnection(ConnectionInit) returns (ConnectionAck);
        rpc CloseConnection(ConnectionClose) returns (CloseAck);
    
        // 下游拉取接口（OpenStack 侧调用）
        rpc PullApproved(stream PullRequest) returns (stream ApprovedMessage);
    
        // 通知接口（安全代理主动推送）
        rpc SubscribeNotify(NotifyRequest) returns (stream NotifyEvent);
    }

### ParsedRequest 解析逻辑

ParseProxyRequest 将 proto ProxyRequest 转换为业务层 ParsedRequest：
- 用 bufio.Scanner 解析 raw_http_request 为 HTTP method/path/headers/body
- 从 X-Proxy-* headers 提取六维设备指纹
- 拼接 OpKey（如 "GET /api/cloud/public/images"）供 Router 使用

### gRPC Server 骨架

- server/grpc/server.go：gRPC 启动 + TLS 配置
- server/grpc/handler.go：5 个 RPC 方法协议层骨架 + 连接管理 + 订阅广播
- server/grpc/interceptor.go：限流拦截器（预留）
- server/grpc/ratelimit.go：TokenBucket 令牌桶（预留）

### 设计决策

- Proto 拆分为 3 个文件（proxy/pull/notify），跨文件 import
- 每个 RPC 方法都有详细注释说明调用时序和职责
- TLS 配置预留 mTLS 升级路径
- ParseProxyRequest 独立于 proto，业务层不依赖 proto 定义

---

## Day 2：存储层 + 指纹匹配引擎

### 目标

六层 Hash 树能匹配，bbolt 能读写用户画像，WAL 保证持久化一致性。

### 存储接口设计 (pkg/storage/store.go)

    type Store interface {
        Update(fn func(tx Tx) error) error  // 可写事务
        View(fn func(tx Tx) error) error    // 只读事务
        Close() error
    }
    
    type Tx interface {
        Get(bucket string, key []byte) ([]byte, error)
        Put(bucket string, key, value []byte) error
        Delete(bucket string, key []byte) error
        Exist(bucket string, key []byte) (bool, error)
        PrefixScan(bucket string, prefix []byte) ([][]byte, [][]byte, error)
        ForEach(bucket string, fn func(k, v []byte) error) error
        Commit() error
        Rollback() error
    }

预定义 bucket：fingerprints / portraits / blacklist / wal / seq

设计要点：
- 所有操作必须通过事务接口，保证原子性
- 后续分布式扩展时可对接分布式事务（2PC/Saga），上层逻辑不变
- bbolt bucket 类似 Column Family，按业务域隔离

### bbolt 实现 (pkg/storage/bolt_store.go)

- 使用 go.etcd.io/bbolt 实现 Store 接口
- Update 事务：writable=false, closed=false
- View 事务：readOnly=true，不允许写操作
- key/value 拷贝：bbolt 返回的 value 在事务结束前有效，需拷贝
- 自动创建所有预定义 bucket

### WAL 预写日志 (pkg/storage/wal.go)

核心流程：

    Begin(connID, op, bucket, key, value)
        -> 写 PENDING 日志到 wal bucket
        -> 返回 sequence number
    
    Commit(connID, seq, op, bucket, key, value)
        -> 执行实际数据写入/删除
        -> 标记 WAL 条目为 COMMITTED
        -> 清理已提交的 WAL 条目
    
    Recover()
        -> 扫描所有 PENDING 状态的 WAL 条目
        -> 逐条重放
        -> 标记为 COMMITTED 并清理

WAL 键格式：{connection_id}:{sequence_number:big_endian_uint64}
- 按 connection_id 前缀扫描可取出某个连接的所有 WAL 记录
- big_endian 保证字典序等于数字序

关键设计决策：
- cleanupCommitted 先收集待删除 key 再统一删除，避免 ForEach 中修改 bucket
- Recover 先 View 收集 PENDING 记录，再 Update 事务重放（两阶段）
- WALEntry.Value 不用 omitempty，避免空值序列化问题

### 指纹匹配引擎 (server/fingerprint/)

#### 树结构设计

    Root (map)
      |-- "linux" --> Node                    Level 0: OS
      |                |-- "10.0.0.1" --> Node  Level 1: IP
      |                |     +-- device-A [LEAF]
      |                +-- "10.0.0.2" --> Node
      |                      +-- device-B [LEAF]
      |-- "windows" --> ...
      +-- "null" --> 跳过 OS 维度

层级顺序：OS -> IP -> Port -> Protocol -> UUID -> Reserved

设计要点：
- 窄顶宽底：顶层 OS 种类少（linux/windows/macos），底层 UUID 唯一
- 每层节点是 map[string]*Node，key 为维度值
- null 键表示维度可缺省，匹配时跳过
- 叶节点出现在最后一个非 nil 维度处（不是固定在最底层）
- 注册时创建路径 + 标记叶节点
- 匹配时逐层查 map，null 跳过，命中叶节点即通过
- 注销时取消叶标记 + 自底向上清理空节点

#### 持久化策略

- 所有写操作通过 WAL 保证一致性
- 启动时：WAL.Recover() -> loadFromStore() 从 bbolt 重建内存树
- Register/Unregister：先更新内存树，再通过 WAL 写入 bbolt
- FingerprintRecord 存储六维指纹的 JSON 序列化
- recordKey 以 UUID 为主键（无 UUID 时用全维度拼接）

#### 可视化调试

Print() 方法输出树结构：
    FingerprintTree:
    +-- linux
        +-- 10.0.0.1
            +-- null
                +-- null
                    +-- device-print [LEAF]


### Day 2 测试用例

| 模块 | 测试数 | 用例 |
|------|--------|------|
| pkg/storage | 5 | BeginCommit/SequenceIncrement/Delete/Recover/MultipleOps |
| server/fingerprint | 9 | EmptyTree/SimpleRegister/NullDimensionSkip/PartialRegistration/LeafAtFirstLevel/Unregister/MultipleDevices/Persistence/Print |

### Handler 集成

- EstablishConnection：设备白名单校验，未注册设备拒绝建立连接
- ProxyStream：请求级指纹二次校验，不匹配返回 BLOCKED
- main.go 初始化流水线：bbolt -> WAL Recover -> FingerprintTree -> gRPC Server


---

## Day 3：决策引擎

### 目标

规则引擎能根据上下文输出决策结果，已集成到 handler 流水线。

### 引擎架构 (server/decision/engine.go)

    type Engine struct {
        rules []Rule
        store *portrait.Store
    }
    
    func (e *Engine) Evaluate(ctx, history, riskLevel) *Decision:
        for each rule:
            if rule.Condition(ctx, history, riskLevel, store):
                if rule.ID == R99:
                    return staticRiskDecision(riskLevel)
                return Decision{Action: rule.Action, ...}
        return Decision{Action: ALLOW, RuleID: "none"}

设计要点：
- 命中第一条规则即停（而非匹配所有取最严格）
- R99 兜底：按静态风险等级分派 ALLOW/AUDIT/ALERT
- 规则函数签名统一：RuleFunc = func(ctx, history, riskLevel, portraitStore) bool
- 规则之间存在逻辑递进：设备级 -> 历史连接级 -> 当前连接级

### 规则列表 (server/decision/rules.go)

| ID | 层级 | 描述 | 条件 | 动作 |
|------|------|------|------|------|
| R01 | 设备级 | 设备已被拉黑 | portraitStore.IsBlacklisted() | BLACKLIST_DEVICE |
| R02 | 历史级 | 最近 3 次连接都触发告警 | history[-3:] 全有 flags | BLACKLIST_DEVICE |
| R03 | 历史级 | 最近 5 次连接累计删除 > 10 | 历史 + 当前删除计数 | BLACKLIST_DEVICE |
| R04 | 历史级 | 历史上被拉黑过 | history 中有 BLACKLIST_DEVICE flag | REQUIRE_2FA |
| R05 | 历史级 | 最近 5 次连接来自 3+ 不同 IP | 去重 IP 数 > 3 | REQUIRE_2FA |
| R06 | 连接级 | 暴力登录失败 > 5 次 | login_failed 事件计数 | BLOCK_LOGIN |
| R07 | 连接级 | 批量删除 > 3 次 | delete 事件计数 | BLOCK_DEVICE |
| R08 | 连接级 | 上传后立即启动 VM | image.upload 后有 vm.start | QUARANTINE_AND_ALERT |
| R09 | 连接级 | 非工作时间写操作 | 0:00-6:00 写操作 | ALERT |
| R10 | 连接级 | 写入比例 > 80% | ctx.WriteRatio() > 0.8 | ALERT |
| R99 | 兜底 | 按静态风险等级 | always true | 按 L0/L1/L2 分派 |

### 静态风险等级分派 (R99)

    L0 (只读查询) -> ALLOW
    L1 (写操作)   -> AUDIT
    L2 (高风险)   -> ALERT
    L3 (极高风险) -> (理论上 R01-R10 已覆盖，不会到 R99)

### 辅助模块

- read_ops.go：READ_OPS 只读操作集合（12 个 GET 端点）
- isOffHours()：判断时间是否在 0:00-6:00
- isReadOp()：通过 HTTP 方法前缀判断读写（types 包内）

### PortraitStore 最小实现 (server/portrait/store.go)

- IsBlacklisted：查询 bbolt blacklist bucket
- GetHistory / AppendSummary：空实现（接口就位，后续填充）
- BlacklistDevice：写入 bbolt blacklist bucket
- OnConnectionClose：空实现（后续对接 WAL 持久化）

### Handler 集成 (server/grpc/handler.go)

ProxyStream 完整流水线：

    1. ParseProxyRequest -> ParsedRequest
    2. FingerprintTree.Match -> 不匹配则 BLOCKED
    3. RecordEvent -> 追加事件到 ConnectionContext
    4. Engine.Evaluate -> 决策结果
    5. 映射到 ProxyResponse status:
       BLOCK/BLOCK_DEVICE/BLACKLIST_DEVICE -> BLOCKED
       REQUIRE_2FA/BLOCK_LOGIN -> RATE_LIMITED
       其他 -> OK

初始化流水线 (cmd/server/main.go)：

    bbolt 打开
    -> WAL.Recover()（崩溃恢复）
    -> FingerprintTree.NewTree()（加载到内存）
    -> portrait.NewStore()
    -> decision.NewEngine()
    -> grpc.New(cfg, fpTree, engine)
    -> grpcServer.Start()

### Day 3 测试用例

| 测试 | 验证 |
|------|------|
| TestEvaluate_R06_BruteForceLogin | 6 次 login_failed -> BLOCK_LOGIN |
| TestEvaluate_R07_BulkDelete | 4 次 image.delete -> BLOCK_DEVICE |
| TestEvaluate_R08_UploadThenStart | upload 后 start -> QUARANTINE_AND_ALERT |
| TestEvaluate_StaticRisk_L1 | L1 无规则命中 -> AUDIT |
| TestEvaluate_StaticRisk_L2 | L2 无规则命中 -> ALERT |
| TestEvaluate_StaticRisk_L0 | L0 无规则命中 -> ALLOW |
| TestEvaluate_NormalGet_Allow | 普通 GET -> ALLOW |


---

## 当前数据流（完整）

    Client 发送 ProxyRequest
        |
        v
    EstablishConnection:
        1. 校验 user_id / device_uuid 非空
        2. FingerprintTree.Match 设备白名单
           -> 不匹配：拒绝建立连接
        3. 创建 ConnectionContext 存入内存
        4. 返回 connection_id
    
    ProxyStream:
        1. ParseProxyRequest -> ParsedRequest
           (解析 raw_http_request + 提取指纹 + 拼接 OpKey)
        2. FingerprintTree.Match 请求级指纹校验
           -> 不匹配：返回 BLOCKED
        3. RecordEvent -> 追加事件到 ConnectionContext
        4. Engine.Evaluate(ctx, history, riskLevel)
           -> 遍历 DECISION_RULES，命中第一条即停
           -> R99 兜底按风险等级分派
        5. 映射 Decision.Action 到 ProxyResponse.Status
        6. 返回 ProxyResponse 给客户端
    
    CloseConnection:
        1. 释放 ConnectionContext
        2. TODO: WAL 持久化 -> PortraitStore
        3. TODO: 通知下游 Subscribers

---

## 测试覆盖汇总

| 模块 | 测试数 | 状态 | 说明 |
|------|--------|------|------|
| pkg/types | 3 | PASS | ParseProxyRequest 解析逻辑 |
| pkg/storage | 5 | PASS | WAL 事务/崩溃恢复 |
| server/fingerprint | 9 | PASS | 指纹树匹配/注册/注销/持久化 |
| server/decision | 7 | PASS | 决策引擎规则匹配 |
| **总计** | **24** | **ALL PASS** | |

---

## 项目当前文件统计

| 目录 | .go 文件数 | 测试文件 |
|------|-----------|----------|
| pkg/proto + pb | 4 (proto) + 4 (gen) | 0 |
| pkg/types | 1 | 1 |
| pkg/config | 1 | 0 |
| pkg/storage | 3 | 1 |
| server/fingerprint | 2 | 1 |
| server/portrait | 1 | 0 |
| server/decision | 3 | 1 |
| server/grpc | 3 | 0 |
| cmd/server | 1 | 0 |
| cmd/client | 1 | 0 |
| **总计** | **24** | **4** |

---

## 待完成（Day 4-8）

| Day | 内容 | 预计产出 |
|-----|------|----------|
| 4 | OutputBuffer + AlertQueue + Router | 消息缓冲/告警队列/风险分级映射表 |
| 5 | DispatchManager + WorkerPool | 弹性伸缩/竞争消费/Worker 处理流水线 |
| 6 | gRPC 接入层完善 + 跨设备接口 | 限流拦截器/跨设备关联接口定义 |
| 7 | Client 端实现 | 重定向模块/行为采集/本地代理 |
| 8 | 端到端集成 + 配置加载 | 完整 main.go/配置驱动/端到端测试 |

### 后续完善项

- 规则 YAML 配置化（目前硬编码）
- BLOCK_LOGIN 定时自动解除
- QUARANTINE_AND_ALERT 对接 CICD 扫描
- REQUIRE_2FA 二次认证挂起/恢复流程
- PortraitStore 历史画像加载/追加（目前空实现）
- ConnectionContext 关闭时通过 WAL 持久化到 PortraitStore
- CloseConnection 通知下游 Subscribers
