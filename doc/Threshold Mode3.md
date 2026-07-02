# Threshold Mode 3 — 生产化就绪文档

---

## 一、架构总览

```
libthreshold.so (客户端 C 共享库)
    │  LD_PRELOAD 注入，劫持 connect/read/write 等 9 个 syscall
    │  TLS 加密 + 自定义二进制帧协议
    ▼
Threshold Server (:9999)
    ├── TLS Listener        → 接受连接，mTLS 双向认证
    ├── Handshake Parser    → 解析握手包（UUID + 目标地址）
    ├── Fingerprint Matcher → 六层 Hash 树设备校验
    ├── Router (V2)         → 操作风险分级（L0-L3）
    ├── Decision Engine     → 白名单/规则匹配（abort）
    ├── Connection Pool     → per-host TCP 连接复用
    └── Frame Protocol      → 二进制帧读写 + 响应封装
            │
            ▼
      目标服务器（业务后端）
```

---

## 二、帧协议规范

### 2.1 客户端 → 服务端

**握手包（连接建立时一次性发送）：**

```
外层帧:  [Length: 4字节 BE] [Payload: Length 字节]

Payload 内部:
  Magic:     0x54 0x48 (2 字节)
  Version:   0x01 (1 字节)
  UUID Len:  1 字节
  UUID:      变长
  Addr Fam:  0x01(IPv4) / 0x02(IPv6) (1 字节)
  Port:      2 字节 BE
  IP:        4 字节 (IPv4) / 16 字节 (IPv6)
```

**数据帧（每个请求）：**

```
[Length: 4字节 BE] [Payload: Length 字节]
```

### 2.2 服务端 → 客户端

**响应帧：**

```
[Status: 1字节] [Length: 4字节 BE] [Payload: Length 字节]
```

**Status 码：**

| 值   | 含义         | 触发条件                         |
| ---- | ------------ | -------------------------------- |
| 0x00 | OK           | 安全校验通过，响应体已附加       |
| 0x01 | BLOCKED      | 指纹不匹配 / 决策引擎阻断        |
| 0x02 | RATE_LIMITED | 连接池耗尽 / 转发失败 / 响应超时 |

### 2.3 限制

| 参数            | 值    | 说明             |
| --------------- | ----- | ---------------- |
| MaxPayloadSize  | 1 MB  | 单帧最大载荷     |
| MaxResponseSize | 10 MB | 后端响应体最大值 |

---

## 三、TLS / mTLS 配置

### 3.1 证书体系

```
CA 自签名证书（ca.crt / ca.key）
  ├── Server 证书（server.crt / server.key）  — SAN 包含监听 IP/域名
  └── Client 证书（device.crt / device.key） — CN 为设备 UUID
```

- CA 证书有效期：10 年
- Server/Client 证书默认有效期：365 天
- 信任链为单级：CA → 服务端证书 / 客户端证书
- 新增设备只需签发客户端证书，服务端无需更新信任池

### 3.2 证书签发

```bash
# 初始化 CA
adminctl ca init

# 签发服务端证书（SAN 字段）
adminctl cert issue --type server --ip 127.0.0.1 --days 365

# 签发客户端证书（CN 字段）
adminctl cert issue --type client --uuid <device-uuid> --days 365
```

### 3.3 服务端 TLS 配置

```go
tls.Config{
    Certificates: []tls.Certificate{serverCert},
    ClientCAs:    caCertPool,
    ClientAuth:   tls.RequireAndVerifyClientCert,
    MinVersion:   tls.VersionTLS12,
}
```

- CACertFile 非空 → 启用 mTLS（验证客户端证书）
- CACertFile 为空或加载失败 → 降级为单向 TLS
- 降级判断通过文件存在性（`os.Stat`），不依赖配置开关

### 3.4 连接过程

```
① 客户端连接 :9999
② TLS 握手：
   → 服务端出示 server.crt
   → 客户端用 ca.crt 验证 server.crt 签名 + SAN
   → 客户端出示 client.crt（CN=UUID）
   → 服务端用 ca.crt 验证 client.crt 签名
   → 服务端要求客户端用私钥签名随机数（证明持有私钥）
③ 协商 Session Key → AES-256-GCM 加密通道建立
④ 客户端发送握手包（UUID + 目标地址）
⑤ 服务端验证握手包 → 返回 OK / BLOCKED
⑥ 进入请求-响应循环
```

---

## 四、连接池设计

### 4.1 架构

```
ConnPool
  ├── hosts: map[string]*hostPool   // per-host 隔离（将不同host分开，但是如果host很多会比较消耗内存）
  │     └── hostPool
  │           ├── mu: sync.Mutex     // 只保护本 host 的栈
  │           └── conns: []*pooledConn  // LIFO 连接栈
  ├── mu: sync.RWMutex              // 只保护 hosts map
  ├── totalConns: int32 (atomic)    // 全局连接计数器
  ├── maxConns: int32               // 全局上限（默认 500）
  ├── maxPerHost: int               // 单 host 上限（默认 20）
  ├── closed: int32 (atomic)        // shutdown 标记
  └── stopCh: chan struct{}         // janitor 退出信号
```

### 4.2 连接生命周期

```
dial() 创建
  │  atomic +1
  ▼
Get() 取出
  │  LIFO → 取栈顶
  │  三道检查：maxLifetime → isAlive → bufio.Buffered()
  ▼
doRoundTrip() 使用
  │  绑定 bufio.Reader（避免预读数据丢失）
  ▼
Put() 放回
  │  closed 检查 → 池满检查 → 更新 lastUsed
  ▼
cleanup() 清理 / closeConn() 关闭
  │  atomic -1
  ▼
GC 回收
```

### 4.3 探活机制

```go
func (p *ConnPool) isAlive(pc *pooledConn) bool {
    pc.conn.SetReadDeadline(time.Now().Add(1 * time.Millisecond))
    _, err := pc.br.Peek(1)  // 通过 bufio.Reader 窥探，不消费字节
    pc.conn.SetReadDeadline(time.Time{})

    if err != nil {
        if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
            return true   // 超时 = 连接活着，只是没数据
        }
        return false      // EOF / reset = 连接已死
    }
    return false           // 有脏数据 = 连接不可信
}
```

**关键点：通过 `bufio.Reader.Peek` 而非直接读 `net.Conn`**，保证探活与数据读取使用同一个缓冲区视角。

### 4.4 防御性检查

从池中取出连接后、返回给调用方之前：

```go
if pc.br.Buffered() > 0 {
    // 上一轮畸形响应导致 bufio 缓冲区有残留字节
    p.closeConn(pc)
    continue
}
```

### 4.5 后台清理

| 参数        | 值      | 说明                      |
| ----------- | ------- | ------------------------- |
| 清理间隔    | 30 秒   | janitor ticker 周期       |
| maxIdle     | 5 分钟  | 空闲超时（基于 lastUsed） |
| maxLifetime | 30 分钟 | 硬上限（基于 created）    |

清理后尾部残留指针置 nil，允许 GC 回收已关闭的 `*pooledConn`。

### 4.6 连接关闭计数

**所有连接关闭必须统一走 `closeConn`：**

```go
func (p *ConnPool) closeConn(pc *pooledConn) {
    pc.conn.Close()
    atomic.AddInt32(&p.totalConns, -1)
}
```

调用点：

| 位置            | 场景                                           |
| --------------- | ---------------------------------------------- |
| Get             | maxLifetime 过期 / isAlive 失败 / bufio 有残留 |
| Put             | pool 已关闭 / 池满                             |
| cleanup         | maxLifetime 过期 / maxIdle 过期 / isAlive 失败 |
| forwardWithPool | 转发失败重试时                                 |
| Close           | 优雅关闭时清空全部连接                         |

### 4.7 状态码对照

| 触发条件               | 返回状态          | 说明                       |
| ---------------------- | ----------------- | -------------------------- |
| 指纹不匹配             | StatusBlocked     | 设备未注册或维度被策略阻断 |
| 决策引擎阻断           | StatusBlocked     | 规则匹配触发 BLOCK         |
| 连接池耗尽             | StatusRateLimited | totalConns 达到 maxConns   |
| dial 失败              | StatusRateLimited | TCP 连不上目标             |
| 转发失败（重试也失败） | StatusRateLimited | 后端无响应 / 超时          |
| 响应体过大             | StatusRateLimited | 超过 MaxResponseSize       |
| pool 已关闭            | StatusRateLimited | 正在 shutdown              |

---

## 五、超时保护

| 阶段                | 超时值 | 方式                       |
| ------------------- | ------ | -------------------------- |
| TLS 握手 + 首帧读取 | 10 秒  | `conn.SetDeadline`         |
| 握手响应写入        | 5 秒   | `conn.SetWriteDeadline`    |
| 请求循环每帧读取    | 60 秒  | `conn.SetReadDeadline`     |
| 转发请求写入        | 10 秒  | `pc.conn.SetWriteDeadline` |
| 转发响应读取        | 10 秒  | `pc.conn.SetReadDeadline`  |
| 新建 TCP 连接       | 5 秒   | `net.DialTimeout`          |

---

## 六、并发控制

### 6.1 TLS 连接并发

```go
sem: make(chan struct{}, maxConns)  // 信号量，默认 1000
```

- Accept → 尝试获取令牌（非阻塞）
- 拿到令牌 → 启动 goroutine 处理
- 令牌池满 → 关闭连接，拒绝服务
- 处理完成 → `defer` 归还令牌

### 6.2 连接池并发

- per-host 锁：不同 host 之间的操作无竞争
- 全局 RWMutex：仅保护 hosts map 的读写（读多写少）
- `totalConns` 原子操作：无锁全局计数
- `closed` 原子标记：shutdown 期间阻止新建连接

---

## 七、安全决策链路

```
请求到达
  │
  ├── ① 帧解析：readFrame（大小限制 1MB）
  │
  ├── ② 指纹校验（六层 Hash 树）
  │     ├── 第一轮：树精确匹配（OS + IP + Port + Protocol + UUID + Reserved）
  │     │     └── 命中 → 放行
  │     ├── 第二轮：UUID 兜底 + 逐维度策略
  │     │     ├── UUID 未注册 → BLOCKED
  │     │     ├── block 策略维度漂移 → BLOCKED
  │     │     ├── audit 策略维度漂移 → 放行 + 审计日志
  │     │     └── ignore 策略 → 静默
  │     └── 匹配失败 → BLOCKED + AlertQueue
  │
  ├── ③ 协议解析：parseHandshake → 提取 Method/Path
  │
  ├── ④ Router 分级（V2 YAML 规则引擎）
  │     ├── L0（只读）→ 直接穿透
  │     └── L1-L3 → 进入决策引擎
  │
  ├── ⑤ Decision Engine（白名单 / 规则匹配）
  │     └── BLOCK / BLOCK_DEVICE / BLACKLIST → StatusBlocked
  │
  └── ⑥ 连接池转发
        ├── Get → doRoundTrip → Put
        └── 失败 → closeConn → 重试一次
```

---

## 八、配置参数

```yaml
# ============================================================
# Mode 3: 直连模式 (Direct Connect) 配置
# 说明: 客户端通过 LD_PRELOAD 劫持 TCP 连接，经 TLS 直连安全代理
# ============================================================
direct_connect:
  # 是否启用直连模式
  # true:  监听 :9999 端口，接受 libthreshold.so 客户端连接
  # false: 不启动直连监听器，仅保留 gRPC 接入层
  enabled: true

  # 监听地址，客户端的 libthreshold.so 将连接此地址
  # 格式: [host]:port，留空 ":port" 表示监听所有网卡
  listen_addr: ":9999"

  # TLS 服务端证书文件路径（PEM 格式）
  # 客户端需要信任签发此证书的 CA，否则 TLS 握手失败
  cert_file: "./data/certs/server.crt"

  # TLS 服务端私钥文件路径（PEM 格式）
  # 私钥文件权限建议设为 0600
  key_file: "./data/certs/server.key"

  # ----------------------------------------------------------
  # 连接池配置
  # 直连模式通过连接池复用到目标服务器的 TCP 连接
  # 减少每请求一次 TCP 三次握手的开销（~1-2ms/次）
  # ----------------------------------------------------------

  # 全局最大连接数（连接池上限 + 并发连接信号量容量）
  # 超过此值的新建连接将被拒绝，返回 RATE_LIMITED 状态
  # 建议: 根据后端服务器承载能力和机器 fd 上限调整
  # 生产推荐: 500-2000
  max_conns: 1000

  # 单个目标地址的最大池化连接数
  # 每个目标维护一个 LIFO 栈，最近使用的连接优先复用
  # 值越大连接复用率越高，但会占用更多 fd 和内存
  # 建议: 10-50，取决于单目标的并发请求数
  max_per_host: 20

  # 连接最大存活时间（硬上限）
  # 无论连接是否仍在使用，超过此时间后将被后台清理协程回收
  # 用于防止长时间存活的连接因中间 NAT/防火墙超时而变成半死连接
  # 格式: Go duration，如 "30m"、"1h"
  max_lifetime: "30m"

  # 连接最大空闲时间
  # 超过此时间未被复用的连接将被后台清理协程回收
  # 基于连接的 lastUsed 时间判断，每次复用时更新
  # 建议: 小于 max_lifetime，通常为 max_lifetime 的 1/5 ~ 1/6
  max_idle: "5m"

  # ----------------------------------------------------------
  # 清理协程配置
  # 后台定时检查连接池中的过期和死连接并回收
  # ----------------------------------------------------------

  # 清理协程唤醒间隔
  # 每隔此时间扫描一次全池，剔除过期（max_lifetime）、
  # 空闲超时（max_idle）和探活失败（isAlive）的连接
  # 值越小清理越及时，但 CPU 开销略增
  # 建议: 15s-60s
  janitor_interval: "30s"

  # ----------------------------------------------------------
  # 超时配置
  # 控制各个阶段的最大等待时间，防止慢连接占用资源
  # ----------------------------------------------------------

  # TCP 连接建立超时
  # 从池中无可用连接时，新建到目标服务器的 TCP 连接的最大等待时间
  # 目标服务器不可达时，超过此时间返回错误
  dial_timeout: "5s"

  # TLS 握手 + 首帧读取超时
  # 客户端连接后必须在此时间内完成 TLS 握手并发送握手包
  # 防止 slowloris 类攻击（连上后什么都不发，占用连接不释放）
  # 建议: 5s-15s
  tls_handshake_timeout: "10s"

  # 请求循环每帧读取超时
  # 长连接场景下，客户端可能间隔较长时间才发送下一个请求
  # 超过此时间未收到新帧则关闭连接，释放资源
  # 建议: 30s-120s，根据业务场景调整
  # 注意: 设太短会误杀正常长连接（如 curl 等待用户输入）
  request_read_timeout: "60s"

  # 转发写入超时
  # 向目标服务器发送请求数据的最大等待时间
  write_timeout: "10s"

  # 转发读取超时
  # 从目标服务器读取响应数据的最大等待时间
  # 后端慢查询或无响应时，超过此时间返回 RATE_LIMITED
  read_timeout: "10s"

  # ----------------------------------------------------------
  # 帧大小限制
  # 二进制帧协议的载荷上限，防止畸形请求导致 OOM
  # ----------------------------------------------------------

  # 单帧最大载荷（字节）
  # 客户端每帧数据不允许超过此值，超过则拒绝读取并关闭连接
  # 应用层一般单次 write 在 1KB-64KB，1MB 是纯防御性上限
  # 1048576 = 1MB
  max_payload_size: 1048576

  # 后端响应体最大值（字节）
  # 超过此值的响应会被截断并返回错误，防止后端异常导致 OOM
  # 10485760 = 10MB
  max_response_size: 10485760
```

| 参数                  | 默认值  | 说明                         |
| --------------------- | ------- | ---------------------------- |
| max_conn              | 1000    | 信号量容量 + 连接池上限      |
| max_per_host          | 20      | per-host LIFO 栈深度         |
| max_lifetime          | 30 分钟 | 硬编码，连接最长存活时间     |
| max_idle              | 5 分钟  | 硬编码，空闲连接最长存活时间 |
| janitor_interval      | 30 秒   | 后台清理周期                 |
| dial_timeout          | 5 秒    | 新建 TCP 连接超时            |
| tls_handshake_timeout | 10 秒   | TLS 握手 + 首帧超时          |
| request_read_timeout  | 60 秒   | 请求循环每帧读取超时         |
| write_timeout         | 10 秒   | 转发写入超时                 |
| read_timeout          | 10 秒   | 转发读取超时                 |
| max_payload_size      | 1 MB    | 单帧最大载荷                 |
| max_response_size     | 10 MB   | 后端响应体最大值             |

---

## 九、已解决的生产问题清单

| #    | 问题                                          | 严重程度 | 解决方案                        |
| ---- | --------------------------------------------- | -------- | ------------------------------- |
| 1    | `maxConns` 默认 0 导致 dial 永远失败          | 致命     | NewConnPool 兜底默认值 500      |
| 2    | `totalConns` 只增不减导致连接池报满但实际为空 | 致命     | 统一 closeConn 管理计数         |
| 3    | `sem` 无缓冲导致所有连接被拒绝                | 致命     | `make(chan struct{}, maxConns)` |
| 4    | `isAlive` 绕过 bufio.Reader 导致数据错位      | 严重     | 改用 bufio.Peek 探活            |
| 5    | 尾部残留指针不置 nil 导致连接对象泄漏         | 中等     | cleanup 后遍历置 nil            |
| 6    | `Put` 不检查 closed 导致 shutdown 后连接泄漏  | 中等     | Put 开头检查 closed 标记        |
| 7    | TLS 握手无超时导致 slowloris 耗尽 goroutine   | 严重     | SetDeadline 10 秒               |
| 8    | 响应体无大小限制导致 OOM                      | 严重     | LimitReader + MaxResponseSize   |
| 9    | 无并发连接数上限导致 fd/goroutine 耗尽        | 严重     | channel 信号量                  |
| 10   | Listener.Close() 无防重入导致 panic           | 中等     | sync.Once                       |
| 11   | closeCh 未初始化导致退出死循环                | 致命     | New 中初始化                    |
| 12   | bufio.NewReader 绑定在 conn 上而非 pooledConn | 严重     | pooledConn 携带 br 字段         |
| 13   | handle 中 defer conn.Close() 重复             | 轻微     | 删除多余的 defer                |

---

## 十、Graceful Shutdown 流程

```
信号到达（SIGTERM / SIGINT）
  │
  ▼
Listener.Close()
  │  closeOnce.Do:
  │    ① close(closeCh)
  │    ② ln.Close()           → Accept 退出循环
  │    ③ pool.Close()          → closed=1 + stopCh + 关闭所有池连接
  │
  ▼
正在处理的 handle goroutine
  │  请求循环的 readFrame 超时（60s）或 readFrame 返回 error
  │  → session 结束 → goroutine 退出
  │  → defer → conn.Close() → sem 令牌归还
  │
  ▼
正在转发的 forwardWithPool
  │  doRoundTrip 超时（10s）
  │  → 重试 Get() → pool.closed=1 → 返回 error
  │  → StatusRateLimited → 响应客户端
  │
  ▼
所有 goroutine 退出
```

**最大停机时间 = TLS 连接读超时（60 秒）+ 转发超时（10 秒）≈ 70 秒**

如果需要更快的停机，可以在 `Listener.Close()` 后额外对所有活跃连接强制设置一个短超时：

```go
// 可选：快速终止活跃连接
func (l *Listener) Shutdown(timeout time.Duration) {
    l.Close()
    time.Sleep(timeout)
    // 此时仍在运行的 goroutine 被强制遗留，进程退出时由 OS 回收
}
```

---

## 十一、可观测性（上线补）

### 11.1 Metrics（Prometheus）

```go
var (
    // 连接池
    poolHits    = prometheus.NewCounter(...)   // 池中复用次数
    poolMisses  = prometheus.NewCounter(...)   // 池中无连接，新建次数
    poolDropped = prometheus.NewCounter(...)   // 连接被拒绝（池满/exhausted/closed）
    activeConns = prometheus.NewGauge(...)     // 当前活跃 TLS 连接数
    totalPooled = prometheus.NewGauge(...)     // 池中总连接数
    totalConns  = prometheus.NewGauge(...)     // atomic totalConns 快照

    // 请求
    requestsTotal   = prometheus.NewCounterVec(..., []string{"status"})
    requestDuration = prometheus.NewHistogramVec(..., []string{"stage"})

    // 安全决策
    fingerprintRejects = prometheus.NewCounter(...)
    decisionBlocks     = prometheus.NewCounter(...)
    alertsSent         = prometheus.NewCounter(...)
)
```

### 11.2 结构化日志

```json
{
  "ts": "2025-06-30T10:12:34.567Z",
  "level": "info",
  "msg": "request_completed",
  "conn_id": "mode3-abc123-1719742354567890000",
  "uuid": "abc123",
  "target": "10.0.0.5:8080",
  "method": "GET",
  "path": "/api/images",
  "risk_level": "L0",
  "decision": "ALLOW",
  "latency_ms": 12,
  "pool_hit": true,
  "frame_size": 2048
}
```

建议接入 `slog`（Go 1.21+）或 `zerolog`，输出 JSON 格式，接入 ELK/Loki。

---

## 十二、上线检查清单

### 12.1 代码层面

| #    | 检查项                                                      | 状态 |
| ---- | ----------------------------------------------------------- | ---- |
| 1    | 帧大小上限 MaxPayloadSize（1MB）                            | OK   |
| 2    | 响应体大小上限 MaxResponseSize（10MB）                      | OK   |
| 3    | TLS 握手 + 首帧 10 秒超时                                   | OK   |
| 4    | 请求循环每帧 60 秒读取超时                                  | OK   |
| 5    | 握手响应 5 秒写入超时                                       | OK   |
| 6    | 转发 10 秒读写超时                                          | OK   |
| 7    | 并发连接信号量（默认 1000）                                 | OK   |
| 8    | 连接池 closed 标记（Get / Put / dial）                      | OK   |
| 9    | totalConns 原子计数（dial +1 / closeConn -1）               | OK   |
| 10   | 所有关闭路径统一走 closeConn                                | OK   |
| 11   | isAlive 通过 bufio.Peek                                     | OK   |
| 12   | bufio.Buffered() 防御性检查                                 | OK   |
| 13   | 尾部残留指针置 nil                                          | OK   |
| 14   | 后台 janitor（30s 清理 / 5min maxIdle / 30min maxLifetime） | OK   |
| 15   | Listener.Close() sync.Once 防重入                           | OK   |
| 16   | closeCh / ln 引用保存 / 优雅退出                            | OK   |
| 17   | mTLS 双向证书认证 + 降级逻辑                                | OK   |
| 18   | 指纹校验 + audit 日志 + alert 告警                          | OK   |
| 19   | 重试逻辑（失败 → closeConn → Get → 重试一次）               | OK   |
| 20   | per-host 锁 + 全局 RWMutex                                  | OK   |
| 21   | doRoundTrip 绑定 bufio.Reader                               | OK   |
| 22   | Config 可配置 MaxConn / MaxPerHost                          | OK   |
| 23   | 二进制协议越界检查                                          | OK   |

### 12.2 部署层面

| #    | 检查项                     | 说明                                 |
| ---- | -------------------------- | ------------------------------------ |
| 1    | 证书文件权限               | ca.key 0600，server.key 0600         |
| 2    | 端口 :9999 防火墙规则      | 仅允许客户端网段访问                 |
| 3    | 进程 ulimit                | nofile 至少 65535                    |
| 4    | systemd Restart 策略       | Restart=on-failure, RestartSec=5     |
| 5    | 日志输出到文件 + logrotate | 防止磁盘写满                         |
| 6    | 健康检查端点               | 建议单独 HTTP 端口暴露 /healthz      |
| 7    | 信号处理                   | 捕获 SIGTERM → 调用 Listener.Close() |

### 12.3 测试层面

| #    | 测试场景                       | 预期行为                          |
| ---- | ------------------------------ | --------------------------------- |
| 1    | 正常连接 → 握手 → 请求 → 响应  | StatusOK，连接复用                |
| 2    | 未注册 UUID 的设备连接         | StatusBlocked，alert 推送         |
| 3    | 目标服务器不可达               | StatusRateLimited，重试一次后返回 |
| 4    | 目标服务器响应超时             | StatusRateLimited，10 秒后返回    |
| 5    | 客户端 TLS 握手后什么都不发    | 10 秒后连接关闭                   |
| 6    | 客户端发送 2MB 的帧            | readFrame 拒绝，连接关闭          |
| 7    | 后端返回 20MB 响应             | LimitReader 截断，返回错误        |
| 8    | 1001 个并发连接                | 第 1001 个被拒绝                  |
| 9    | 发送 SIGTERM                   | 正在处理的请求完成后退出          |
| 10   | 连接池连接超过 30 分钟         | cleanup 自动关闭                  |
| 11   | 连接池连接空闲 5 分钟          | cleanup 自动关闭                  |
| 12   | 目标服务器重启后连接池中的连接 | isAlive 探活失败，自动重建        |

---

## 十三、后续迭代（按优先级）

| 优先级 | 项目                 | 说明                                              |
| ------ | -------------------- | ------------------------------------------------- |
| P2     | Prometheus metrics   | 连接池命中率、请求 QPS、决策耗时、错误率          |
| P2     | 结构化日志           | 统一 JSON 格式，接入 ELK/Loki                     |
| P2     | 健康检查端点         | /healthz 暴露服务状态 + 池状态                    |
| P2     | 配置热加载           | YAML 规则 + 黑白名单支持 fsnotify 热更新          |
| P3     | 决策引擎建模         | 基于真实流量数据标定阈值，引入时序行为分析        |
| P3     | 连接池指标导出       | 当前 totalConns / activeConns / pool 深度         |
| P3     | TCP 非 HTTP 场景优化 | 当前 doRoundTrip 假设后端是 HTTP，纯 TCP 需要适配 |