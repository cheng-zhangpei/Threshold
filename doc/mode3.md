# Mode 3 直连模式开发文档

@author：程章培

[toc]

## 一、概述

Mode 3（直连模式）是 Threshold 安全代理系统的第三种接入模式。与 Mode 1（原生 gRPC）和 Mode 2（SOCKS5 转 gRPC）不同，Mode 3 完全绕开 gRPC 协议栈，通过 `LD_PRELOAD` 劫持客户端进程的系统调用，将 TCP 流量透明重定向到安全代理服务端，经 TLS 加密后转发到真实目标。

Mode 3 的核心价值在于**零侵入性** — 任何 C/C++ 程序（包括 curl、wget、数据库客户端等）无需修改代码或配置代理，仅通过环境变量注入 `.so` 库即可接入安全代理。

### 1.1 架构总览

任意 C 程序 (curl / wget / 应用) │ connect() 被 LD_PRELOAD 劫持 ▼ libthreshold.so │ 1. 修改目标地址 → Threshold Server:9999 │ 2. TLS 握手 │ 3. 发送握手包 (设备UUID + 真实目标地址) │ 4. 后续数据帧封装 + TLS 加密转发 ▼ Threshold Server (TCP+TLS Listener, :9999) │ 1. TLS 终止 │ 2. 解析握手包 → 指纹校验 │ 3. 安全决策（Router 分级 + Decision Engine） │ 4. 直接转发到真实目标 ▼ 真实目标服务器

1.2 与 M

| 维度       | Mode 1 (gRPC)           | Mode 2 (SOCKS5)             | Mode 3 (直连)            |
| ---------- | ----------------------- | --------------------------- | ------------------------ |
| 传输协议   | gRPC (HTTP/2)           | gRPC (HTTP/2)               | 原生 TCP + TLS           |
| 客户端侵入 | 需要 IDV Client 集成    | 需要 SOCKS5 支持            | **零侵入**（LD_PRELOAD） |
| 加密       | gRPC 自带 TLS/mTLS      | gRPC 自带 TLS/mTLS          | OpenSSL TLS              |
| 身份标识   | EstablishConnection RPC | EstablishConnection RPC     | 二进制握手包             |
| 数据帧     | ProxyStream protobuf    | ProxyStream protobuf        | 4字节长度前缀            |
| 决策粒度   | 每个 ProxyStream 消息   | 每个 ProxyStream 消息       | 连接级（一次性决策）     |
| 适用场景   | IDV Client 深度集成     | 浏览器、curl 等 SOCKS5 应用 | 任意 C/C++ 程序          |

---

## 二、劫持模块设计（libthreshold.so）

### 2.1 模块结构
### 1.2 与 Mode 1/2 的对比

| 维度       | Mode 1 (gRPC)           | Mode 2 (SOCKS5)             | Mode 3 (直连)            |
| ---------- | ----------------------- | --------------------------- | ------------------------ |
| 传输协议   | gRPC (HTTP/2)           | gRPC (HTTP/2)               | 原生 TCP + TLS           |
| 客户端侵入 | 需要 IDV Client 集成    | 需要 SOCKS5 支持            | **零侵入**（LD_PRELOAD） |
| 加密       | gRPC 自带 TLS/mTLS      | gRPC 自带 TLS/mTLS          | OpenSSL TLS              |
| 身份标识   | EstablishConnection RPC | EstablishConnection RPC     | 二进制握手包             |
| 数据帧     | ProxyStream protobuf    | ProxyStream protobuf        | 4字节长度前缀            |
| 决策粒度   | 每个 ProxyStream 消息   | 每个 ProxyStream 消息       | 连接级（一次性决策）     |
| 适用场景   | IDV Client 深度集成     | 浏览器、curl 等 SOCKS5 应用 | 任意 C/C++ 程序          |

---

## 二、劫持模块设计（libthreshold.so）

### 2.1 模块结构

text

libthreshold/ ├── CMakeLists.txt ├── include/ │ ├── protocol.h # 二进制协议常量与帧格式定义 │ ├── config.h # 配置管理（环境变量读取） │ ├── device_uuid.h # 设备 UUID 采集 │ ├── conn_table.h # fd → 连接状态映射表 │ ├── tls_ctx.h # TLS 上下文管理（OpenSSL） │ ├── framing.h # 长度前缀帧读写 │ ├── handshake.h # 握手协议构造与解析 │ └── hook.h # 系统调用 hook 声明 ├── src/ │ ├── libthreshold.c # 入口文件 │ ├── config.c # 配置加载 │ ├── device_uuid.c # 设备标识采集 │ ├── conn_table.c # 连接状态管理 │ ├── tls_ctx.c # TLS 初始化与连接 │ ├── framing.c # 帧协议读写 │ ├── handshake.c # 握手包编解码 │ └── hook.c # 系统调用 hook 实现（核心） └── test/ └── test_main.c # 测试客户端

text

```
### 2.2 系统调用 Hook 机制

Mode 3 的核心原理是通过 `LD_PRELOAD` 机制覆盖 glibc 的系统调用实现。Linux 的动态链接器在加载共享库时，先加载的库中的同名符号会覆盖后加载的。通过设置 `LD_PRELOAD=./threshold.so`，我们的 `connect()`、`write()`、`read()` 等函数会替代 glibc 的原始实现。

**Hook 的函数清单：**

| 函数 | 用途 | 原始函数获取方式 |
|---|---|---|
| `connect()` | 拦截 TCP 连接，替换目标地址 | `dlsym(RTLD_NEXT, "connect")` |
| `write()` | 拦截写出，帧封装后 TLS 发送 | `dlsym(RTLD_NEXT, "write")` |
| `read()` | 拦截读入，从帧缓冲区返回 | `dlsym(RTLD_NEXT, "read")` |
| `send()` | 同 write，部分库调用此函数 | `dlsym(RTLD_NEXT, "send")` |
| `sendto()` | 同 write，curl 实际调用此函数 | `dlsym(RTLD_NEXT, "sendto")` |
| `sendmsg()` | 同 write，散列发送 | `dlsym(RTLD_NEXT, "sendmsg")` |
| `recv()` | 同 read | `dlsym(RTLD_NEXT, "recv")` |
| `readv()` | 同 read，散列读取，curl 读响应调用 | `dlsym(RTLD_NEXT, "readv")` |
| `close()` | 连接关闭时清理 TLS 和缓冲区 | `dlsym(RTLD_NEXT, "close")` |

函数指针通过 `dlsym(RTLD_NEXT, ...)` 在 `.so` 的 `__attribute__((constructor))` 中获取，该函数在 `main()` 之前自动执行：

```c
__attribute__((constructor))
static void init_hooks(void) {
    real_connect = dlsym(RTLD_NEXT, "connect");
    real_write   = dlsym(RTLD_NEXT, "write");
    real_read    = dlsym(RTLD_NEXT, "read");
    real_send    = dlsym(RTLD_NEXT, "send");
    real_sendto  = dlsym(RTLD_NEXT, "sendto");
    real_sendmsg = dlsym(RTLD_NEXT, "sendmsg");
    real_recv    = dlsym(RTLD_NEXT, "recv");
    real_readv   = dlsym(RTLD_NEXT, "readv");
    real_close   = dlsym(RTLD_NEXT, "close");

    conn_table_init();
    tls_ctx_init();
    g_hooks_ready = 1;
}
### 2.2 系统调用 Hook 机制

Mode 3 的核心原理是通过 `LD_PRELOAD` 机制覆盖 glibc 的系统调用实现。Linux 的动态链接器在加载共享库时，先加载的库中的同名符号会覆盖后加载的。通过设置 `LD_PRELOAD=./threshold.so`，我们的 `connect()`、`write()`、`read()` 等函数会替代 glibc 的原始实现。

**Hook 的函数清单：**

| 函数 | 用途 | 原始函数获取方式 |
|---|---|---|
| `connect()` | 拦截 TCP 连接，替换目标地址 | `dlsym(RTLD_NEXT, "connect")` |
| `write()` | 拦截写出，帧封装后 TLS 发送 | `dlsym(RTLD_NEXT, "write")` |
| `read()` | 拦截读入，从帧缓冲区返回 | `dlsym(RTLD_NEXT, "read")` |
| `send()` | 同 write，部分库调用此函数 | `dlsym(RTLD_NEXT, "send")` |
| `sendto()` | 同 write，curl 实际调用此函数 | `dlsym(RTLD_NEXT, "sendto")` |
| `sendmsg()` | 同 write，散列发送 | `dlsym(RTLD_NEXT, "sendmsg")` |
| `recv()` | 同 read | `dlsym(RTLD_NEXT, "recv")` |
| `readv()` | 同 read，散列读取，curl 读响应调用 | `dlsym(RTLD_NEXT, "readv")` |
| `close()` | 连接关闭时清理 TLS 和缓冲区 | `dlsym(RTLD_NEXT, "close")` |

函数指针通过 `dlsym(RTLD_NEXT, ...)` 在 `.so` 的 `__attribute__((constructor))` 中获取，该函数在 `main()` 之前自动执行：

```c
__attribute__((constructor))
static void init_hooks(void) {
    real_connect = dlsym(RTLD_NEXT, "connect");
    real_write   = dlsym(RTLD_NEXT, "write");
    real_read    = dlsym(RTLD_NEXT, "read");
    real_send    = dlsym(RTLD_NEXT, "send");
    real_sendto  = dlsym(RTLD_NEXT, "sendto");
    real_sendmsg = dlsym(RTLD_NEXT, "sendmsg");
    real_recv    = dlsym(RTLD_NEXT, "recv");
    real_readv   = dlsym(RTLD_NEXT, "readv");
    real_close   = dlsym(RTLD_NEXT, "close");

    conn_table_init();
    tls_ctx_init();
    g_hooks_ready = 1;
}
```



### 2.3 connect() hook 详解



`connect()` 是整个模块的入口。当应用调用 `connect(sockfd, target_addr, ...)` 时，hook 函数执行以下流程：



text

```
connect(sockfd, original_addr)
    │
    ├── should_bypass() 检查
    │   ├── 非 TCP 连接 → 跳过，走原始 connect
    │   ├── 连向 proxy 自身 → 跳过（防递归）
    │   └── 都不是 → 继续劫持
    │
    ├── 替换目标地址为 proxy server (127.0.0.1:9999)
    ├── real_connect(sockfd, proxy_addr)
    │
    ├── [非阻塞socket] 处理 EINPROGRESS
    │   ├── select() 等待连接完成
    │   ├── getsockopt() 检查连接是否成功
    │   └── fcntl() 切回阻塞模式（TLS 握手需要）
    │
    ├── TLS 握手（tls_connect → SSL_connect）
    ├── 发送握手包（UUID + 目标地址）
    ├── 接收握手响应（OK / BLOCKED）
    │
    └── conn_table_set() 保存连接状态
connect(sockfd, original_addr)
    │
    ├── should_bypass() 检查
    │   ├── 非 TCP 连接 → 跳过，走原始 connect
    │   ├── 连向 proxy 自身 → 跳过（防递归）
    │   └── 都不是 → 继续劫持
    │
    ├── 替换目标地址为 proxy server (127.0.0.1:9999)
    ├── real_connect(sockfd, proxy_addr)
    │
    ├── [非阻塞socket] 处理 EINPROGRESS
    │   ├── select() 等待连接完成
    │   ├── getsockopt() 检查连接是否成功
    │   └── fcntl() 切回阻塞模式（TLS 握手需要）
    │
    ├── TLS 握手（tls_connect → SSL_connect）
    ├── 发送握手包（UUID + 目标地址）
    ├── 接收握手响应（OK / BLOCKED）
    │
    └── conn_table_set() 保存连接状态
```



**防递归设计：**



`should_bypass()` 中检查目标地址是否为 proxy server 自身。如果不做此检查，当应用连接 `127.0.0.1:9999` 时，`connect()` hook 会再次调用 `real_connect(127.0.0.1:9999)`，形成无限递归。



### 2.4 递归 Hook 保护



这是 Mode 3 开发中遇到的最隐蔽的问题之一。`write()` 和 `read()` 的 hook 中调用了 `frame_send()` 和 `consume_recv_buf()`，这些函数内部使用 `SSL_write()` 和 `SSL_read()`。OpenSSL 底层会再次调用 `write(fd, ...)` 和 `read(fd, ...)`，触发我们的 hook，形成递归：



text

```
curl write(fd=5, HTTP请求)
  → 我们的 hook → frame_send() → SSL_write()
    → OpenSSL 内部调用 write(fd=5, TLS记录)
      → 我们的 hook → frame_send() → SSL_write()
        → 无限递归 → 栈溢出
curl write(fd=5, HTTP请求)
  → 我们的 hook → frame_send() → SSL_write()
    → OpenSSL 内部调用 write(fd=5, TLS记录)
      → 我们的 hook → frame_send() → SSL_write()
        → 无限递归 → 栈溢出
```



**解决方案：线程局部递归保护标志**



c

```
static __thread int g_in_io = 0;

ssize_t write(int fd, const void *buf, size_t count) {
    conn_entry_t *entry = conn_table_get(fd);
    if (!entry || g_in_io) {        // 正在进行 TLS IO 时，走原始 write
        return real_write(fd, buf, count);
    }

    g_in_io = 1;                    // 设置保护标志
    int ret = frame_send(entry->ssl, buf, (uint32_t)count);
    g_in_io = 0;                    // 清除保护标志

    if (ret != 0) {
        errno = ECONNRESET;
        return -1;
    }
    return (ssize_t)count;
}
static __thread int g_in_io = 0;

ssize_t write(int fd, const void *buf, size_t count) {
    conn_entry_t *entry = conn_table_get(fd);
    if (!entry || g_in_io) {        // 正在进行 TLS IO 时，走原始 write
        return real_write(fd, buf, count);
    }

    g_in_io = 1;                    // 设置保护标志
    int ret = frame_send(entry->ssl, buf, (uint32_t)count);
    g_in_io = 0;                    // 清除保护标志

    if (ret != 0) {
        errno = ECONNRESET;
        return -1;
    }
    return (ssize_t)count;
}
```



使用 `__thread` 确保多线程安全。每个 I/O hook（`write`、`read`、`send`、`sendto`、`sendmsg`、`recv`、`readv`）都需要相同的保护。



值得注意的是，TLS 握手阶段（`tls_connect()`）不会触发递归，因为此时 fd 尚未加入 `conn_table`，`conn_table_get(fd)` 返回 NULL，hook 直接走原始函数。递归只在握手完成后、curl 发送 HTTP 请求时才会发生。



### 2.5 非阻塞 Socket 处理



curl 在建立连接时使用非阻塞 socket。当 `connect()` 被调用时，系统立即返回 `-1` 并设置 `errno = EINPROGRESS`，表示连接正在进行中。curl 通过 `select()` / `poll()` 等待连接完成。



hook 需要正确处理这种情况：



c

```
int ret = real_connect(sockfd, (struct sockaddr *)&proxy_addr, sizeof(proxy_addr));

if (ret != 0) {
    if (errno == EINPROGRESS) {
        // select 等待连接完成
        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(sockfd, &wfds);
        struct timeval tv = {.tv_sec = 5, .tv_usec = 0};
        select(sockfd + 1, NULL, &wfds, NULL, &tv);

        // 检查连接结果
        int sock_err = 0;
        socklen_t errlen = sizeof(sock_err);
        getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &sock_err, &errlen);

        // 关键：切回阻塞模式
        // TLS 握手需要阻塞 socket，否则 SSL_connect 会失败
        int flags = fcntl(sockfd, F_GETFL, 0);
        fcntl(sockfd, F_SETFL, flags & ~O_NONBLOCK);
    }
}
int ret = real_connect(sockfd, (struct sockaddr *)&proxy_addr, sizeof(proxy_addr));

if (ret != 0) {
    if (errno == EINPROGRESS) {
        // select 等待连接完成
        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(sockfd, &wfds);
        struct timeval tv = {.tv_sec = 5, .tv_usec = 0};
        select(sockfd + 1, NULL, &wfds, NULL, &tv);

        // 检查连接结果
        int sock_err = 0;
        socklen_t errlen = sizeof(sock_err);
        getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &sock_err, &errlen);

        // 关键：切回阻塞模式
        // TLS 握手需要阻塞 socket，否则 SSL_connect 会失败
        int flags = fcntl(sockfd, F_GETFL, 0);
        fcntl(sockfd, F_SETFL, flags & ~O_NONBLOCK);
    }
}
```



不切回阻塞模式会导致 `SSL_connect()` 失败，报错 `error:00000000:lib(0)::reason(0)`，这是 OpenSSL 在非阻塞 socket 上表现异常的典型症状。



### 2.6 写入函数覆盖



curl 的发送函数选择与 libc 版本和编译选项有关。实测发现 curl 在不同环境下可能调用 `send()`、`sendto()` 或 `sendmsg()`。如果只 hook `send()` 而遗漏 `sendto()`，HTTP 请求会绕过 hook 直接发送明文到 proxy server 的 TLS socket，导致服务端拒绝。



**必须同时 hook 的函数：**



- `write()` — 标准 POSIX 写入
- `send()` — socket 发送
- `sendto()` — 带目标地址的发送（curl 常用）
- `sendmsg()` — 散列发送（使用 `struct iovec`）



**必须同时 hook 的读取函数：**



- `read()` — 标准 POSIX 读取
- `recv()` — socket 接收
- `readv()` — 散列读取（curl 读取 HTTP 响应时调用）



### 2.7 连接状态管理



每个被代理的 fd 维护一个 `conn_entry_t`：



c

```
typedef struct {
    int                      active;      // 是否激活
    SSL                     *ssl;         // TLS 连接
    struct sockaddr_storage  orig_addr;   // 原始目标地址
    socklen_t                orig_addrlen;
    char                    *recv_buf;    // 响应帧缓冲区
    uint32_t                 recv_buf_len;
    uint32_t                 recv_buf_pos;
} conn_entry_t;
typedef struct {
    int                      active;      // 是否激活
    SSL                     *ssl;         // TLS 连接
    struct sockaddr_storage  orig_addr;   // 原始目标地址
    socklen_t                orig_addrlen;
    char                    *recv_buf;    // 响应帧缓冲区
    uint32_t                 recv_buf_len;
    uint32_t                 recv_buf_pos;
} conn_entry_t;
```



以 fd 作为索引（`static conn_entry_t g_table[MAX_FD]`），O(1) 查找。`close()` hook 中执行 `SSL_shutdown()` + `SSL_free()` + 释放缓冲区。



### 2.8 配置化



所有外部参数通过环境变量注入，避免编译时硬编码：



| 环境变量                | 默认值                     | 说明                    |
| ----------------------- | -------------------------- | ----------------------- |
| `THRESHOLD_PROXY_HOST`  | `127.0.0.1`                | 代理服务器地址          |
| `THRESHOLD_PROXY_PORT`  | `9999`                     | 代理服务器端口          |
| `THRESHOLD_CA_CERT`     | `certs/server.crt`         | CA 证书路径（TLS 验证） |
| `THRESHOLD_DEVICE_UUID` | 自动采集 `/etc/machine-id` | 设备唯一标识            |



------



## 三、服务端 TCP Listener 设计



### 3.1 与现有架构的关系



TCP Listener 作为 Threshold Server 进程内的一个新组件启动，与 gRPC Layer 并行运行，共享指纹引擎、路由、决策引擎等核心组件：



text

```
Threshold Server (同一进程)
├── gRPC Layer (:50051)        — Mode 1/2，保持不变
├── TCP Listener (:9999)       — Mode 3，新增
├── Fingerprint Engine         — 共享
├── Router V2                  — 共享
├── Decision Engine            — 共享
├── DispatchManager            — 共享
└── AlertQueue                 — 共享
Threshold Server (同一进程)
├── gRPC Layer (:50051)        — Mode 1/2，保持不变
├── TCP Listener (:9999)       — Mode 3，新增
├── Fingerprint Engine         — 共享
├── Router V2                  — 共享
├── Decision Engine            — 共享
├── DispatchManager            — 共享
└── AlertQueue                 — 共享
```



### 3.2 组件结构



text

```
server/tcplistener/
├── protocol.go      # 二进制协议解析（握手包、帧格式）
├── listener.go      # TLS 监听 + 连接处理主逻辑
server/tcplistener/
├── protocol.go      # 二进制协议解析（握手包、帧格式）
├── listener.go      # TLS 监听 + 连接处理主逻辑
```



### 3.3 连接处理流程



text

```
TLS Accept
    │
    ├── TLS 握手（tls.Conn.Handshake）
    ├── 读取握手包（readFrame → parseHandshake）
    ├── 指纹校验（fpTree.Match）
    │   ├── 失败 → writeRespFrame(BLOCKED) + alertQueue
    │   └── 成功 → writeRespFrame(OK)
    │
    └── 请求循环
        ├── readFrame 读取请求帧
        ├── secureRoute 安全决策
        │   ├── Router.Classify → 风险等级
        │   ├── L0 → 直接放行
        │   ├── L1-L3 → Decision Engine 评估
        │   │   ├── BLOCK → 返回 BLOCKED
        │   │   └── 通过 → 继续
        │   └── 无 Router/DM → 降级直通
        │
        └── forwardAndRespond
            ├── net.Dial(真实目标)
            ├── 发送原始请求
            ├── 读取原始响应
            └── writeRespFrame(OK, 响应数据)
TLS Accept
    │
    ├── TLS 握手（tls.Conn.Handshake）
    ├── 读取握手包（readFrame → parseHandshake）
    ├── 指纹校验（fpTree.Match）
    │   ├── 失败 → writeRespFrame(BLOCKED) + alertQueue
    │   └── 成功 → writeRespFrame(OK)
    │
    └── 请求循环
        ├── readFrame 读取请求帧
        ├── secureRoute 安全决策
        │   ├── Router.Classify → 风险等级
        │   ├── L0 → 直接放行
        │   ├── L1-L3 → Decision Engine 评估
        │   │   ├── BLOCK → 返回 BLOCKED
        │   │   └── 通过 → 继续
        │   └── 无 Router/DM → 降级直通
        │
        └── forwardAndRespond
            ├── net.Dial(真实目标)
            ├── 发送原始请求
            ├── 读取原始响应
            └── writeRespFrame(OK, 响应数据)
```



### 3.4 依赖注入与降级策略



TCP Listener 通过 `Deps` 结构体接收外部组件，所有组件均可为 nil：



go

```
type Deps struct {
    Router   *router_v2.Router         // 路由分级
    DM       *dispatch.DispatchManager // L1-L3 异步调度
    Portrait *portrait.Store           // 用户画像
}
type Deps struct {
    Router   *router_v2.Router         // 路由分级
    DM       *dispatch.DispatchManager // L1-L3 异步调度
    Portrait *portrait.Store           // 用户画像
}
```



降级策略：



| 条件        | 行为                                    |
| ----------- | --------------------------------------- |
| 全部可用    | 完整安全决策链路                        |
| Router 为空 | 所有请求默认 L0，跳过分级               |
| DM 为空     | L1-L3 降级为直通转发，打印 WARNING 日志 |
| 全部为空    | 纯 TLS 转发（仅加密 + 指纹校验）        |



不会因为任何组件缺失而 panic 或拒绝服务。



------



## 四、二进制协议设计



### 4.1 握手包



连接建立时客户端发送一次，服务端响应一次。通过 TLS 加密通道传输。



**客户端 → 服务端：**



text

```
┌──────────┬──────────┬───────────────┬──────────────────────┐
│ Magic(2) │ Ver (1)  │ UUID Len (1)  │ UUID (16-36 bytes)   │
│ 0x54 0x48│  0x01    │               │                      │
├──────────┴──────────┴───────────────┼──────────────────────┤
│                                      │ Target Addr (变长)    │
│                                      │ Family(1)+Port(2)+IP │
└──────────────────────────────────────┴──────────────────────┘
┌──────────┬──────────┬───────────────┬──────────────────────┐
│ Magic(2) │ Ver (1)  │ UUID Len (1)  │ UUID (16-36 bytes)   │
│ 0x54 0x48│  0x01    │               │                      │
├──────────┴──────────┴───────────────┼──────────────────────┤
│                                      │ Target Addr (变长)    │
│                                      │ Family(1)+Port(2)+IP │
└──────────────────────────────────────┴──────────────────────┘
```



Target Addr 编码：



text

```
┌──────────┬──────────────┬──────────────────────┐
│ Family(1)│ Port (2 BE)  │ IP (4 or 16 bytes)   │
│ 0x01=IPv4│              │                      │
│ 0x02=IPv6│              │                      │
└──────────┴──────────────┴──────────────────────┘
┌──────────┬──────────────┬──────────────────────┐
│ Family(1)│ Port (2 BE)  │ IP (4 or 16 bytes)   │
│ 0x01=IPv4│              │                      │
│ 0x02=IPv6│              │                      │
└──────────┴──────────────┴──────────────────────┘
```



**服务端 → 客户端（握手响应）：**



text

```
┌─────────────────────────────┐
│ Status (1 byte)             │
│ 0x00 = OK                   │
│ 0x01 = BLOCKED              │
│ 0x02 = RATE_LIMITED         │
└─────────────────────────────┘
┌─────────────────────────────┐
│ Status (1 byte)             │
│ 0x00 = OK                   │
│ 0x01 = BLOCKED              │
│ 0x02 = RATE_LIMITED         │
└─────────────────────────────┘
```



### 4.2 数据帧



握手完成后，每个请求-响应循环使用帧协议传输。



**客户端 → 服务端（请求帧）：**



text

```
┌──────────────────────┬───────────────────────────────┐
│ Length (4 bytes BE)   │ Payload (Length bytes)         │
│                       │ 原始 HTTP 请求 / 应用数据      │
└──────────────────────┴───────────────────────────────┘
┌──────────────────────┬───────────────────────────────┐
│ Length (4 bytes BE)   │ Payload (Length bytes)         │
│                       │ 原始 HTTP 请求 / 应用数据      │
└──────────────────────┴───────────────────────────────┘
```



**服务端 → 客户端（响应帧）：**



text

```
┌──────────┬──────────────┬──────────────────────────────┐
│ Status(1)│ Length (4 BE)│ Payload (Length bytes)        │
│ 0x00=OK  │              │ 目标服务器的原始响应数据       │
│ 0x01=BLK │  (阻断时=0)  │                               │
└──────────┴──────────────┴──────────────────────────────┘
┌──────────┬──────────────┬──────────────────────────────┐
│ Status(1)│ Length (4 BE)│ Payload (Length bytes)        │
│ 0x00=OK  │              │ 目标服务器的原始响应数据       │
│ 0x01=BLK │  (阻断时=0)  │                               │
└──────────┴──────────────┴──────────────────────────────┘
```



设计决策：响应帧携带 Status 字段，让客户端能在数据层面感知阻断，而不仅仅依赖连接断开。



------



## 五、为什么 Mode 3 不走 Waiter/Sender/OutputBuffer



这是 Mode 3 与 Mode 1/2 最重要的架构差异。



### 5.1 Mode 1/2 的异步架构



Mode 1/2 的数据流是：



text

```
gRPC ProxyStream
    → Router 分级
    → DispatchManager 入队
    → Worker 决策
    → OutputBuffer.Put（带 RequestID）
    → Sender Worker 从 OutputBuffer 取出
    → Sender 转发到 OpenStack
    → Sender 收到响应
    → Waiter.Complete(RequestID, 响应)
    → gRPC stream.Send(响应) → 客户端
gRPC ProxyStream
    → Router 分级
    → DispatchManager 入队
    → Worker 决策
    → OutputBuffer.Put（带 RequestID）
    → Sender Worker 从 OutputBuffer 取出
    → Sender 转发到 OpenStack
    → Sender 收到响应
    → Waiter.Complete(RequestID, 响应)
    → gRPC stream.Send(响应) → 客户端
```



这条链路是**异步的**，原因是 Mode 1/2 的设计目标是对接 OpenStack API，安全决策和请求转发是两个独立的关注点。决策引擎可能需要触发镜像扫描（QUARANTINE_AND_ALERT）、限速（THROTTLE）等异步操作，不能阻塞等待后端响应。



### 5.2 Mode 3 不适合这条链路



Mode 3 的场景是**通用 TCP 代理**，客户端（如 curl）发送一个 HTTP 请求，期望收到一个 HTTP 响应。这是严格的请求-响应同步模式。



如果 Mode 3 也走 OutputBuffer → Sender → Waiter 链路，会产生以下问题：



**问题一：Sender 用 HTTP 客户端转发，破坏原始请求**



Sender 组件内部使用 Go 的 `net/http` 客户端转发请求。当 Mode 3 的客户端发送原始 HTTP 请求时，Sender 会解析 URL 并重新构造请求，导致 URL 拼接错误。实测发现 Sender 将目标地址和路径错误拼接为：



text

```
实际转发: "http://127.0.0.1:8080http//127.0.0.1:8080/api/test"
实际转发: "http://127.0.0.1:8080http//127.0.0.1:8080/api/test"
```



这是因为 Sender 为 Mode 1/2 的 OpenStack API 场景设计，假设请求是标准的 REST API，而 Mode 3 的流量是任意协议。



**问题二：Sender 返回的不是原始 HTTP 响应**



Sender 收到后端响应后，通过 `Waiter.Complete()` 返回的是 response body，不包含 HTTP 状态行和响应头。curl 收到裸 HTML 数据后报错 `HTTP/0.9 when not allowed`，因为缺少 `HTTP/1.1 200 OK` 等头部信息。



**问题三：请求-响应语义不匹配**



Mode 3 的每个请求帧需要一个完整的响应帧回传给客户端。Waiter 机制等待的是 Sender 的转发结果，但 Sender 可能因为超时、错误等原因无法返回正确格式的响应。



### 5.3 Mode 3 的正确架构



Mode 3 的安全决策和数据转发应该解耦：



text

```
请求帧
    → 安全检查（Router + Decision Engine）
        ├── 阻断 → 返回 BLOCKED 帧
        └── 通过 → 直接转发到真实目标
                   → 读取原始响应
                   → 帧封装回传给客户端
请求帧
    → 安全检查（Router + Decision Engine）
        ├── 阻断 → 返回 BLOCKED 帧
        └── 通过 → 直接转发到真实目标
                   → 读取原始响应
                   → 帧封装回传给客户端
```



安全决策是同步的 — 要么通过，要么阻断。不需要异步队列、不需要 Sender、不需要 Waiter。



`DM.Enqueue()` 仅用于获取决策结果（通过 Future 同步等待），不使用其 OutputBuffer 投递功能。安全检查通过后，`Listener` 直接通过 `net.Dial()` 连接真实目标，发送原始字节，读取原始响应，帧封装后通过 TLS 回传。



这样设计的优势：



| 维度     | 说明                                    |
| -------- | --------------------------------------- |
| 协议透明 | 原始请求和响应原封不动转发，不限于 HTTP |
| 延迟低   | 不经过 OutputBuffer/Sender 的异步链路   |
| 实现简单 | 不依赖 Waiter 的超时和注册机制          |
| 故障隔离 | Sender 的 bug 不影响 Mode 3             |



------



## 六、踩坑记录



### 6.1 指纹归一化：空字符串 vs nil



**现象：** 设备已注册但指纹匹配始终失败。



**根因：** 指纹树的 `Match()` 和 `registerInMemory()` 中，空字符串 `""` 和 `nil` 被映射为不同的 key。注册时 `device-tool` 传入 `os=""`（空字符串），树里第一层 key 是 `""`；匹配时 Mode 3 传入 `os=nil`，树里查找的 key 是 `"null"`。`"" ≠ "null"` 导致第一层就匹配失败。



**修复：** 在树的遍历逻辑中统一归一化：



go

```
if val == nil || *val == "" {
    key = NullKey  // "null"
} else {
    key = *val
}
if val == nil || *val == "" {
    key = NullKey  // "null"
} else {
    key = *val
}
```



同时在 `lastNonNil` 的判断中加入 `*d != ""`，确保空字符串不被视为有效维度。



**教训：** Go 中 `nil` 和空字符串是不同的值。在做任何"无值"判断时，必须同时处理两种情况。



### 6.2 OS 默认值问题



**现象：** 指纹归一化修复后仍然匹配失败。



**根因：**`device-tool` 代码中有默认值逻辑：



go

```
if osType == "" {
    osType = "linux"
}
if osType == "" {
    osType = "linux"
}
```



即使不传 `-os` 参数，注册时也会写入 `os="linux"`。而 Mode 3 的握手包不包含 OS 信息，匹配时传 nil → 归一化为 `"null"`，与 `"linux"` 不匹配。



**修复：** tcplistener 匹配时固定传 `OS="linux"`，因为 Mode 3 的 LD_PRELOAD 机制天然限定在 Linux 平台。



### 6.3 EINPROGRESS 非阻塞连接



**现象：**`connect to proxy failed: Operation now in progress`，TLS 握手失败。



**根因：** curl 使用非阻塞 socket。`real_connect()` 对非阻塞 socket 立即返回 `-1`，`errno = EINPROGRESS`。原始代码将此视为失败直接返回，没有等待连接完成。



**修复：** 用 `select()` 等待连接完成，再用 `getsockopt(SO_ERROR)` 检查结果。由于 `EINPROGRESS` 只在非阻塞 socket 上出现，连接成功后需要切回阻塞模式（`fcntl F_SETFL ~O_NONBLOCK`），因为后续的 `SSL_connect()` 在阻塞模式下工作更稳定。



### 6.4 TLS 握手在非阻塞 Socket 上失败



**现象：**`connect to proxy completed` 之后 TLS 握手报错 `error:00000000:lib(0)::reason(0)`。



**根因：**`select()` 表明连接已建立，但 socket 仍处于非阻塞模式。OpenSSL 的 `SSL_connect()` 在非阻塞 socket 上行为不同，返回错误信息不明确。



**修复：** 在 `select()` 成功后、`tls_connect()` 之前，将 socket 设回阻塞模式：



c

```
int flags = fcntl(sockfd, F_GETFL, 0);
fcntl(sockfd, F_SETFL, flags & ~O_NONBLOCK);
int flags = fcntl(sockfd, F_GETFL, 0);
fcntl(sockfd, F_SETFL, flags & ~O_NONBLOCK);
```



### 6.5 write() 递归导致栈溢出



**现象：** curl 连接建立后发送 HTTP 请求时崩溃，或服务端收到 TLS 记录被拒绝。



**根因：**`write()` hook 调用 `frame_send()` → `SSL_write()` → OpenSSL 内部调用 `write(fd, tls_record)` → 触发我们的 `write()` hook → 无限递归。



这个问题在 TLS 握手阶段不会出现，因为握手时 fd 尚未加入 `conn_table`，`conn_table_get()` 返回 NULL，hook 直接走原始函数。递归只在握手完成、`conn_table_set()` 之后才触发。



**修复：** 使用 `__thread` 线程局部变量 `g_in_io` 作为递归保护标志。所有 I/O hook 检查该标志，如果当前正在 TLS I/O 中，则直接调用原始函数。



### 6.6 curl 调用 sendto() 而非 send()



**现象：** 即使 hook 了 `send()`，HTTP 请求仍然明文发送到 TLS socket，服务端拒绝。



**根因：** curl（基于 libcurl）在某些 libc 版本下实际调用 `sendto()` 而非 `send()`。`sendto()` 未被 hook，原始数据直接发到 fd=5（proxy server 的 TLS socket），TLS 层收到明文 HTTP 数据，判定为非法 TLS 记录，断开连接。



**验证方式：**



bash

```
strace -e trace=sendto,sendmsg,send,write curl http://...
strace -e trace=sendto,sendmsg,send,write curl http://...
```



**修复：** 同时 hook `sendto()` 和 `sendmsg()`，内部逻辑与 `send()` 相同。



### 6.7 curl 调用 readv() 读取响应



**现象：** 发送成功，但 curl 报错 `Received HTTP/0.9 when not allowed`。



**根因：** curl 读取 HTTP 响应时调用的是 `readv()`（scatter-gather read）而非 `read()`。`readv()` 未被 hook，curl 从 TLS socket 上直接读取，读到的是 TLS 记录而非 HTTP 响应明文，解析失败。



**修复：** hook `readv()`，将所有 `struct iovec` 的缓冲区拼接为一块，通过 `consume_recv_buf()` 读取，再写回各个 iov。



### 6.8 Mode 3 走 Sender 链路导致 URL 拼接错误



**现象：** 服务端日志显示 `Get "http://127.0.0.1:8080http//127.0.0.1:8080/api/test": EOF`。



**根因：** Mode 3 最初复用了 Mode 1/2 的 OutputBuffer → Sender → Waiter 链路。Sender 使用 `net/http` 客户端转发，内部的 URL 构造逻辑将 `TargetAddr` 和原始请求路径做了错误拼接。



**修复：** Mode 3 不走 OutputBuffer/Sender/Waiter。安全决策通过后，`Listener` 直接 `net.Dial()` 连接真实目标，发送原始请求字节，读取原始响应字节。决策和转发完全解耦。



------



## 七、配置



### 7.1 服务端配置



在 `server.yaml` 中新增 `direct_connect` 配置段：



yaml

```
direct_connect:
  enabled: true
  listen_addr: ":9999"
  cert_file: "certs/server.crt"
  key_file: "certs/server.key"
direct_connect:
  enabled: true
  listen_addr: ":9999"
  cert_file: "certs/server.crt"
  key_file: "certs/server.key"
```



### 7.2 客户端使用



bash

```
# 设置环境变量
export THRESHOLD_PROXY_HOST=192.168.1.100  # 代理服务器地址
export THRESHOLD_PROXY_PORT=9999           # 代理服务器端口
export THRESHOLD_CA_CERT=/path/to/ca.crt   # CA 证书路径
export THRESHOLD_DEVICE_UUID=my-device     # 设备 UUID（可选）

# 注入库
LD_PRELOAD=/path/to/threshold.so curl http://example.com/api
# 设置环境变量
export THRESHOLD_PROXY_HOST=192.168.1.100  # 代理服务器地址
export THRESHOLD_PROXY_PORT=9999           # 代理服务器端口
export THRESHOLD_CA_CERT=/path/to/ca.crt   # CA 证书路径
export THRESHOLD_DEVICE_UUID=my-device     # 设备 UUID（可选）

# 注入库
LD_PRELOAD=/path/to/threshold.so curl http://example.com/api
```



------



## 八、测试验证



### 8.1 测试工具



- `tools/tcpcheck/main.go` — Go 编写的协议测试客户端，模拟 `libthreshold.so` 的行为，用于验证服务端 TLS + 握手 + 帧协议
- `libthreshold/build/test_client` — C 编写的测试客户端，用于验证 `.so` 的 hook 生效



### 8.2 测试链路



text

```
终端 1: python3 -m http.server 8080        ← 目标 HTTP 服务
终端 2: go run cmd/server/main.go          ← Threshold Server
终端 3: go run tools/tcpcheck/main.go      ← 协议验证
终端 4: LD_PRELOAD=... curl ...            ← 完整链路验证
终端 1: python3 -m http.server 8080        ← 目标 HTTP 服务
终端 2: go run cmd/server/main.go          ← Threshold Server
终端 3: go run tools/tcpcheck/main.go      ← 协议验证
终端 4: LD_PRELOAD=... curl ...            ← 完整链路验证
```



### 8.3 已验证的功能



| 功能                         | 状态 |
| ---------------------------- | ---- |
| TLS 双向加密通道             | ✅    |
| 二进制握手包协议             | ✅    |
| 设备指纹校验（六层 Hash 树） | ✅    |
| Router 分级（L0-L3）         | ✅    |
| Decision Engine 评估         | ✅    |
| HTTP 请求转发                | ✅    |
| HTTP 响应回传                | ✅    |
| 非阻塞 socket 处理           | ✅    |
| 递归 hook 保护               | ✅    |
| 未注册设备阻断               | ✅    |
| curl 完整链路                | ✅    |



------



## 九、已知限制与后续工作



### 9.1 当前限制



| 限制                 | 说明                                                         |
| -------------------- | ------------------------------------------------------------ |
| 仅支持 Linux         | LD_PRELOAD 是 Linux 专属机制                                 |
| 仅支持请求-响应      | 不支持长连接（WebSocket、SSH、数据库连接）                   |
| 每次请求独立连接目标 | 不复用到目标服务器的 TCP 连接                                |
| 无 mTLS              | 原型阶段仅服务端证书，生产阶段需升级为双向 TLS               |
| 决策粒度为连接级     | 每个请求帧都过 Router + Decision，但行为分析仅在连接建立时评估 |



### 9.2 后续工作



1. 1.**长连接支持** — 适配 WebSocket、SSH 等场景
2. 2.**mTLS 升级** — 客户端证书认证，设备拉黑通过吊销证书实现
3. 3.**连接复用** — 同一目标地址复用 TCP 连接
4. 4.**性能基准测试** — 对比 Mode 1/2 的延迟和吞吐
5. 5.**配置文件化** — proxy 地址、CA 路径等从配置文件读取（当前为环境变量）