
# libthreshold 项目文档

## 1. 项目简介

libthreshold 是一个 Linux 共享库（.so），通过 LD_PRELOAD 机制注入到任意 C 程序中，拦截网络系统调用（connect / read / write / send / recv / close），将 TCP 流量透明地转发到一个 TLS 代理服务器。

核心思路：应用程序不知道代理的存在，它照常调用 connect()，但 libthreshold 拦截该调用，改为连接代理服务器，建立 TLS 通道，并通过自定义握手协议告知代理原本想连谁，由代理代为转发。

---

## 2. 编译环境准备

安装依赖（在 WSL 终端中执行）：

    sudo apt update
    sudo apt install -y gcc cmake make libssl-dev

验证安装：

    gcc --version
    cmake --version

---

## 3. 编译步骤

在项目根目录下执行：

    mkdir -p build && cd build
    cmake ..
    make -j12

编译成功后 build/ 目录下生成：

- threshold.so（共享库，用于 LD_PRELOAD 注入）
- test_client（测试客户端，验证 hook 是否生效）

注意：CMakeLists.txt 设置了 PREFIX ""，所以输出文件名是 threshold.so 而非 libthreshold.so。

---

## 4. 配置说明

通过环境变量配置，无需修改代码：

    THRESHOLD_PROXY_HOST    默认 127.0.0.1     代理服务器 IP
    THRESHOLD_PROXY_PORT    默认 9999          代理服务器端口
    THRESHOLD_CA_CERT       默认 certs/server.crt  CA 证书路径
    THRESHOLD_DEVICE_UUID   自动生成           设备标识，留空则读取 /etc/machine-id

---

## 5. 生成测试证书

    cd certs && bash generate.sh

生成 ca.crt（CA根证书）、server.crt（服务器证书）、server.key（服务器私钥）。

---

## 6. 测试方法

    # 终端1：启动 echo 服务
    ncat -l 8080
    
    # 终端2：注入库并运行测试客户端
    LD_PRELOAD=./build/threshold.so ./build/test_client 127.0.0.1 8080

看到 connect() intercepted 说明 hook 生效。

对任意程序注入：
    LD_PRELOAD=./build/threshold.so ./your_application

库会在程序启动时自动执行初始化（通过 __attribute__((constructor))），拦截所有后续的网络连接。

---

## 7. 架构与模块

目录结构：

    include/
      protocol.h    协议常量 + 握手包结构体
      config.h      配置（环境变量读取）
      device_uuid.h 设备 UUID 采集
      conn_table.h  fd到连接状态映射表
      tls_ctx.h     TLS 上下文管理
      framing.h     长度前缀帧读写
      handshake.h   握手协议
      hook.h        系统调用 hook 声明
    src/
      libthreshold.c  入口（预留空壳）
      config.c        配置加载
      device_uuid.c   UUID 采集
      conn_table.c    连接表管理
      tls_ctx.c       OpenSSL TLS 初始化
      framing.c       帧编解码
      handshake.c     握手包编解码
      hook.c          核心：系统调用拦截与重定向

模块调用流程：

    connect() -> hook.c 拦截 -> 连接代理 -> TLS握手 -> 发送握手包 -> 记录连接表 -> 返回fd
    write()   -> hook.c 拦截 -> 编帧 -> TLS加密发送到代理
    read()    -> hook.c 拦截 -> 从帧缓冲区解码 -> 返回给应用
    close()   -> hook.c 拦截 -> SSL_shutdown + 释放资源

各模块职责：

    hook.c        核心，通过 dlsym(RTLD_NEXT,...) 获取原始函数指针，覆盖 libc
    config.c      从环境变量读取代理配置
    device_uuid.c 采集设备 UUID
    conn_table.c  以 fd 为 key 的数组表，记录代理连接
    tls_ctx.c     初始化 OpenSSL，创建 SSL 对象
    framing.c     长度前缀帧协议 [4字节长度][payload]
    handshake.c   构造/解析握手包
    protocol.h    协议常量定义

---

## 8. 协议设计（Mode 3）

传输层：TLS over TCP

帧格式：
    客户端 -> 服务端：[Length: 4字节大端序][Payload]
    服务端 -> 客户端：[Status: 1字节][Length: 4字节大端序][Payload]

握手流程：
    1. 客户端发送：Magic(0x54 0x48) + Version(0x01) + UUID长度 + UUID + 地址族 + 端口 + IP
    2. 服务端回复：Status(0x00=OK / 0x01=BLOCKED / 0x02=RATE_LIMITED)

---

## 9. 在 CLion 中开发

    1. File -> Open -> 选择 libthreshold/ 目录
    2. CLion 自动识别 CMakeLists.txt
    3. Build -> Build Project (Ctrl+F9)

---

## 10. 常见问题

    Q: 编译报找不到 OpenSSL
    A: 安装 libssl-dev: sudo apt install libssl-dev
    
    Q: LD_PRELOAD 后程序崩溃
    A: 检查 threshold.so 和目标程序是否都是 64 位: file threshold.so
    
    Q: 看不到 hook 输出
    A: 日志输出到 stderr，确认 LD_PRELOAD 路径正确
    
    Q: 可以 hook HTTPS 吗
    A: 可以。库拦截 socket 层面的 connect/read/write，与应用层协议无关

---

## 11. 技术细节

初始化通过 __attribute__((constructor)) 在 hook.c 中完成，在 main() 之前自动执行。

dlsym(RTLD_NEXT, "connect") 获取 libc 中原始 connect 地址，保存在 real_connect 中。我们的 connect() 先做代理逻辑，不代理的连接走 real_connect()。

---

## 12. 错误处理策略

### 12.1 代理不可达

当 Threshold Server 无法连接时（TCP connect 失败、TLS 握手超时等），libthreshold 的行为取决于配置：

    THRESHOLD_FAIL_OPEN     默认 false     false=阻断，目标程序收到 ECONNREFUSED
                                              true=降级，走 real_connect() 直连目标

默认行为（FAIL_OPEN=false）：

    connect() 拦截
      -> 连接代理失败
      -> errno 设为 ECONNREFUSED
      -> 返回 -1 给目标程序
    
    目标程序看到的行为与"目标服务本身不在线"完全一致，不会 crash。

降级行为（FAIL_OPEN=true）：

    connect() 拦截
      -> 连接代理失败
      -> 调用 real_connect() 走原始连接
      -> 后续 read/write 不经过 TLS，直接透传
    
    注意：降级模式下安全校验完全绕过，仅用于调试或非敏感环境。

### 12.2 TLS 通信失败

连接已建立、TLS 通道已开通，但后续 SSL_read / SSL_write 出错：

    SSL_write 返回 <= 0：
      -> 检查 SSL_get_error()
      -> SSL_ERROR_ZERO_RETURN（对端正常关闭）-> 返回 0 给应用
      -> SSL_ERROR_SYSCALL（底层 socket 错误）-> 设置 errno，返回 -1
      -> 其他错误 -> 设置 errno = EIO，返回 -1
    
    SSL_read 返回 <= 0：
      -> 同上处理
      -> 确保不向应用返回未定义数据

### 12.3 握手协议失败

代理返回 Status != 0x00（OK）：

    Status 0x01 (BLOCKED)  -> errno = ECONNREFUSED，返回 -1
    Status 0x02 (RATE_LIMITED) -> errno = EAGAIN，返回 -1（应用可重试）
    未知状态码 -> errno = EIO，返回 -1

### 12.4 非代理连接的 fallback

以下情况不经过代理，直接调用 real_connect()：

    connect() 目标是 AF_UNIX（本地 socket）
    connect() 目标是 127.0.0.1 / ::1（环回地址，可配置是否代理）
    socket 类型不是 SOCK_STREAM（UDP 等不代理）
    THRESHOLD_PROXY_HOST 未配置或为空

---

## 13. 连接生命周期详细流程

### 13.1 connect 完整流程

    应用调用 connect(fd, addr, addrlen)
        |
        |-- 判断是否需要代理（地址族、目标地址、socket 类型）
        |       |
        |       |-- 不需要 -> real_connect(fd, addr, addrlen) -> 返回
        |       |
        |       |-- 需要代理 -> 继续
        |
        |-- real_connect(fd, proxy_addr)    // 连接代理服务器
        |
        |-- SSL_new + SSL_connect           // TLS 握手
        |
        |-- 发送握手包（Magic + Version + UUID + 目标地址）
        |
        |-- 接收握手响应（1 字节 Status）
        |       |
        |       |-- 0x00 OK -> 继续
        |       |-- 其他 -> 清理资源，返回 -1
        |
        |-- conn_table[fd] = { ssl, target_addr, ... }
        |
        |-- 返回 0 给应用

### 13.2 write / send 完整流程

    应用调用 write(fd, buf, len)
        |
        |-- 查 conn_table[fd]
        |       |
        |       |-- 未找到 -> real_write(fd, buf, len)  // 非代理连接
        |       |
        |       |-- 找到 -> 继续
        |
        |-- frame_encode(buf, len)          // 添加 4 字节长度前缀
        |
        |-- SSL_write(frame)                // TLS 加密发送到代理
        |
        |-- 返回应用原始写入的字节数

### 13.3 read / recv 完整流程

    应用调用 read(fd, buf, len)
        |
        |-- 查 conn_table[fd]
        |       |
        |       |-- 未找到 -> real_read(fd, buf, len)
        |       |
        |       |-- 找到 -> 继续
        |
        |-- 检查帧缓冲区是否有完整帧
        |       |
        |       |-- 有完整帧 -> frame_decode() -> 拷贝到 buf -> 返回字节数
        |       |
        |       |-- 数据不足 -> SSL_read() 读取更多数据 -> 解帧 -> 返回
        |
        |-- SSL_read 遇到错误 -> 按 12.2 处理

### 13.4 close 完整流程

    应用调用 close(fd)
        |
        |-- 查 conn_table[fd]
        |       |
        |       |-- 未找到 -> real_close(fd)
        |       |
        |       |-- 找到 -> 继续
        |
        |-- SSL_shutdown(ssl)               // TLS 关闭通知（先发后收）
        |-- SSL_free(ssl)                   // 释放 SSL 对象
        |-- conn_table[fd] = NULL           // 清除连接记录
        |-- 释放帧缓冲区
        |
        |-- real_close(fd)                  // 关闭底层 socket
    
    注意顺序：必须先 SSL_shutdown 再 real_close，否则对端收到的是 TCP RST
    而非 TLS close_notify，OpenSSL 会报 SSL_ERROR_SYSCALL。
    
    dup2 场景：
    目标程序可能调用 dup2() 复制 fd，此时 conn_table 需要同步更新。
    拦截 dup2()，如果 oldfd 在 conn_table 中，将记录复制到 newfd。

---

## 14. 线程安全

### 14.1 并发场景

目标程序可能多线程运行，以下操作可能并发发生：

    线程 A: connect(fd=5, ...)     线程 B: write(fd=3, ...)
    线程 C: read(fd=3, ...)        线程 D: close(fd=7, ...)

### 14.2 conn_table 加锁策略

    方案：读写锁（pthread_rwlock_t）
    
    connect / close   -> pthread_rwlock_wrlock   // 写操作，独占
    read / write      -> pthread_rwlock_rdlock   // 读操作，共享
    
    conn_table 采用固定大小数组（fd 值作为索引），读操作只是数组下标访问
    加读写锁后并发读几乎无竞争。

### 14.3 线程初始化

    dlsym 调用本身不是线程安全的。解决方案：
    
    __attribute__((constructor)) 阶段（main 之前，单线程环境）
      -> 调用 dlsym 预加载所有原始函数指针
      -> 保存在全局 static 变量中
      -> hook 函数直接使用预加载的指针，运行时不再调用 dlsym
    
    已预加载的函数：
      real_connect / real_read / real_write
      real_send / real_recv / real_close
      real_dup2 / real_dup3

### 14.4 OpenSSL 线程安全

    OpenSSL 1.1.0+ 内部已实现线程安全，每个 SSL 对象绑定到单个 fd，
    不同 fd 对应不同 SSL 对象，天然隔离，无需额外加锁。
    
    如需支持 OpenSSL 1.0.x，需手动设置 locking_callback（不推荐）。

---

## 15. 与 Threshold 生态的关系

### 15.1 定位

    Threshold Client（Go 实现）
      -> 基于 gRPC 的客户端，需要 IDV Client 主动连接
      -> 适用于可控的终端环境（IDV 场景）
    
    libthreshold（C 实现）
      -> 基于 LD_PRELOAD 的透明注入，目标程序无需修改
      -> 适用于任意 C/C++ 程序，无需对方配合
    
    两者是同一安全代理架构的不同接入方式，共享同一个 Threshold Server 后端。

### 15.2 对比

    维度                Threshold Client       libthreshold
    语言                Go                      C
    注入方式            gRPC 主动连接           LD_PRELOAD 注入
    目标程序            IDV Client              任意 C 程序
    目标程序需要修改    是（gRPC SDK）          否
    平台                跨平台                  Linux only
    代理协议            gRPC（EstablishConn）   Mode 3 自定义协议
    TLS                 gRPC 内置               OpenSSL 手动管理
    行为采集            Collector 组件          暂无（后续迭代）
    部署复杂度          需安装客户端            LD_PRELOAD 一行命令

### 15.3 协议兼容性

    libthreshold 使用 Mode 3 协议（自定义二进制协议 over TLS），与
    Threshold Server 的 gRPC 接入层对接时需要一个协议转换层。
    
    当前 Threshold Server 的 gRPC 接入层处理的是 Protobuf 编码的 RPC，
    libthreshold 发送的是自定义帧格式，两者不直接兼容。
    
    解决方案：
      方案 A：Threshold Server 新增 Mode 3 监听端口，独立于 gRPC 接入层
      方案 B：在 Threshold Client（Go）侧增加 Mode 3 -> gRPC 的转换代理
      方案 C：libthreshold 改用 gRPC 协议（增加 grpc-c 依赖，增加复杂度）
    
    推荐方案 A，保持 libthreshold 的轻量性。

---

## 16. 性能考量

### 16.1 开销来源

    开销项              量级              说明
    dlsym 查找          0（启动时预加载）  constructor 阶段完成，运行时无开销
    conn_table 查找     O(1)              数组下标访问，读写锁几乎无竞争
    TLS 加解密          ~1-3μs/次         取决于 cipher suite 和数据大小
    帧编解码            <1μs/次           memcpy + 4字节长度头
    代理网络延迟        取决于部署位置     同机 <0.1ms，跨机 1-10ms

### 16.2 已知限制

    - 每次 read/write 都会触发一次 SSL_read/SSL_write，对于高频小包
      场景（如数据库查询），性能损耗比例较高
    - 没有帧缓冲区复用，每次 read 都 malloc/free 帧缓冲区
    - conn_table 固定大小，默认 MAX_FD = 1024，超过需重新编译

### 16.3 优化方向（后续迭代）

    - 帧缓冲区对象池，减少 malloc/free
    - 合并小包：write 时攒多个小帧一次性 SSL_write
    - conn_table 使用 epoll fd 直接索引，避免额外查找
    - 零拷贝：对于大块数据（镜像上传），考虑 sendfile 拦截

---

## 17. 安全考量

### 17.1 LD_PRELOAD 的固有风险

    LD_PRELOAD 注入对 setuid 程序无效（glibc 安全机制自动忽略）。
    目标程序如果调用 execve() 执行子进程，子进程不会继承 LD_PRELOAD，
    除非显式设置环境变量。这意味着：
      - 子进程的网络连接不经过代理
      - 安全策略在 fork + exec 边界断裂
    
    缓解方案：配合 iptables/nftables 规则，禁止非代理的出站连接。

### 17.2 设备 UUID 采集

    默认从 /etc/machine-id 读取，如果该文件不存在或为空：
      -> 退化为 hostname hash
      -> 如果 hostname 也无法获取，生成随机 UUID 并缓存到
         $XDG_RUNTIME_DIR/.threshold_device_uuid
      -> 每次进程启动 UUID 一致（在同一会话内）

### 17.3 证书校验

    TLS 连接代理时默认校验服务端证书：
      - 使用 THRESHOLD_CA_CERT 指定的 CA 证书
      - 验证主机名匹配 THRESHOLD_PROXY_HOST
      - 不跳过校验（开发调试时可设置 THRESHOLD_TLS_INSECURE=1）

---

## 18. 调试指南

### 18.1 日志输出

    所有日志输出到 stderr，格式：
    
    [threshold] connect() intercepted: fd=5 -> 192.168.1.100:8080 (via proxy 127.0.0.1:9999)
    [threshold] handshake OK, device=abc123
    [threshold] write() intercepted: fd=5, 1024 bytes -> framed + TLS
    [threshold] close() intercepted: fd=5, SSL_shutdown done
    
    日志级别由环境变量控制：
    
    THRESHOLD_LOG_LEVEL     默认 1
      0 = 静默（仅错误）
      1 = 基本（连接建立/关闭）
      2 = 详细（每次 read/write）
      3 = 调试（帧内容 hex dump，慎用）

### 18.2 strace 配合调试

    strace -f -e trace=connect,read,write,close -o trace.log \
      LD_PRELOAD=./build/threshold.so ./your_application
    
    对比 strace 输出和 threshold 日志，确认 hook 位置是否正确。

### 18.3 验证 TLS 通道

    # 终端 1：启动 Mode 3 兼容的代理服务端
    # 终端 2：注入并运行
    LD_PRELOAD=./build/threshold.so curl http://example.com
    
    观察 stderr 输出确认 connect 被拦截、TLS 握手成功、数据帧转发正常。
