[toc]

### 本模块负责

| 能力                                    | 状态                             |
| --------------------------------------- | -------------------------------- |
| Router入口 + L0-L3静态分级              | 做                               |
| DispatchManager + Worker弹性伸缩        | 做                               |
| 六层Hash树指纹匹配 + WAL + bbolt        | 做                               |
| 以连接为单位的用户画像 + DECISION_RULES | 做                               |
| OutputBuffer + gRPC Notify              | 做                               |
| AlertQueue + 设备拉黑                   | 做                               |
| mTLS双向认证                            | 做（工程实现）                   |
| 跨设备关联画像接口（算法可扩展）        | 做，只定义接口，具体算法后续迭代 |

### 不在本模块做

| 项目                 | 归属       | 说明                                                         |
| -------------------- | ---------- | ------------------------------------------------------------ |
| 消息队列防打爆       | 基础设施层 | Router前挂消息队列，运维配置                                 |
| 可观测性             | 运维       | Prometheus + Grafana，部署阶段配                             |
| 分布式数据库替换     | 存储层     | PortraitStore接口抽象好了，换后端实现即可                    |
| 分布式事务           | 存储层     | 同上                                                         |
| 灰度发布             | 运维       | K8S滚动部署，应用本身无状态                                  |
| 日志审计             | 后续迭代   | 上线后补，接入统一存储底座后数据库安全交给别的模块           |
| 镜像沙箱扫描/修复    | CICD模块   | 独立服务，安全代理只负责在L1上传时通过gRPC触发扫描通知，不负责扫描本身 |
| 跨设备关联的具体算法 | 后续迭代   | 接口定义好，初期走简单规则，后续可以换更复杂的算法           |

```
┌─────────────────────────────────────────────────────┐
│                   安全代理模块                         │
│                                                      │
│  Router → DispatchManager → WorkerPool               │
│           ↓                    ↓                     │
│      弹性伸缩策略         指纹Hash树匹配               │
│                           用户画像评估                  │
│                           DECISION_RULES              │
│                           CrossDeviceCorrelator接口    │
│           ↓                    ↓                     │
│      OutputBuffer ←──── 通过                          │
│      AlertQueue  ←──── 阻断                          │
│           ↓              ↓                           │
│      gRPC Notify    gRPC Alert                       │
│           ↓              ↓                           │
│      mTLS加密通道      设备拉黑                       │
└───────┬──────────────────┬───────────────────────────┘
        │                  │
        │ 触发扫描          │ 回调结果
        ▼                  │
┌───────────────┐          │
│  CICD模块      │──────────┘
│  沙箱扫描/修复  │
└───────────────┘
        ▲
        │ 拉取已通过消息
        │
┌───────┴───────┐
│  OpenStack    │
└───────────────┘
        ▲
        │ 读audit.log
        │
┌───────┴───────┐
│  Flask应用     │
└───────────────┘
```

## 3.1 客户端架构与数据流



### 3.1.1 架构概述

安全代理客户端部署于用户终端设备之上，作为原生IDV客户端与云平台之间的透明中间层。其核心设计目标是：在不修改原生客户端代码的前提下，对所有发往OpenStack服务端的流量进行截获、身份附加与加密传输。客户端由三个独立运行的组件构成——重定向模块、行为采集进程与本地代理服务，三者通过进程间通信协作完成流量的安全处理。

客户端整体采用旁路拦截的设计思路。重定向模块工作于操作系统网络栈层面，将原生客户端发往云平台的流量重定向至本地代理服务的监听端口；行为采集进程独立运行，持续监控用户在本次连接中的操作行为并生成行为摘要标签；本地代理服务接收被重定向的原始请求后，在HTTP Header中附加设备指纹与行为摘要，随后通过gRPC建立的mTLS加密通道将请求发送至服务端代理。

### 3.1.2 数据流

客户端处理单个请求的完整数据流如图所示：

```
原生IDV客户端
    │
    │ HTTP明文请求（发往OpenStack）
    │
    ▼
┌──────────────────────────┐
│  重定向模块                │
│                          │
│  • PAC脚本（浏览器场景）   │
│  • proxychains（命令行）   │
│                          │
│  将目标地址重写为           │
│  localhost:8080           │
└──────────┬───────────────┘
           │
           ▼
┌──────────────────────────┐
│  本地代理服务              │
│                          │
│  ① 接收原始HTTP请求       │
│  ② 查询行为采集进程        │
│     获取当前OpTag          │
│  ③ 附加X-Proxy-*字段      │
│     （UUID, IP, OS,       │
│      Port, Protocol,      │
│      Reserved, OpTag,     │
│      Timestamp）           │
│  ④ 通过gRPC+mTLS         │
│     发送至服务端            │
└──────────┬───────────────┘
           │
           │ gRPC Stream（mTLS加密）
           │
           ▼
      服务端代理
           │
           │ gRPC Stream（mTLS加密）
           │
           ▼
┌──────────────────────────┐
│  本地代理服务（响应回路）    │
│                          │
│  ⑤ 接收服务端加密响应      │
│  ⑥ 解密                   │
│  ⑦ 剥离X-Proxy-*字段      │
│  ⑧ 还原为原始HTTP响应      │
└──────────┬───────────────┘
           │
           ▼
原生IDV客户端（收到正常响应）
```



### 3.1.3 重定向模块

重定向模块负责将原生客户端发往云平台的流量透明地转发至本地代理服务。本文针对三种用户访问场景分别设计了对应的重定向方案。

**浏览器访问场景**：通过PAC（Proxy Auto-Config）脚本实现。PAC脚本部署于局域网内某台服务器的IIS服务上，浏览器代理配置指向该脚本的URL地址。脚本内部根据请求的目标地址判断是否需要代理——仅当目标匹配云平台地址时才进行重定向，其余流量直连放行，避免代理对非云平台流量产生不必要的干扰。

**命令行工具访问场景**：通过proxychains工具实现。proxychains通过`LD_PRELOAD`机制劫持进程的socket系统调用，将所有TCP连接重定向至配置文件中指定的代理地址。使用时只需在命令前添加`proxychains4`前缀，对原有命令行操作无侵入。

**自研应用访问场景**：通过配置环境变量`LD_LIBRARY_PATH`实现。该环境变量用于指定系统默认动态链接库路径之外的其他查找路径，在程序加载运行期间生效，且优先级高于系统默认路径。通过在应用启动脚本中设置该变量，可以用代理系统封装的重定向动态链接库替换原本的系统动态链接库，从而实现请求截获。原型阶段暂不采用该方案，生产阶段根据实际需求决定是否实现。

### 3.1.4 行为采集进程

行为采集进程以独立线程运行于客户端本地，负责记录用户在本次连接中的全部操作行为。该进程维护一个内存中的事件列表，每当原生客户端发起一个请求时，本地代理服务调用行为采集进程记录该请求的操作类型（由HTTP方法和路由路径映射得到）及时间戳。行为采集进程还负责生成行为摘要标签（OpTag），该标签反映了当前连接中截至目前的操作风险概览，作为附加字段写入每个请求的HTTP Header中。

行为采集进程的设计权衡在于：**是否需要在客户端侧做复杂的行为分析**。本文选择在客户端侧仅做事件记录与OpTag生成，不做决策判断。原因是客户端处于不可信环境，行为分析与决策应由服务端统一执行，客户端仅承担数据采集职能。这种设计也使得客户端保持轻量，降低了对终端设备的性能影响。

### 3.1.5 本地代理服务

本地代理服务是客户端的核心组件，承担请求截获、字段附加、加密传输与响应回传四项职能。

**指纹附加**：本地代理服务接收到重定向模块转发的原始HTTP请求后，在请求的HTTP Header中追加一组`X-Proxy-*`字段。完整的设备指纹由六项信息组成：UUID（设备唯一标识）、OS（操作系统类型）、IP（客户端IP地址）、Port（源端口）、Protocol（协议类型）、Reserved（保留字段）。其中UUID由客户端首次启动时采集并写入本地配置文件，后续启动时直接读取不再重复采集。指纹字段中可能存在的缺省项标记为null值，服务端指纹匹配时跳过对应层级。

**加密传输**：本地代理服务通过gRPC协议与服务端通信，底层传输通道采用mTLS双向认证。原型阶段使用自签名证书实现单向TLS（服务端证书、客户端跳过验证），生产阶段升级为双向TLS，客户端也需持有由CA签发的客户端证书。gRPC的使用使得通信接口由Protocol Buffers定义，具备天然的跨语言兼容性和版本管理能力。

**响应回传**：服务端返回的响应经过gRPC加密通道传输至客户端后，本地代理服务剥离自定义的`X-Proxy-*`字段，将响应还原为原始HTTP格式后交还给原生客户端。对于持续传输类请求（如镜像上传），数据沿着已建立的gRPC流持续传输，客户端与服务端之间的通信全程加密。

### 3.1.6 客户端设计权衡

客户端架构的设计涉及以下关键权衡：

**透明性与功能性的权衡**：为了不修改原生客户端代码，代理必须在网络层进行截获。这意味着代理无法获取原生客户端的业务上下文（如当前操作的具体含义），只能通过HTTP方法和路由路径来推断操作类型。本文认为这种抽象层级是足够的，因为OpenStack的RESTful API设计使得每个操作都可以通过方法和路径唯一确定。

**客户端可信度的权衡**：客户端运行在用户设备上，用户可能篡改客户端组件、伪造指纹信息或绕过代理直连服务端。本文通过以下措施缓解该风险：服务端对指纹信息进行签名校验（生产阶段），防止篡改；服务端验证UUID是否已注册，防止伪造；服务端可配置为仅接受来自已知客户端IP段的连接。但从根本上说，零信任架构下客户端不可完全信任，因此决策逻辑必须在服务端执行，客户端仅负责数据采集与传输。

**独立进程vs嵌入式采集的行为采集设计权衡**：行为采集进程设计为独立进程而非嵌入到本地代理服务中，原因是独立进程崩溃不会影响代理服务的核心转发功能，且独立进程便于单独升级和维护。代价是增加了进程间通信的复杂性，但在原型阶段该代价可以接受。

------



## 3.2 服务端架构与数据流

### 3.2.1 架构概述

安全代理服务端部署于独立服务器之上，作为客户端与OpenStack之间的安全网关。与客户端的轻量设计不同，服务端承担了整个安全代理系统最核心的职责——流量解密、设备身份校验、用户行为评估与访问控制决策。

服务端由六个组件构成：gRPC接入层、Router、DispatchManager与WorkerPool、指纹匹配引擎、用户画像与决策引擎、OutputBuffer与AlertQueue。所有组件运行于同一进程内，通过内存中的channel和队列进行通信，避免了引入外部消息中间件带来的运维复杂度。组件之间的通信接口由Protocol Buffers定义，未来如需拆分为独立服务，仅需将内存channel替换为gRPC调用，上层逻辑无需修改。

### 3.2.2 数据流

服务端处理单个请求的完整数据流如图所示：

```
客户端代理
    │
    │ gRPC Stream（mTLS加密）
    │
    ▼
┌─────────────────────────────────────────────────────┐
│  gRPC接入层                                           │
│  • TLS终止                                           │
│  • 请求反序列化                                       │
│  • 基础限流（令牌桶）                                  │
└──────────────────────┬──────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────┐
│  Router                                              │
│  • 读取gRPC方法路径和HTTP方法                          │
│  • 查OPERATION_RISK静态映射表                          │
│  • 判定操作风险等级 L0 / L1 / L2 / L3                  │
└──────────┬─────────────────────┬────────────────────┘
           │                     │
    L0 只读查询              L1/L2/L3
           │                     │
           ▼                     ▼
    直接穿透至                ┌──────────────┐
    OutputBuffer            │ DispatchManager│
           │                │                │
           │                │ ① 消息入队      │
           │                │ ② 检查队列深度   │
           │                │ ③ 弹性伸缩判断   │
           │                └───────┬────────┘
           │                        │
           │                        ▼
           │                ┌────────────────────────┐
           │                │      WorkerPool         │
           │                │                         │
           │                │  Worker1 ←┐             │
           │                │  Worker2 ←─┤ 竞争消费    │
           │                │  ...       │             │
           │                │  WorkerN ←─┘             │
           │                └────────┬────────────────┘
           │                         │
           │                ┌────────┴────────┐
           │                │                 │
           │         每个Worker内部：          │
           │                │                 │
           │                ▼                 │
           │    ┌─────────────────────┐       │
           │    │ ① 指纹Hash树匹配     │       │
           │    │    匹配失败 → Alert  │       │
           │    │                     │       │
           │    │ ② 加载用户画像       │       │
           │    │    当前ConnectionCtx │       │
           │    │    + 历史画像摘要    │       │
           │    │                     │       │
           │    │ ③ DECISION_RULES    │       │
           │    │    逐条匹配         │       │
           │    │    命中第一条即停    │       │
           │    └────────┬────────────┘       │
           │             │                    │
           │      ┌──────┴──────┐             │
           │      │             │             │
           │    通过          阻断             │
           │      │             │             │
           │      ▼             ▼             │
           │  OutputBuffer  AlertQueue        │
           │      │             │             │
           │      │      L3额外触发           │
           │      │      设备拉黑             │
           │      │             │             │
           └──────┼─────────────┼─────────────┘
                  │             │
                  ▼             ▼
           gRPC Notify    gRPC Alert
           (下游拉取)      (告警通知)
                  │
                  ▼
           OpenStack
```

连接生命周期的完整数据流如图所示：

```
连接建立
    │
    ├── ① 创建ConnectionContext
    ├── ② 从DB加载该用户的历史画像摘要
    ├── ③ gRPC notify下游："user_id新连接建立"
    │
    ▼
连接存续期间
    │
    ├── 每个请求按上述流程处理
    ├── 通过的事件追加到ConnectionContext.events
    ├── 每次决策同时读取ConnectionContext和历史摘要
    │
    ▼
连接断开
    │
    ├── ① ConnectionContext序列化
    ├── ② 事务写入DB（WAL + 持久化存储）
    │       • 追加连接摘要到该用户的事件链
    │       • 更新设备最后活跃时间
    ├── ③ 更新该用户的历史画像摘要（供下次连接使用）
    ├── ④ 释放内存
    └── ⑤ gRPC notify下游："user_id连接已关闭"
```

## 3.3 服务端各环节详细设计与权衡

### 3.3.1 gRPC接入层

#### 基本原理

gRPC接入层是服务端对外暴露的唯一网络入口，承担TLS终止、请求反序列化与基础限流三项职能。所有来自客户端的gRPC Stream在此处完成TLS握手，将密文还原为明文Protocol Buffers消息，再交由下游Router处理。

接入层通过gRPC拦截器（Interceptor）机制实现横切关注点的注入，而非在业务代码中硬编码。拦截器链的执行顺序为：TLS验证 → 限流检查 → 请求反序列化 → 交由Router。

```protobuf
// 通信接口定义
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

message ProxyRequest {
    string connection_id = 1;
    string device_uuid = 2;
    string user_id = 3;
    bytes raw_http_request = 4;       // 原始HTTP请求（已附加X-Proxy-*字段）
    map<string, string> metadata = 5; // 附加元数据
    int64 timestamp = 6;
}

message ProxyResponse {
    string connection_id = 1;
    bytes raw_http_response = 2;      // HTTP响应
    enum Status {
        OK = 0;
        BLOCKED = 1;
        BLACKLISTED = 2;
        RATE_LIMITED = 3;
    }
    Status status = 3;
    string reason = 4;
}
```

#### 技术点1：基础限流

接入层实现令牌桶限流，作为全局流量的第一道闸门。限流的目标不是精确控制，而是防止瞬时流量将下游DispatchManager和WorkerPool打穿。限流粒度为全局限流（不区分用户），因为更细粒度的限流由Router和决策引擎在业务层实现。

令牌桶参数的设定需要权衡安全性与用户体验：桶容量过小会导致正常用户请求被误限，过大则失去了限流的防护意义。本文在原型阶段设定为每秒1000个请求，桶容量2000，生产阶段根据实际流量监控数据调整。

```
class TokenBucketLimiter:
    def __init__(self, rate: int, capacity: int):
        self.rate = rate              # 每秒产生的令牌数
        self.capacity = capacity      # 桶容量
        self.tokens = capacity        # 当前令牌数
        self.last_refill = time.monotonic()
        self.lock = threading.Lock()

    def allow(self) -> bool:
        with self.lock:
            now = time.monotonic()
            elapsed = now - self.last_refill
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
            self.last_refill = now
            if self.tokens >= 1:
                self.tokens -= 1
                return True
            return False
```

#### 技术点2：mTLS双向认证

原型阶段采用单向TLS：服务端持有证书和私钥，客户端跳过证书验证（`ssl.CERT_NONE`）。生产阶段升级为双向TLS后，客户端也需持有由CA签发的客户端证书，服务端在TLS握手阶段验证客户端证书的合法性。被拉黑的设备通过吊销其客户端证书实现永久拒绝，无需依赖应用层的黑名单检查。

```
# 生产阶段的服务端TLS配置
class SecureGRPCServer:
    def __init__(self, cert_path, key_path, ca_path):
        with open(cert_path, 'rb') as f:
            server_cert = f.read()
        with open(key_path, 'rb') as f:
            server_key = f.read()
        with open(ca_path, 'rb') as f:
            ca_cert = f.read()

        server_credentials = grpc.ssl_server_credentials(
            [(server_key, server_cert)],
            root_certificates=ca_cert,
            require_client_auth=True,  # 生产阶段要求客户端证书
        )
```

#### 设计权衡：接入层不做业务判断

接入层仅负责"能不能进来"（TLS验证、限流），不负责"进来之后怎么办"（操作风险判定、行为评估）。这一设计的权衡在于：如果在接入层就做业务判断，可以更早地拒绝非法请求，节省下游计算资源。但代价是接入层逻辑变重，与业务耦合，难以独立升级和扩展。本文选择保持接入层轻量，将所有业务判断下沉至Router和Worker层，接入层仅作为协议边界和流量闸门。



------



### 3.3.2 Router

#### 基本原理

Router接收gRPC接入层反序列化后的请求消息，根据gRPC方法路径和原始HTTP请求中的方法与路由，查OPERATION_RISK静态映射表，判定操作风险等级。

```
class Router:
    def __init__(self, operation_risk: dict, dispatch_manager: DispatchManager):
        self.operation_risk = operation_risk    # 静态风险映射表
        self.dispatch = dispatch_manager

    async def route(self, message: ProxyRequest) -> ProxyResponse:
        # 提取操作标识
        op_key = self._extract_op_key(message)

        # 查静态映射表
        risk_level = self.operation_risk.get(op_key, L1)  # 默认L1

        if risk_level == L0:
            # 直接穿透，不入队
            await self.dispatch.direct_pass(message)
            return ProxyResponse(status=OK)

        # L1及以上，入队交由Worker处理
        decision = await self.dispatch.enqueue(message, risk_level)
        return self._build_response(decision)

    def _extract_op_key(self, message: ProxyRequest) -> str:
        """从原始HTTP请求中提取方法和路径，组装为操作标识"""
        http_request = parse_raw_http(message.raw_http_request)
        method = http_request.method  # GET, POST, DELETE, PUT, ...
        path = http_request.path      # /api/cloud/public/images/download
        return f"{method} {path}"
```



#### 技术点：路径模糊匹配

OPERATION_RISK映射表中的路径可能包含通配符（如`/api/local/images/*/sync`），Router需要支持通配符匹配。本文采用正则表达式预编译的方式：将映射表中的路径模式在初始化时编译为正则表达式，运行时直接匹配，避免每次请求都做字符串解析。

```
class OperationRiskTable:
    def __init__(self, risk_rules: dict):
        self.compiled = []
        for pattern, level in risk_rules.items():
            # "/api/local/images/*/sync" → "^/api/local/images/[^/]+/sync$"
            regex = re.compile(
                "^" + re.escape(pattern).replace(r"\*", "[^/]+") + "$"
            )
            self.compiled.append((regex, level))

    def lookup(self, method: str, path: str) -> int:
        key = f"{method} {path}"
        for regex, level in self.compiled:
            if regex.match(key):
                return level
        return L1  # 未知操作默认L1，宁可误审不漏放
```

#### 设计权衡：未知操作的风险定级

对于映射表中不存在的操作，Router将其默认定级为L1（写操作，需审计）而非L0（直接放行）。这是基于安全原则的保守选择：未知操作应被审慎对待，交由Worker进一步分析，而非直接穿透。代价是新增API端点时需要同步更新映射表，否则新端点的请求都会进入Worker队列，增加不必要的处理开销。本文认为这个代价是可接受的，因为新增API端点本身就是低频操作，同步更新映射表的成本很低。

------



### 3.3.3 DispatchManager与WorkerPool

#### 基本原理

DispatchManager是服务端的调度中枢，管理WorkerPool的生命周期，根据负载动态伸缩Worker数量，并将Router分发的消息路由至Worker处理。Worker是无状态的处理单元，多个Worker通过竞争消费共享消息队列，天然实现负载均衡。

```
┌─────────────────────────────────────────┐
│             DispatchManager              │
│                                          │
│  ┌──────────────────────────────────┐   │
│  │       SharedMessageQueue          │   │
│  │  (asyncio.Queue, bounded)         │   │
│  └───────────────┬──────────────────┘   │
│                  │                       │
│    ┌─────────────┼─────────────┐        │
│    ▼             ▼             ▼        │
│ ┌──────┐   ┌──────┐   ┌──────┐        │
│ │Worker│   │Worker│   │Worker│        │
│ │  1   │   │  2   │   │  N   │        │
│ └──┬───┘   └──┬───┘   └──┬───┘        │
│    │          │          │              │
│    ▼          ▼          ▼              │
│ ┌──────────────────────────────┐       │
│ │     OutputBuffer              │       │
│ │     AlertQueue                │       │
│ └──────────────────────────────┘       │
│                                          │
│  ┌──────────────────────────────────┐   │
│  │       PoolPolicy                   │   │
│  │  • min_workers: 2                  │   │
│  │  • max_workers: 64                 │   │
│  │  • scale_up_threshold: 100         │   │
│  │  • scale_down_idle_sec: 30         │   │
│  └──────────────────────────────────┘   │
└─────────────────────────────────────────┘
```



#### 技术点1：弹性伸缩

DispatchManager维护一个后台协程`monitor_loop`，每5秒检查一次WorkerPool状态。扩容条件为消息队列深度超过阈值且当前Worker数未达上限，缩容条件为Worker空闲时间超过阈值且当前Worker数高于下限。

```
class DispatchManager:
    def __init__(self, policy: PoolPolicy, fingerprint_tree, portrait_store,
                 output_buffer, alert_queue):
        self.policy = policy
        self.message_queue = asyncio.Queue(maxsize=policy.max_queue_size)
        self.workers: list[Worker] = []
        self.output_buffer = output_buffer
        self.alert_queue = alert_queue
        self.fingerprint_tree = fingerprint_tree
        self.portrait_store = portrait_store
        self.next_worker_id = 0

    async def enqueue(self, message: ProxyRequest, risk_level: int) -> Decision:
        """Router调用，将消息入队并返回决策结果"""
        future = asyncio.Future()
        await self.message_queue.put((message, risk_level, future))
        await self.maybe_scale_up()
        return await future  # 阻塞等待Worker处理完成

    async def direct_pass(self, message: ProxyRequest):
        """L0直接穿透"""
        await self.output_buffer.put(message)

    async def maybe_scale_up(self):
        if len(self.workers) >= self.policy.max_workers:
            return
        if self.message_queue.qsize() < self.policy.scale_up_threshold:
            return
        # 每次扩容step个Worker
        for _ in range(self.policy.scale_up_step):
            if len(self.workers) >= self.policy.max_workers:
                break
            worker = Worker(
                id=self.next_worker_id,
                input_queue=self.message_queue,
                output_buffer=self.output_buffer,
                alert_queue=self.alert_queue,
                fingerprint_tree=self.fingerprint_tree,
                portrait_store=self.portrait_store,
            )
            self.next_worker_id += 1
            self.workers.append(worker)
            asyncio.create_task(worker.run())

    async def monitor_loop(self):
        """后台监控协程"""
        while True:
            # 移除已退出的Worker
            self.workers = [w for w in self.workers if w.alive]

            # 缩容：空闲Worker过多时回收
            idle_workers = [w for w in self.workers if w.is_idle()]
            target = max(self.policy.min_workers,
                         len(self.workers) - len(idle_workers) + self.policy.scale_up_step)
            for w in idle_workers[:max(0, len(self.workers) - target)]:
                await w.shutdown()
            self.workers = [w for w in self.workers if w.alive]

            await asyncio.sleep(self.policy.health_check_interval_sec)
```



#### 技术点2：Worker内部处理流程

```
class Worker:
    def __init__(self, id, input_queue, output_buffer, alert_queue,
                 fingerprint_tree, portrait_store):
        self.id = id
        self.input_queue = input_queue
        self.output_buffer = output_buffer
        self.alert_queue = alert_queue
        self.fingerprint_tree = fingerprint_tree
        self.portrait_store = portrait_store
        self.alive = True
        self.last_active = time.monotonic()
        self.idle_timeout = 30  # 秒

    async def run(self):
        while self.alive:
            try:
                message, risk_level, future = await asyncio.wait_for(
                    self.input_queue.get(), timeout=self.idle_timeout
                )
                self.last_active = time.monotonic()

                # Step 1: 指纹匹配
                fingerprint = extract_fingerprint(message)
                if not self.fingerprint_tree.match(fingerprint):
                    future.set_result(Decision(action=BLOCK, reason="fingerprint_mismatch"))
                    await self.alert_queue.put(AlertResult(message, "fingerprint_mismatch"))
                    continue

                # Step 2: 加载用户画像
                ctx = message.connection_context
                history = self.portrait_store.get_history(ctx.user_id)

                # Step 3: 决策引擎评估
                decision = evaluate_rules(ctx, history, risk_level)

                # Step 4: 根据决策结果分发
                if decision.action in (BLOCK_DEVICE, BLACKLIST, BLOCK_LOGIN):
                    future.set_result(decision)
                    await self.alert_queue.put(AlertResult(message, decision))
                    if decision.action == BLACKLIST:
                        self.portrait_store.blacklist(ctx.device_uuid)
                else:
                    # 记录事件到ConnectionContext
                    ctx.record_event(extract_op_type(message))
                    future.set_result(decision)
                    await self.output_buffer.put(message)

            except asyncio.TimeoutError:
                # Worker空闲，标记时间
                pass
            except Exception as e:
                logging.error(f"Worker {self.id} error: {e}")
                if not future.done():
                    future.set_result(Decision(action=BLOCK, reason=f"internal_error: {e}"))

    def is_idle(self):
        return time.monotonic() - self.last_active > self.idle_timeout

    async def shutdown(self):
        self.alive = False
```

#### 设计权衡：同步结果返回 vs 异步Fire-and-Forget

Worker处理完成后通过`Future`将决策结果同步返回给Router，Router再将结果返回给客户端。这种设计使得客户端能够立即知道请求是否被放行。替代方案是fire-and-forget——Worker处理完成后只管投递到OutputBuffer，客户端不等待决策结果。本文选择同步返回，原因是客户端需要根据服务端的响应决定后续操作（如被拒绝时提示用户），异步方案下客户端无法获得即时反馈。

但同步返回也引入了一个问题：Router调用`enqueue`后会阻塞等待Future完成，如果Worker处理耗时较长（如涉及镜像安全扫描），Router协程会被占用。对此的缓解措施是：L0穿透不入队不阻塞；L1的审计类操作处理速度快，阻塞时间短；真正耗时的操作（如异步扫描）由CICD模块独立执行，Worker只需触发扫描任务即可立即返回。



------



### 3.3.4 指纹匹配引擎

#### 基本原理

指纹匹配引擎对请求中携带的六维设备指纹进行快速校验，判断该设备是否为已注册的合法设备。引擎采用六层Hash树结构，每层对应指纹的一个维度，从UUID层开始逐层哈希匹配，最坏情况的时间复杂度为O(7)。

#### 技术点1：六层Hash树结构

```
Level 0: UUID层
    每个已注册设备的UUID哈希映射到一个bucket
    bucket内存储该设备的下一维度索引指针
    │
    ├── uuid_a → Level 1 bucket set A
    ├── uuid_b → Level 1 bucket set B
    └── ...

Level 1: OS层
    操作系统类型（linux/windows/macos）的哈希
    │
Level 2: IP层
    客户端IP地址的哈希
    │
Level 3: Port层
    源端口的哈希
    │
Level 4: Protocol层
    协议类型的哈希
    │
Level 5: Reserved层
    保留字段的哈希（当前为空，预留扩展）
```

匹配算法从Level 0开始，每层取出对应维度的值计算哈希，在该层的哈希表中查找。如果当前维度的值为null（该字段缺省），则跳过该层继续下一层。如果任意一层查找失败，判定为指纹不匹配。

```
class FingerprintTree:
    def __init__(self, db_backend):
        self.levels = 6
        self.backend = db_backend  # bbolt或其他KV存储
        # 初始化时从持久化存储加载树结构到内存

    def match(self, fingerprint: dict) -> bool:
        """六层匹配，任一层失败返回False"""
        dimensions = [
            fingerprint.get("uuid"),
            fingerprint.get("os"),
            fingerprint.get("ip"),
            fingerprint.get("port"),
            fingerprint.get("protocol"),
            fingerprint.get("reserved"),
        ]

        current_node = self.root
        for i, value in enumerate(dimensions):
            if value is None or value == "":
                # 缺省字段，跳过该层
                continue

            key = f"L{i}:{value}"
            child = current_node.children.get(key)
            if child is None:
                return False
            current_node = child

        return current_node.is_registered  # 到达叶子且标记为已注册

    def register(self, fingerprint: dict):
        """注册新设备指纹"""
        dimensions = [
            fingerprint.get("uuid"),
            fingerprint.get("os"),
            fingerprint.get("ip"),
            fingerprint.get("port"),
            fingerprint.get("protocol"),
            fingerprint.get("reserved"),
        ]

        current_node = self.root
        for i, value in enumerate(dimensions):
            if value is None or value == "":
                continue
            key = f"L{i}:{value}"
            if key not in current_node.children:
                current_node.children[key] = TreeNode()
            current_node = current_node.children[key]

            # B树风格的bucket大小控制
            if len(current_node.children) > self.bucket_threshold:
                self._split_node(current_node)

        current_node.is_registered = True
        # 写WAL
        self.wal.append({"op": "register", "fingerprint": fingerprint})
```



#### 技术点2：null节点与缺省匹配

指纹的某些维度可能缺失（如设备未上报操作系统类型）。null节点的作用是保持树结构不断裂：缺省字段对应的位置不创建子节点分支，而是直接跳过，继续匹配下一层。

这一设计的权衡在于：跳过某个维度会降低匹配的精确度。例如，两个设备的UUID不同但UUID都合法，跳过IP维度后两个设备的指纹可能在后续维度上相同，导致误放行。本文认为UUID本身的唯一性已经足够强（128位标识符，重复概率接近零），后续维度更多是作为辅助校验而非主标识符，因此单个维度缺失不会显著降低安全性。生产阶段可以通过配置策略要求至少匹配N个维度（如至少匹配UUID + 另外两个维度），对缺省匹配的容忍度进行灵活控制。

#### 技术点3：B树防退化

每层的哈希bucket设置大小阈值（如1024个条目），超过阈值时按B树规则进行节点分裂。这防止了极端情况下单个bucket退化为线性查找，保证每层的查找始终为O(log N)。在实际运行中，由于UUID的强唯一性，Level 0层几乎不会出现bucket过大的情况，退化主要可能发生在IP层（多个设备可能来自同一IP段）和Port层（常用端口有限），B树分裂策略对这两层的保护意义最大。

#### 持久化设计

指纹索引的持久化采用WAL + bbolt两层方案：

```
写入流程:
  ① 将指纹变更操作写入WAL日志（顺序写，保证崩溃安全）
  ② 异步将WAL中的操作应用到bbolt中的Hash树索引
  ③ 定期生成Hash树的全量快照
  ④ 快照成功后截断WAL，释放磁盘空间

读取流程:
  ① 正常情况从内存中的Hash树索引读取
  ② 进程重启后从bbolt加载索引到内存
  ③ 若bbolt损坏，从最近一次快照+WAL重放恢复
```



------



### 3.3.5 用户画像存储（PortraitStore）

#### 基本原理

PortraitStore为每个用户维护一份画像数据，记录该用户历次连接的行为摘要。画像数据以连接为粒度存储——每次连接结束时生成一份连接摘要并追加到该用户的画像历史中。决策引擎在处理新请求时同时读取当前ConnectionContext（本次连接的实时事件）和DB中的历史画像摘要，综合判定风险。

#### 数据结构

```
@dataclass
class ConnectionSummary:
    connection_id: str
    user_id: str
    device_uuid: str
    connected_at: float
    ended_at: float
    duration_sec: float
    ip: str
    event_counts: dict          # {"image.upload": 3, "vm.start": 1, ...}
    flags_triggered: list       # ["alert_admin", "throttle"]
    off_hours_writes: int
    total_events: int
    write_ratio: float          # 写操作占总操作的比例

@dataclass
class ConnectionContext:
    """当前连接的实时上下文，内存中维护"""
    connection_id: str
    user_id: str
    device_uuid: str
    connected_at: float
    ip: str
    events: list                # [(op_type, timestamp), ...]

    def record_event(self, op_type: str):
        self.events.append((op_type, time.time()))

    def event_counts(self) -> dict:
        counts = {}
        for op, _ in self.events:
            counts[op] = counts.get(op, 0) + 1
        return counts

    def write_event_count(self) -> int:
        return sum(1 for op, _ in self.events if op not in READ_OPS)

    def write_ratio(self) -> float:
        if not self.events:
            return 0.0
        return self.write_event_count() / len(self.events)

    def last_event(self, op_type: str) -> Optional[float]:
        for op, ts in reversed(self.events):
            if op == op_type:
                return ts
        return None

    def is_off_hours(self) -> bool:
        hour = datetime.fromtimestamp(time.time()).hour
        return 0 <= hour < 6
```

#### 存储接口

```
class PortraitBackend(ABC):
    @abstractmethod
    def get_summaries(self, user_id: str, limit: int = 10) -> list[ConnectionSummary]:
        """获取最近N次连接的摘要"""
        ...

    @abstractmethod
    def append_summary(self, user_id: str, summary: ConnectionSummary):
        """追加连接摘要"""
        ...

    @abstractmethod
    def is_blacklisted(self, device_uuid: str) -> bool:
        """查询设备是否已拉黑"""
        ...

    @abstractmethod
    def blacklist_device(self, device_uuid: str, reason: str):
        """拉黑设备"""
        ...
```

初期实现用bbolt，生产阶段可替换为分布式数据库或者统一的存储池，上层PortraitStore逻辑不变。

#### 连接断开时的持久化

```
class PortraitStore:
    def __init__(self, backend: PortraitBackend):
        self.backend = backend

    def on_connection_close(self, ctx: ConnectionContext):
        summary = ConnectionSummary(
            connection_id=ctx.connection_id,
            user_id=ctx.user_id,
            device_uuid=ctx.device_uuid,
            connected_at=ctx.connected_at,
            ended_at=time.time(),
            duration_sec=time.time() - ctx.connected_at,
            ip=ctx.ip,
            event_counts=ctx.event_counts(),
            flags_triggered=ctx.triggered_flags,
            off_hours_writes=sum(1 for op, ts in ctx.events
                                 if op not in READ_OPS and self._is_off_hours(ts)),
            total_events=len(ctx.events),
            write_ratio=ctx.write_ratio(),
        )
        # 事务写入，一致性交给存储后端
        self.backend.append_summary(ctx.user_id, summary)
```

#### 设计权衡：以连接为粒度 vs 以时间桶为粒度

本文选择以连接为粒度而非时间桶，原因如下。时间桶方案在桶边界处可能存在事件归属模糊的问题（一个请求的处理跨越两个时间桶时归属哪个桶），且需要在内存中维护所有用户的窗口状态（包括非活跃用户），内存开销与用户数成正比。连接方案仅维护当前活跃连接的上下文，连接断开后即释放内存，内存开销仅与并发连接数成正比。此外，以连接为粒度天然携带了连接时长、来源IP等上下文信息，这些信息在时间桶方案中需要额外维护。连接方案的代价是决策时只能看到"本次连接的事件"和"历史连接的摘要"，无法精确到跨连接的任意时间窗口。本文认为这个精度损失是可接受的，因为行为异常在单次连接中通常已经表现得足够明显，跨连接的异常则通过历史摘要中的flags_triggered和累计计数来捕捉。

------



### 3.3.6 OutputBuffer与AlertQueue

#### 基本原理

OutputBuffer暂存通过校验的消息，通过gRPC的`SubscribeNotify`接口通知下游OpenStack侧定期拉取。AlertQueue暂存被阻断的消息和告警信息，通过gRPC推送至管理员监控端。

两个组件的设计目标一致：**解耦上下游，允许下游按自己的节奏消费**。

#### OutputBuffer

```
class OutputBuffer:
    def __init__(self, max_size=10000):
        self.queue = asyncio.Queue(maxsize=max_size)
        self.subscribers: list[asyncio.Queue] = []  # gRPC stream对应的队列

    async def put(self, message: ProxyRequest):
        await self.queue.put(message)
        # 通知所有订阅者
        for sub in self.subscribers:
            await sub.put("new_data")

    def subscribe(self) -> asyncio.Queue:
        """下游gRPC stream调用，注册为订阅者"""
        sub_queue = asyncio.Queue()
        self.subscribers.append(sub_queue)
        return sub_queue

    async def pull(self, batch_size=100) -> list[ProxyRequest]:
        """下游拉取接口，一次最多取batch_size条"""
        batch = []
        for _ in range(batch_size):
            try:
                batch.append(self.queue.get_nowait())
            except asyncio.QueueEmpty:
                break
        return batch
```

#### AlertQueue

```
class AlertQueue:
    def __init__(self):
        self.queue = asyncio.Queue()

    async def put(self, alert: AlertResult):
        await self.queue.put(alert)
        # 立即触发告警推送（不等待拉取）
        await self._push_alert(alert)

    async def _push_alert(self, alert: AlertResult):
        """通过gRPC stream推送给管理员监控端"""
        for subscriber in self.alert_subscribers:
            await subscriber.put(alert)
```

#### 设计权衡：通知 vs 轮询

OutputBuffer采用"通知+拉取"模式：有新数据时通知下游，下游收到通知后再来批量拉取。替代方案是纯轮询——下游每隔固定时间主动来拉取。通知模式的优点是实时性更好，下游不会在没有数据时空跑拉取请求。但通知本身也是一次网络调用，如果下游处理速度慢，频繁通知会造成不必要的开销。本文的做法是：通知只携带"有新数据"的信号（不包含数据本身），数据的传输通过下游主动拉取的gRPC stream完成，通知的开销极小。

------



## 3.4 决策引擎

### 3.4.1 设计目标

决策引擎是安全代理系统的核心智能组件，其职责是：给定一个请求的操作类型、当前连接的行为历史、该用户的历史画像摘要，输出一个明确的决策结果——放行、审计、限速、阻断、拉黑。

决策引擎的设计遵循以下原则：

- **声明式而非命令式**：决策规则以配置形式声明，不硬编码在业务逻辑中
- **规则可组合**：多条规则可同时生效，取最严格的响应
- **上下文感知**：同一操作在不同上下文中可能得到不同的决策结果
- **可审计**：每次决策的输入、命中规则和输出均可追溯

### 3.4.2 架构

决策引擎不是一个独立服务，而是一个被Worker调用的函数库。它接收三个输入：

```
┌─────────────────────────────────────────────────┐
│                  决策引擎                          │
│                                                  │
│  输入：                                           │
│    ① RiskLevel（Router判定的静态风险等级）          │
│    ② ConnectionContext（当前连接的实时事件）        │
│    ③ History（最近N次连接的历史画像摘要）            │
│                                                  │
│  处理：                                           │
│    规则引擎逐条匹配DECISION_RULES                   │
│    从上到下，命中第一条即停                          │
│                                                  │
│  输出：                                           │
│    Decision(action, reason, matched_rule_id)      │
└─────────────────────────────────────────────────┘
```

```
@dataclass
class Decision:
    action: str        # ALLOW, AUDIT, THROTTLE, BLOCK, BLACKLIST, REQUIRE_2FA
    reason: str        # 人类可读的原因
    rule_id: str       # 命中的规则ID，未命中则为"static_risk_only"
```



### 3.4.3 规则定义

DECISION_RULES是一组有序的条件-动作对。每条规则包含一个条件函数和一个响应动作。条件函数接收当前连接上下文和历史画像摘要作为输入，返回布尔值。规则按严重程度从上到下排列，引擎从第一条开始匹配，命中即停。

```
READ_OPS = {
    "GET /api/cloud/public/images",
    "GET /api/cloud/private/images",
    "GET /api/local/images",
    "GET /api/local/stats",
    "GET /api/vms/status",
    "GET /api/vms/running",
    "GET /api/vms/log",
    "GET /api/security/policy",
    "GET /api/audit/events",
}

DECISION_RULES = [
    # ============================================
    # 第一层：设备级拦截（不看行为，只看设备状态）
    # ============================================

    {
        "id": "R01_DEVICE_BLACKLISTED",
        "description": "设备已被拉黑，直接拒绝",
        "condition": lambda ctx, history, risk, portrait_store:
            portrait_store.is_blacklisted(ctx.device_uuid),
        "action": BLOCK_DEVICE,
    },

    # ============================================
    # 第二层：历史连接级拦截（看跨连接的行为模式）
    # ============================================

    {
        "id": "R02_REPEAT_OFFENDER",
        "description": "最近3次连接都触发过告警，屡教不改",
        "condition": lambda ctx, history, risk, portrait_store:
            len(history) >= 3
            and all(len(s.flags_triggered) > 0 for s in history[-3:]),
        "action": BLACKLIST_DEVICE,
    },

    {
        "id": "R03_HISTORICAL_HEAVY_DELETE",
        "description": "最近5次连接累计删除操作超过10次",
        "condition": lambda ctx, history, risk, portrait_store:
            sum(s.event_counts.get("image.delete", 0)
                + s.event_counts.get("image.delete_private_cloud", 0)
                + s.event_counts.get("image.delete_private_all", 0)
                + s.event_counts.get("image.delete_local", 0)
                for s in history[-5:])
            + ctx.event_counts().get("image.delete", 0) > 10,
        "action": BLACKLIST_DEVICE,
    },

    {
        "id": "R04_HISTORICAL_BLACKLISTED",
        "description": "历史上被拉黑过，本次要求二次认证",
        "condition": lambda ctx, history, risk, portrait_store:
            any("BLACKLIST_DEVICE" in s.flags_triggered for s in history[-3:]),
        "action": REQUIRE_2FA,
    },

    {
        "id": "R05_IP_HOPPING",
        "description": "最近5次连接来自3个以上不同IP",
        "condition": lambda ctx, history, risk, portrait_store:
            len(set(s.ip for s in history[-5:] + [type('S', (), {'ip': ctx.ip})])) > 3,
        "action": REQUIRE_2FA,
    },

    # ============================================
    # 第三层：当前连接级拦截（看本次连接内的行为）
    # ============================================

    {
        "id": "R06_BRUTE_FORCE_LOGIN",
        "description": "当前连接内暴力登录失败超过5次",
        "condition": lambda ctx, history, risk, portrait_store:
            sum(1 for op, _ in ctx.events if op == "login_failed") > 5,
        "action": BLOCK_LOGIN_10MIN,
    },

    {
        "id": "R07_BULK_DELETE",
        "description": "当前连接内删除操作超过3次",
        "condition": lambda ctx, history, risk, portrait_store:
            sum(ctx.event_counts().get(k, 0) for k in
                ["image.delete", "image.delete_private_cloud",
                 "image.delete_private_all", "image.delete_local"]) > 3,
        "action": BLOCK_DEVICE,
    },

    {
        "id": "R08_UPLOAD_THEN_START",
        "description": "上传镜像后立即启动虚拟机，可疑载荷注入",
        "condition": lambda ctx, history, risk, portrait_store:
            ctx.event_counts().get("image.upload", 0) >= 1
            and ctx.event_counts().get("vm.start", 0) >= 1
            and (ctx.last_event("image.upload") or float('inf'))
                < (ctx.last_event("vm.start") or 0),
        "action": QUARANTINE_AND_ALERT,
    },

    {
        "id": "R09_HEAVY_WRITER",
        "description": "当前连接写操作超过20次",
        "condition": lambda ctx, history, risk, portrait_store:
            ctx.write_event_count() > 20,
        "action": THROTTLE,
    },

    {
        "id": "R10_OFF_HOURS_PATTERN",
        "description": "非工作时间且历史连接也有非工作时间写操作",
        "condition": lambda ctx, history, risk, portrait_store:
            ctx.is_off_hours()
            and ctx.write_event_count() > 5
            and any(s.off_hours_writes > 5 for s in history[-3:]),
        "action": BLOCK_WRITE_OPS,
    },

    # ============================================
    # 第四层：默认兜底（按Router判定的静态风险等级处理）
    # ============================================

    {
        "id": "R99_STATIC_RISK_FALLBACK",
        "description": "无动态规则命中，按静态风险等级处理",
        "condition": lambda ctx, history, risk, portrait_store: True,
        "action": None,  # 由risk_level决定，见下方
    },
]
```



### 3.4.4 规则匹配逻辑

```
def evaluate_rules(ctx: ConnectionContext,
                   history: list[ConnectionSummary],
                   risk_level: int,
                   portrait_store: PortraitStore) -> Decision:

    for rule in DECISION_RULES:
        if rule["condition"](ctx, history, risk_level, portrait_store):
            if rule["action"] is not None:
                # 命中具体规则
                ctx.triggered_flags.append(rule["action"])
                return Decision(
                    action=rule["action"],
                    reason=rule["description"],
                    rule_id=rule["id"],
                )
            else:
                # 命中兜底规则，按静态风险等级决定
                return _static_risk_decision(risk_level)

    # 理论上不会到这里（兜底规则永远命中）
    return Decision(action=ALLOW, reason="no_rule_matched", rule_id="none")


def _static_risk_decision(risk_level: int) -> Decision:
    if risk_level == L1:
        return Decision(action=AUDIT, reason="L1_write_operation", rule_id="R99")
    elif risk_level == L2:
        return Decision(action=ALERT, reason="L2_high_risk_operation", rule_id="R99")
    else:
        return Decision(action=ALLOW, reason="default_allow", rule_id="R99")
```



### 3.4.5 决策响应动作定义

| 动作                 | 含义       | 对请求的处理               | 额外副作用                   |
| -------------------- | ---------- | -------------------------- | ---------------------------- |
| ALLOW                | 放行       | 请求转发至OpenStack        | 无                           |
| AUDIT                | 审计放行   | 请求转发至OpenStack        | 记录详细日志                 |
| ALERT                | 告警放行   | 请求转发至OpenStack        | 告警推送至管理员             |
| THROTTLE             | 限速       | 请求转发但限速             | 后续请求增加延迟             |
| BLOCK                | 阻断       | 请求不转发，返回拒绝       | 无                           |
| BLOCK_DEVICE         | 设备阻断   | 该设备后续所有请求拒绝     | 设备标记为临时阻断           |
| BLOCK_LOGIN          | 登录阻断   | 登录请求拒绝，10分钟后解除 | 定时任务自动解除             |
| BLOCK_WRITE_OPS      | 写操作阻断 | 读操作放行，写操作拒绝     | 仅本次连接生效               |
| REQUIRE_2FA          | 二次认证   | 请求暂挂，要求二次认证     | 通过后正常放行               |
| QUARANTINE_AND_ALERT | 隔离告警   | 镜像存入隔离区             | 触发CICD扫描任务             |
| BLACKLIST_DEVICE     | 拉黑设备   | 拒绝所有请求               | 设备永久拉黑 + 锁账户 + 告警 |



### 3.4.6 规则命中顺序的设计权衡

本文采用"命中第一条即停"而非"匹配所有规则取最严格"的策略。两种策略的核心区别在于：

**命中即停**：规则按严重程度排序，越靠前的规则对应的响应越严重。第一个命中的规则即为最终决策。优点是逻辑简单、性能可预测（不需要遍历所有规则）；缺点是如果多条规则同时命中，只能看到第一条，丢失了其他规则的上下文信息。

**匹配所有取最严格**：遍历所有规则，收集所有命中的规则，取响应最严格的作为最终决策。优点是不遗漏任何命中；缺点是需要遍历全部规则，且"最严格"的定义需要一个优先级排序（本质上还是需要排序）。

本文选择命中即停，理由是规则已经按严重程度排序，且规则之间存在逻辑递进关系——设备已拉黑就不需要再判断它有没有频繁删除，历史已标记为屡犯就不需要再检查它IP跳变。命中即停在这种递进结构下等价于匹配所有取最严格，且性能更好。

如果未来规则之间不存在递进关系（如两条独立的规则可能同时命中且需要同时触发告警），可以将命中即停改为命中后继续匹配但只取最严格响应的策略。引擎的架构不依赖于命中策略的选择，修改匹配函数即可切换。

### 3.4.7 规则配置的可扩展性

DECISION_RULES在原型阶段以Python列表形式硬编码。生产阶段建议抽离为配置文件（如YAML或JSON），支持不重启热加载。规则的条件函数可以抽象为一组标准的比较算子（大于、小于、包含、模式匹配等），配置文件中声明算子和参数即可，不需要编写Python lambda。

```
# 生产阶段的规则配置示例
rules:
  - id: R06_BRUTE_FORCE_LOGIN
    description: "当前连接内暴力登录失败超过5次"
    conditions:
      - field: "current_connection.events.login_failed.count"
        operator: "gt"
        value: 5
    action: BLOCK_LOGIN_10MIN

  - id: R07_BULK_DELETE
    description: "当前连接内删除操作超过3次"
    conditions:
      - field: "current_connection.events.delete.count"
        operator: "gt"
        value: 3
    action: BLOCK_DEVICE
```

这样安全管理员可以在不修改代码的情况下调整阈值和响应动作，降低了运维成本。同时规则的版本化管理也可以纳入配置中心（如Consul或etcd），实现变更的可追溯和回滚。