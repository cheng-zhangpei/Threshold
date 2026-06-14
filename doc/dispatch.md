# DispatchManager 模块设计文档

## 1. 模块定位

DispatchManager 是 Threshold 安全代理服务端的调度中枢，位于 Router 和决策引擎之间。职责是接收 Router 分级后的任务，通过 WorkerPool 弹性伸缩处理，并保证在高并发下的背压可控。

在整个数据流中的位置：

```
客户端 gRPC 请求
    |
gRPC Handler（指纹校验）
    |
Router（L0/L1/L2/L3 静态分级）
    |
+-- L0 -> OutputBuffer（直接穿透）
+-- L1+ -> DispatchManager（本模块）
              |
         memoryQueue（buffered channel）
              |
         WorkerPool（竞争消费）
              |
         Decision Engine（R01-R10 + R99）
              |
         +-- ALLOW/AUDIT -> OutputBuffer
         +-- BLOCK/ALERT -> AlertQueue
```

## 2. 核心组件

### 2.1 DispatchManager

调度中枢，管理任务队列、Worker 生命周期、溢出持久化。

核心方法：

| 方法 | 职责 |
|------|------|
| Enqueue() | Router 调用入口，非阻塞投递到队列，满则溢出到 bbolt |
| monitorLoop() | 后台协程，周期性检查队列深度 + 扩缩容 + 回捞 |
| Shutdown() | 优雅关闭，等待所有 Worker 和 monitor 退出 |

### 2.2 Worker

无状态处理单元，从队列竞争消费任务。通过 atomic.Bool.CompareAndSwap 实现无锁退休，不会中断正在处理的任务。

处理流水线：

```
1. 从 dm.queue 读取 DispatchTask（竞争消费）
2. 构建 ConnectionContext（注入 opKey 事件）
3. 调用 dm.decisionFn（对接 Decision Engine）
4. 通过 task.ResultCh 同步返回决策结果给调用者
```

### 2.3 TaskStore

溢出持久化层，封装 bbolt 读写，类似 WAL 层的封装模式。

| 方法 | 说明 |
|------|------|
| Overflow(task) | 将任务序列化写入 bbolt，key 用 big-endian 序列号保序 |
| Reload(batch) | 只读批量读取，不删除（两阶段提交思想） |
| Cleanup(keys) | 确认投递成功后批量删除 |
| PendingCount() | 查询 bbolt 中待回捞数量 |

## 3. 背压与溢出机制

### 3.1 为什么需要溢出

当请求量突增时，内存队列（buffered channel）可能被打满。如果直接拒绝，Router 会收到 THROTTLE 响应。如果阻塞等待，Router 会被堵住，级联影响上游。

溢出机制的核心思想：**将热路径（内存队列）溢出的数据转存到冷路径（bbolt），等队列空闲后再批量回捞。**

### 3.2 溢出流程

```
Enqueue() 被调用
    |
    +-- select 投递 queue
    |    +-- 成功 -> 阻塞等 resultCh
    |    +-- 失败（default）-> 队列满，执行溢出
    |              |
    |         1. 生成唯一 overflowKey（原子计数器）
    |         2. 将 resultCh 保留在 pending map 中
    |         3. TaskStore.Overflow() 写入 bbolt
    |         4. 调用者阻塞等待 resultCh 或 shutdown
```

**关键设计：溢出时 resultCh 不丢失**

溢出的任务写入 bbolt 时，原始调用者的 resultCh 保留在内存 pending map 中（以 overflowKey 为索引）。当 monitor_loop 将任务从 bbolt 回捞时，从 pending map 中取出原始 resultCh 组装成 DispatchTask 投递到队列，Worker 处理完后通过原始 resultCh 返回结果。

**保证了：即使任务经过“内存 -> bbolt -> 内存”的完整冷路径，调用者仍然能拿到决策结果。**

### 3.3 回捞流程

```
monitorLoop() 定期触发
    |
    +-- checkScale()    // 弹性伸缩
    +-- reloadFromStorage()
         |
         1. 检查 queue 深度 < ReloadSize（默认 4000）
         2. 计算可加载数量 = MaxQueueSize - 当前深度
         3. TaskStore.Reload(batch) 从 bbolt 批量读取
         4. 对每个任务：
            +-- 从 pending map 取出原始 resultCh
            +-- 投递到 queue
         5. 投递成功的条目调用 TaskStore.Cleanup() 删除
         6. 投递失败的条目放回 pending map 等下次
```

### 3.4 阈值参数

| 参数 | 默认值 | 触发条件 | 说明 |
|------|--------|----------|------|
| MaxQueueSize | 10000 | channel 容量 | 内存队列最大容量 |
| ReloadSize | 4000 | queue 深度 < ReloadSize | 队列空闲到此值以下才触发回捞 |
| ReloadBatch | 500 | 每次回捞上限 | 避免一次性加载过多 |

## 4. 弹性伸缩

### 4.1 扩容策略

```
checkScale() 被调用（每 HealthCheckIntervalSec 秒）
    |
    +-- queue 深度 > ScaleUpThreshold && 当前 Worker 数 < MaxWorkers
    |    +-- 新增 ScaleUpStep 个 Worker
    |
    +-- queue 深度 < ScaleDownThreshold && 当前 Worker 数 > MinWorkers
         +-- 退休 ScaleDownStep 个 Worker
```

### 4.2 默认参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| MinWorkers | 2 | 最小保底 Worker 数 |
| MaxWorkers | 64 | 最大上限 |
| ScaleUpThreshold | 100 | 队列深度超过此值触发扩容 |
| ScaleUpStep | 4 | 每次扩容增加的 Worker 数 |
| ScaleDownThreshold | 20 | 队列深度低于此值触发缩容 |
| ScaleDownStep | 2 | 每次缩容减少的 Worker 数 |
| HealthCheckIntervalSec | 5 | 巡检间隔 |

### 4.3 扩缩容时序

```
t=0s:  1 Worker, queue=0
       20 个任务同时入队，每个处理耗时 100ms

t=0s:  queue 深度迅速升到 10+
       1 个 Worker 处理速度跟不上
       monitor_loop 5 秒后检查

t=5s:  queue 深度 > 100（ScaleUpThreshold）
       从 1 扩到 5（+4）
       5 个 Worker 并行处理

t=6s:  队列清空，queue=0

t=10s: monitor_loop 检查
       queue 深度 < 20（ScaleDownThreshold）
       从 5 缩到 3（-2，不低于 MinWorkers=2）

t=15s: 持续空闲
       从 3 缩到 2（MinWorkers，不再缩）
```

### 4.4 退休机制

Worker 退休通过 atomic.Bool.CompareAndSwap 实现无锁标记。退休是软的——Worker 在处理完当前任务后才检查退休标记，不会中断正在处理的任务。保证了不会丢失正在执行的请求。

## 5. 级联奔溃防护

### 5.1 防护机制

| 层级 | 机制 | 效果 |
|------|------|------|
| Router 层 | buffered channel + default 背压 | Router 不被阻塞，返回 THROTTLE |
| DispatchManager 层 | 溢出到 bbolt | 队列满不丢数据 |
| Worker 层 | 弹性扩容 | 队列积压时自动增加 Worker |
| 存储层 | bbolt 持久化 | 跨重启不丢数据 |

### 5.2 极端场景

**Worker 全部被堵（决策引擎 hang）：**
- 内存队列满 -> 溢出到 bbolt
- bbolt 也满 -> Overflow 返回错误 -> Router 收到 THROTTLE
- 不会死锁，因为所有路径都有非阻塞出口

## 6. 测试覆盖

### 6.1 测试矩阵

| 类别 | 测试数 | 覆盖内容 |
|------|--------|----------|
| TaskStore 持久化 | 3 | 溢出写入 / 回捞读取 / Cleanup / 批量限制 / PendingCount |
| DispatchManager 基础 | 4 | 单任务入队 / 100 并发 / 溢出到 bbolt / 弹性扩缩容 |
| 决策引擎联调 | 8 | R99 三级风险 / R07 批量删除 / R08 上传后启动 / 混合风险 / 溢出决策一致性 |
| **总计** | **15** | |

### 6.2 联调测试设计思路

基础测试验证“组件能跑”，联调测试验证“决策正确”。

**关键问题：** DispatchManager 的 Worker 是无状态的，每次 process() 创建新的 ConnectionContext。跨请求的规则（如 R06 暴力登录 > 5 次）在当前架构下不会跨 Worker 累积。

**解决方案：** 联调测试中通过自定义 DecisionFn 在单次调用中注入多事件，模拟 Worker 内部累积的场景。验证的是决策引擎在 DispatchManager 异步流水线中的正确性。

**溢出决策一致性测试：** OverflowPreservesDecision 验证任务经过内存 -> bbolt -> 回捞 -> Worker 完整冷路径后，决策结果与热路径完全一致。这是背压机制正确性的核心保证。

### 6.3 测试中的延迟注入

| 场景 | 延迟 | 目的 |
|------|------|------|
| OverflowToStorage | 50ms/task | 队列打满，强制溢出 |
| ScaleUp | 100ms/task | Worker 处理慢，队列积压触发扩容 |
| OverflowPreservesDecision | 20ms/task | 同时触发溢出 + 决策引擎联调 |

**权衡：** 延迟注入让测试变慢（每个 ~2-4 秒），但这是验证异步行为的必要手段。

## 7. 已知限制与后续演进

| 限制 | 影响 | 后续方案 |
|------|------|----------|
| Worker 无状态，不共享 ConnectionContext | 跨请求规则无法累积 | 接入 PortraitStore + WAL |
| bbolt 单机存储 | 溢出数据不跨节点 | 可替换为 Redis/Kafka |
| channel 容量固定 | 运行时不可调 | 可改为 ring buffer |
| 扩缩容间隔固定 | 突发流量有延迟 | 可加队列深度突变检测 |
| Reload 和 Cleanup 非原子 | 回捞后 crash 可能重复处理 | 基于 bbolt 事务的幂等性 |

## 8. 配置示例

```yaml
# config/server.yaml
dispatch:
  min_workers: 2
  max_workers: 64
  scale_up_threshold: 100
  scale_up_step: 4
  max_queue_size: 10000
  idle_timeout_sec: 30
  health_check_interval_sec: 5
```

默认值通过 DefaultPoolPolicy() + zeroFillPolicy() 两级兜底：配置文件未写的字段用默认值，代码中零值字段也用默认值。避免因漏配置导致 panic。
