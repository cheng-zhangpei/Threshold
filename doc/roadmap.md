# Threshold - 优化路线图

## 1. 工程化（生产可用）

### 1.1 规则配置化
- 当前：12 条规则硬编码在 server/decision/rules.go
- 目标：YAML/JSON 配置文件，支持热加载不重启
- 工作量：1-2 天

### 1.2 画像参数配置化
- 当前：RiskScore 权重（40/20/20/20）和阈值（0.7）硬编码
- 目标：从配置文件读取，按环境/角色可调
- 工作量：半天

### 1.3 结构化审计日志
- 当前：log.Printf 文本日志
- 目标：接入 slog/zerolog，JSON 格式，支持日志级别
- 工作量：1 天

### 1.4 Prometheus Metrics
- 当前：无可观测性
- 目标：请求计数、延迟分布、队列深度、Worker 数等指标
- 工作量：1 天

### 1.5 mTLS 双向认证
- 当前：单向 TLS / 无 TLS
- 目标：Client-Server 双向证书认证
- 工作量：半天

## 2. 功能增强

### 2.1 ConnectionContext WAL 持久化
- 当前：ConnectionContext 存内存，重启丢失
- 目标：通过 WAL 事务持久化到 bbolt，重启可恢复
- 工作量：1 天

### 2.2 BLOCK_LOGIN 定时自动解除
- 当前：BLOCK_LOGIN 永久阻断
- 目标：10 分钟后自动解除，支持手动解除
- 工作量：1 天

### 2.3 QUARANTINE_AND_ALERT 对接 CICD
- 当前：只触发告警
- 目标：通过 gRPC 通知 CICD 模块执行沙箱扫描
- 工作量：2 天

### 2.4 REQUIRE_2FA 二次认证流程
- 当前：规则定义了但未实现挂起/恢复
- 目标：请求挂起，等待二次认证通过后恢复
- 工作量：2-3 天

### 2.5 CloseConnection 通知下游
- 当前：连接关闭只更新画像
- 目标：通过 SubscribeNotify 推送连接关闭事件给下游
- 工作量：半天

### 2.6 ListDevices 实现
- 当前：返回空列表
- 目标：遍历 bbolt 返回所有已注册设备
- 工作量：半天

### 2.7 Portrait 历史画像加载
- 当前：PortraitStore 重启后历史丢失
- 目标：启动时从 bbolt 加载历史 ConnectionSummary
- 工作量：1 天

## 3. Client 端完善

### 3.1 指纹字段注入
- 当前：ProxyStream 只是透传 raw_http_request
- 目标：在 raw_http_request 中注入 X-Proxy-UUID/OS/IP 等指纹 header
- 工作量：1 天

### 3.2 TLS 支持
- 当前：Client 连接 Server 用 insecure
- 目标：支持 TLS/mTLS 证书配置
- 工作量：半天

### 3.3 PullApproved / SubscribeNotify 转发
- 当前：返回 not implemented
- 目标：完整转发给 Server
- 工作量：1 天

### 3.4 Client 测试覆盖
- 当前：proxy 包无单元测试
- 目标：mock Server 端验证透传逻辑
- 工作量：1 天

## 4. 架构演进

### 4.1 分布式存储替换
- 当前：bbolt 单机存储
- 目标：PortraitStore 接口已抽象，可换 Redis/PostgreSQL
- 工作量：2-3 天

### 4.2 跨设备关联算法
- 当前：SimpleCorrelator 简单规则（1/2/3+ 用户）
- 目标：基于行为模式的 ML 评分模型
- 工作量：持续迭代

### 4.3 画像评分增强
- 当前：线性加权模型（4 个维度）
- 目标：时间衰减 + 非线性评分 + 角色分级
- 工作量：持续迭代

### 4.4 可观测性
- 当前：无
- 目标：Prometheus + Grafana + 分布式追踪
- 工作量：2-3 天
