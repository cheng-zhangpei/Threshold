package dispatch

import "Threshold/pkg/types"

// PoolPolicy WorkerPool 弹性伸缩策略
type PoolPolicy struct {
	MinWorkers int // 最小 Worker 数量
	MaxWorkers int // 最大 Worker 数量

	ScaleUpThreshold   int // 队列深度超过此值触发扩容
	ScaleUpStep        int // 每次扩容增加的 Worker 数量
	ScaleDownThreshold int // 队列深度低于此值触发缩容
	ScaleDownStep      int // 每次缩容减少的 Worker 数量

	MaxQueueSize int // 内存队列最大容量
	OverflowSize int // 队列超过此值时溢出到 bbolt
	ReloadSize   int // 队列低于此值时从 bbolt 回捞
	ReloadBatch  int // 每次从 bbolt 回捞的批次大小

	IdleTimeoutSec         int // Worker 空闲缩容超时（秒）
	HealthCheckIntervalSec int // monitor_loop 巡检间隔（秒）
}

// DefaultPoolPolicy 返回默认策略配置
func DefaultPoolPolicy() PoolPolicy {
	return PoolPolicy{
		MinWorkers:           2,
		MaxWorkers:           64,
		ScaleUpThreshold:     100,
		ScaleUpStep:          4,
		ScaleDownThreshold:   20,
		ScaleDownStep:        2,
		MaxQueueSize:         10000,
		OverflowSize:         8000,
		ReloadSize:           4000,
		ReloadBatch:          500,
		IdleTimeoutSec:       30,
		HealthCheckIntervalSec: 5,
	}
}

// PolicyFromConfig 从配置结构生成策略，零值保留默认值
func PolicyFromConfig(cfg types.PoolPolicy) PoolPolicy {
	p := DefaultPoolPolicy()
	if cfg.MinWorkers > 0 {
		p.MinWorkers = cfg.MinWorkers
	}
	if cfg.MaxWorkers > 0 {
		p.MaxWorkers = cfg.MaxWorkers
	}
	if cfg.ScaleUpThreshold > 0 {
		p.ScaleUpThreshold = cfg.ScaleUpThreshold
	}
	if cfg.ScaleUpStep > 0 {
		p.ScaleUpStep = cfg.ScaleUpStep
	}
	if cfg.MaxQueueSize > 0 {
		p.MaxQueueSize = cfg.MaxQueueSize
	}
	if cfg.IdleTimeoutSec > 0 {
		p.IdleTimeoutSec = cfg.IdleTimeoutSec
	}
	if cfg.HealthCheckIntervalSec > 0 {
		p.HealthCheckIntervalSec = cfg.HealthCheckIntervalSec
	}
	return p
}
