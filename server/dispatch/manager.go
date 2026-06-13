package dispatch

import (
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"Threshold/pkg/storage"
	"Threshold/pkg/types"
)

// ============================================================
// DispatchTask 队列中的处理单元
// ============================================================

type DispatchTask struct {
	Parsed   *types.ParsedRequest
	Risk     types.RiskLevel
	ResultCh chan *types.Decision
}

// Dispatcher 接口（Router 依赖此接口入队）
type Dispatcher interface {
	Enqueue(parsed *types.ParsedRequest, riskLevel types.RiskLevel) *types.Decision
}

// zeroFillPolicy 对零值字段填充默认值
func zeroFillPolicy(p PoolPolicy) PoolPolicy {
	def := DefaultPoolPolicy()
	if p.MinWorkers <= 0 {
		p.MinWorkers = def.MinWorkers
	}
	if p.MaxWorkers <= 0 {
		p.MaxWorkers = def.MaxWorkers
	}
	if p.ScaleUpThreshold <= 0 {
		p.ScaleUpThreshold = def.ScaleUpThreshold
	}
	if p.ScaleUpStep <= 0 {
		p.ScaleUpStep = def.ScaleUpStep
	}
	if p.ScaleDownThreshold <= 0 {
		p.ScaleDownThreshold = def.ScaleDownThreshold
	}
	if p.ScaleDownStep <= 0 {
		p.ScaleDownStep = def.ScaleDownStep
	}
	if p.MaxQueueSize <= 0 {
		p.MaxQueueSize = def.MaxQueueSize
	}
	if p.OverflowSize <= 0 {
		p.OverflowSize = def.OverflowSize
	}
	if p.ReloadSize <= 0 {
		p.ReloadSize = def.ReloadSize
	}
	if p.ReloadBatch <= 0 {
		p.ReloadBatch = def.ReloadBatch
	}
	if p.IdleTimeoutSec <= 0 {
		p.IdleTimeoutSec = def.IdleTimeoutSec
	}
	if p.HealthCheckIntervalSec <= 0 {
		p.HealthCheckIntervalSec = def.HealthCheckIntervalSec
	}
	return p
}

// ============================================================
// pendingEntry 溢出任务的等待记录
// ============================================================

type pendingEntry struct {
	resultCh chan *types.Decision
}

// DispatchManager 调度中枢
type DispatchManager struct {
	policy PoolPolicy
	store  storage.Store
	ts     *TaskStore
	queue  chan DispatchTask
	done   chan struct{}
	wg     sync.WaitGroup

	workers  []*Worker
	workerMu sync.Mutex
	nextID   atomic.Int64

	// 溢出等待映射
	pendingMu   sync.Mutex
	pending     map[string]*pendingEntry
	overflowSeq atomic.Int64

	overflowed atomic.Int64
	processed  atomic.Int64
	reloaded   atomic.Int64

	decisionFn func(ctx *types.ConnectionContext, history []*types.ConnectionSummary, riskLevel types.RiskLevel) *types.Decision
}

type DispatcherConfig struct {
	Policy     PoolPolicy
	Store      storage.Store
	DecisionFn func(ctx *types.ConnectionContext, history []*types.ConnectionSummary, riskLevel types.RiskLevel) *types.Decision
}

func NewDispatchManager(cfg DispatcherConfig) *DispatchManager {
	if cfg.DecisionFn == nil {
		cfg.DecisionFn = func(_ *types.ConnectionContext, _ []*types.ConnectionSummary, _ types.RiskLevel) *types.Decision {
			return &types.Decision{Action: types.ALLOW, Reason: "default pass"}
		}
	}
	cfg.Policy = zeroFillPolicy(cfg.Policy)

	dm := &DispatchManager{
		policy:     cfg.Policy,
		store:      cfg.Store,
		ts:         NewTaskStore(cfg.Store),
		queue:      make(chan DispatchTask, cfg.Policy.MaxQueueSize),
		done:       make(chan struct{}),
		pending:    make(map[string]*pendingEntry),
		decisionFn: cfg.DecisionFn,
	}

	for i := 0; i < cfg.Policy.MinWorkers; i++ {
		dm.spawnWorker()
	}
	dm.wg.Add(1)
	go dm.monitorLoop()

	log.Printf("dispatch: started with %d workers, queue size %d", cfg.Policy.MinWorkers, cfg.Policy.MaxQueueSize)
	return dm
}

func (dm *DispatchManager) nextOverflowKey() string {
	return fmt.Sprintf("ovf-%d", dm.overflowSeq.Add(1))
}

// ============================================================
// Enqueue
// ============================================================

func (dm *DispatchManager) Enqueue(parsed *types.ParsedRequest, riskLevel types.RiskLevel) *types.Decision {
	resultCh := make(chan *types.Decision, 1)
	task := DispatchTask{Parsed: parsed, Risk: riskLevel, ResultCh: resultCh}

	select {
	case dm.queue <- task:
	default:
		key := dm.nextOverflowKey()
		dm.pendingMu.Lock()
		dm.pending[key] = &pendingEntry{resultCh: resultCh}
		dm.pendingMu.Unlock()

		_, err := dm.ts.Overflow(OverflowTask{Parsed: parsed, Risk: riskLevel, OverflowKey: key})
		if err != nil {
			dm.pendingMu.Lock()
			delete(dm.pending, key)
			dm.pendingMu.Unlock()
			log.Printf("dispatch: overflow failed: %v", err)
			return &types.Decision{Action: types.THROTTLE, Reason: "queue full and overflow failed"}
		}
		dm.overflowed.Add(1)

		select {
		case decision := <-resultCh:
			return decision
		case <-dm.done:
			return &types.Decision{Action: types.THROTTLE, Reason: "dispatch shutting down"}
		}
	}

	select {
	case decision := <-resultCh:
		return decision
	case <-dm.done:
		return &types.Decision{Action: types.THROTTLE, Reason: "dispatch shutting down"}
	}
}

// ============================================================
// monitor_loop
// ============================================================

func (dm *DispatchManager) monitorLoop() {
	defer dm.wg.Done()
	ticker := time.NewTicker(time.Duration(dm.policy.HealthCheckIntervalSec) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			dm.checkScale()
			dm.reloadFromStorage()
		case <-dm.done:
			return
		}
	}
}

func (dm *DispatchManager) checkScale() {
	depth := len(dm.queue)
	numWorkers := dm.workerCount()

	if depth > dm.policy.ScaleUpThreshold && numWorkers < dm.policy.MaxWorkers {
		step := dm.policy.ScaleUpStep
		if numWorkers+step > dm.policy.MaxWorkers {
			step = dm.policy.MaxWorkers - numWorkers
		}
		for i := 0; i < step; i++ {
			dm.spawnWorker()
		}
		log.Printf("dispatch: scaled up to %d workers (queue depth: %d)", dm.workerCount(), depth)
	}

	if depth < dm.policy.ScaleDownThreshold && numWorkers > dm.policy.MinWorkers {
		step := dm.policy.ScaleDownStep
		if numWorkers-step < dm.policy.MinWorkers {
			step = numWorkers - dm.policy.MinWorkers
		}
		if step > 0 {
			dm.retireWorkers(step)
			log.Printf("dispatch: scaled down to %d workers (queue depth: %d)", dm.workerCount(), depth)
		}
	}
}

func (dm *DispatchManager) reloadFromStorage() {
	depth := len(dm.queue)
	if depth > dm.policy.ReloadSize {
		return
	}

	available := dm.policy.MaxQueueSize - depth
	batch := dm.policy.ReloadBatch
	if batch > available {
		batch = available
	}
	if batch <= 0 {
		return
	}

	result, err := dm.ts.Reload(batch)
	if err != nil {
		log.Printf("dispatch: reload failed: %v", err)
		return
	}
	if len(result.Tasks) == 0 {
		return
	}

	var loaded int
	var successKeys [][]byte
	for _, rt := range result.Tasks {
		dm.pendingMu.Lock()
		pe, ok := dm.pending[rt.OverflowKey]
		if ok {
			delete(dm.pending, rt.OverflowKey)
		}
		dm.pendingMu.Unlock()

		var resultCh chan *types.Decision
		if ok {
			resultCh = pe.resultCh
		} else {
			resultCh = make(chan *types.Decision, 1)
		}

		task := DispatchTask{Parsed: rt.Parsed, Risk: rt.Risk, ResultCh: resultCh}
		select {
		case dm.queue <- task:
			loaded++
			successKeys = append(successKeys, rt.Key)
		default:
			if ok {
				dm.pendingMu.Lock()
				dm.pending[rt.OverflowKey] = pe
				dm.pendingMu.Unlock()
			}
		}
	}

	if len(successKeys) > 0 {
		dm.ts.Cleanup(successKeys)
	}
	if loaded > 0 {
		dm.reloaded.Add(int64(loaded))
		log.Printf("dispatch: reloaded %d tasks from storage", loaded)
	}
}

// ============================================================
// Worker 管理
// ============================================================

func (dm *DispatchManager) spawnWorker() {
	id := dm.nextID.Add(1)
	w := NewWorker(id, dm)
	dm.workerMu.Lock()
	dm.workers = append(dm.workers, w)
	dm.workerMu.Unlock()
	go w.Run()
}

func (dm *DispatchManager) retireWorkers(count int) {
	dm.workerMu.Lock()
	defer dm.workerMu.Unlock()

	retired := 0
	var remaining []*Worker
	for _, w := range dm.workers {
		if retired < count && w.TryRetire() {
			retired++
		} else {
			remaining = append(remaining, w)
		}
	}
	dm.workers = remaining
}

func (dm *DispatchManager) workerCount() int {
	dm.workerMu.Lock()
	defer dm.workerMu.Unlock()
	return len(dm.workers)
}

// ============================================================
// Stats
// ============================================================

type Stats struct {
	QueueDepth  int64
	WorkerCount int
	Overflowed  int64
	Processed   int64
	Reloaded    int64
}

func (dm *DispatchManager) GetStats() Stats {
	return Stats{
		QueueDepth:  int64(len(dm.queue)),
		WorkerCount: dm.workerCount(),
		Overflowed:  dm.overflowed.Load(),
		Processed:   dm.processed.Load(),
		Reloaded:    dm.reloaded.Load(),
	}
}

// ============================================================
// Shutdown
// ============================================================

func (dm *DispatchManager) Shutdown() {
	close(dm.done)
	dm.wg.Wait()
}
