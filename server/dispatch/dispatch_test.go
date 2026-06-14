package dispatch

import (
	"os"
	"sync"
	"testing"
	"time"

	"Threshold/pkg/storage"
	"Threshold/pkg/types"
	"Threshold/server/decision"
	"Threshold/server/portrait"
)

func newTestStore(t *testing.T) storage.Store {
	t.Helper()
	tmpFile, _ := os.CreateTemp("", "dispatch-test-*.db")
	tmpFile.Close()
	t.Cleanup(func() { os.Remove(tmpFile.Name()) })
	store, err := storage.NewBoltStore(tmpFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

func newTestParsedRequest(id string, method string, path string) *types.ParsedRequest {
	return &types.ParsedRequest{
		ConnectionID: id,
		DeviceUUID:   "device-" + id,
		UserID:       "user-" + id,
		Timestamp:    time.Now(),
		Method:       method,
		Path:         path,
		OpKey:        method + " " + path,
	}
}

func newEngineDecisionFn(store storage.Store) func(*types.ConnectionContext, []*types.ConnectionSummary, types.RiskLevel) *types.Decision {
	ps := portrait.NewStore(store)
	engine := decision.NewEngine(ps)
	return engine.Evaluate
}

// ============================================================
// TaskStore 溢出持久化测试
// ============================================================

func TestTaskStore_OverflowAndReload(t *testing.T) {
	store := newTestStore(t)
	ts := NewTaskStore(store)

	for i := 0; i < 3; i++ {
		parsed := newTestParsedRequest("c"+string(rune('0'+i)), "POST", "/api/vms/start")
		_, err := ts.Overflow(OverflowTask{Parsed: parsed, Risk: types.L1})
		if err != nil {
			t.Fatalf("Overflow error: %v", err)
		}
	}

	result, err := ts.Reload(10)
	if err != nil {
		t.Fatalf("Reload error: %v", err)
	}
	if len(result.Tasks) != 3 {
		t.Fatalf("Reload got %d tasks, want 3", len(result.Tasks))
	}

	for i, rt := range result.Tasks {
		if rt.Risk != types.L1 {
			t.Errorf("task[%d].Risk = %d, want L1", i, rt.Risk)
		}
	}

	var keys [][]byte
	for _, rt := range result.Tasks {
		keys = append(keys, rt.Key)
	}
	cleanResult, _ := ts.Cleanup(keys)
	if cleanResult.Deleted != 3 {
		t.Errorf("Cleanup deleted %d, want 3", cleanResult.Deleted)
	}

	emptyResult, _ := ts.Reload(10)
	if len(emptyResult.Tasks) != 0 {
		t.Errorf("Reload after cleanup got %d, want 0", len(emptyResult.Tasks))
	}
}

func TestTaskStore_ReloadBatchLimit(t *testing.T) {
	store := newTestStore(t)
	ts := NewTaskStore(store)

	for i := 0; i < 5; i++ {
		parsed := newTestParsedRequest("c", "DELETE", "/api/images/"+string(rune('0'+i)))
		ts.Overflow(OverflowTask{Parsed: parsed, Risk: types.L2})
	}

	result, err := ts.Reload(2)
	if err != nil {
		t.Fatalf("Reload error: %v", err)
	}
	if len(result.Tasks) != 2 {
		t.Fatalf("Reload got %d tasks, want 2", len(result.Tasks))
	}

	pending, _ := ts.PendingCount()
	if pending.Count != 5 {
		t.Errorf("PendingCount = %d, want 5", pending.Count)
	}

	var keys [][]byte
	for _, rt := range result.Tasks {
		keys = append(keys, rt.Key)
	}
	ts.Cleanup(keys)

	pending, _ = ts.PendingCount()
	if pending.Count != 3 {
		t.Errorf("PendingCount after cleanup = %d, want 3", pending.Count)
	}
}

func TestTaskStore_PendingCount(t *testing.T) {
	store := newTestStore(t)
	ts := NewTaskStore(store)

	pending, _ := ts.PendingCount()
	if pending.Count != 0 {
		t.Errorf("empty store PendingCount = %d, want 0", pending.Count)
	}

	for i := 0; i < 10; i++ {
		parsed := newTestParsedRequest("c", "POST", "/api/test")
		ts.Overflow(OverflowTask{Parsed: parsed, Risk: types.L1})
	}

	pending, _ = ts.PendingCount()
	if pending.Count != 10 {
		t.Errorf("PendingCount = %d, want 10", pending.Count)
	}
}

// ============================================================
// DispatchManager 基础测试
// ============================================================

func TestDispatchManager_EnqueueAndProcess(t *testing.T) {
	store := newTestStore(t)
	dm := NewDispatchManager(DispatcherConfig{
		Policy: PoolPolicy{
			MinWorkers:           2,
			MaxWorkers:           8,
			MaxQueueSize:         64,
			HealthCheckIntervalSec: 5,
		},
		Store: store,
		DecisionFn: func(_ *types.ConnectionContext, _ []*types.ConnectionSummary, _ types.RiskLevel) *types.Decision {
			return &types.Decision{Action: types.ALLOW, Reason: "test-ok", RuleID: "test"}
		},
	})
	defer dm.Shutdown()

	parsed := newTestParsedRequest("c1", "GET", "/api/cloud/public/images")
	decision := dm.Enqueue(parsed, types.L0)

	if decision.Action != types.ALLOW {
		t.Errorf("action = %d, want ALLOW", decision.Action)
	}
	if decision.Reason != "test-ok" {
		t.Errorf("reason = %q, want test-ok", decision.Reason)
	}
}

func TestDispatchManager_ConcurrentEnqueue(t *testing.T) {
	store := newTestStore(t)
	dm := NewDispatchManager(DispatcherConfig{
		Policy: PoolPolicy{
			MinWorkers:           4,
			MaxWorkers:           16,
			MaxQueueSize:         256,
			HealthCheckIntervalSec: 5,
		},
		Store: store,
		DecisionFn: func(_ *types.ConnectionContext, _ []*types.ConnectionSummary, _ types.RiskLevel) *types.Decision {
			return &types.Decision{Action: types.ALLOW}
		},
	})
	defer dm.Shutdown()

	var wg sync.WaitGroup
	n := 100
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(idx int) {
			defer wg.Done()
			parsed := newTestParsedRequest("c", "POST", "/api/vms/start")
			decision := dm.Enqueue(parsed, types.L1)
			if decision == nil {
				t.Error("nil decision")
			}
		}(i)
	}
	wg.Wait()

	stats := dm.GetStats()
	if stats.Processed != int64(n) {
		t.Errorf("Processed = %d, want %d", stats.Processed, n)
	}
}

func TestDispatchManager_OverflowToStorage(t *testing.T) {
	store := newTestStore(t)
	dm := NewDispatchManager(DispatcherConfig{
		Policy: PoolPolicy{
			MinWorkers:           1,
			MaxWorkers:           2,
			MaxQueueSize:         4,
			HealthCheckIntervalSec: 1,
		},
		Store: store,
		DecisionFn: func(_ *types.ConnectionContext, _ []*types.ConnectionSummary, _ types.RiskLevel) *types.Decision {
			time.Sleep(50 * time.Millisecond)
			return &types.Decision{Action: types.ALLOW}
		},
	})
	defer dm.Shutdown()

	var wg sync.WaitGroup
	n := 20
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			parsed := newTestParsedRequest("c", "POST", "/api/vms/start")
			dm.Enqueue(parsed, types.L1)
		}()
	}
	wg.Wait()

	stats := dm.GetStats()
	if stats.Overflowed == 0 {
		t.Error("expected some tasks to be overflowed to storage")
	}
	if stats.Processed < int64(n) {
		t.Errorf("Processed = %d, want >= %d", stats.Processed, n)
	}
}

func TestDispatchManager_ScaleUp(t *testing.T) {
	store := newTestStore(t)
	dm := NewDispatchManager(DispatcherConfig{
		Policy: PoolPolicy{
			MinWorkers:           1,
			MaxWorkers:           8,
			ScaleUpThreshold:     5,
			ScaleUpStep:          2,
			ScaleDownThreshold:   1,
			ScaleDownStep:        1,
			MaxQueueSize:         128,
			HealthCheckIntervalSec: 1,
		},
		Store: store,
		DecisionFn: func(_ *types.ConnectionContext, _ []*types.ConnectionSummary, _ types.RiskLevel) *types.Decision {
			time.Sleep(100 * time.Millisecond)
			return &types.Decision{Action: types.ALLOW}
		},
	})
	defer dm.Shutdown()

	initialWorkers := dm.workerCount()

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			parsed := newTestParsedRequest("c", "POST", "/api/vms/start")
			dm.Enqueue(parsed, types.L1)
		}()
	}

	time.Sleep(2 * time.Second)

	now := dm.workerCount()
	if now <= initialWorkers {
		t.Errorf("workers did not scale up: %d <= %d", now, initialWorkers)
	}

	wg.Wait()
}

// ============================================================
// 决策引擎联调测试
// ============================================================

func TestDispatch_WithEngine_StaticRisk_L0_Allow(t *testing.T) {
	store := newTestStore(t)
	decisionFn := newEngineDecisionFn(store)
	dm := NewDispatchManager(DispatcherConfig{
		Policy: PoolPolicy{
			MinWorkers:           2,
			MaxWorkers:           8,
			MaxQueueSize:         64,
			HealthCheckIntervalSec: 5,
		},
		Store:      store,
		DecisionFn: decisionFn,
	})
	defer dm.Shutdown()

	parsed := newTestParsedRequest("c-l0", "GET", "/api/cloud/public/images")
	decision := dm.Enqueue(parsed, types.L0)

	if decision.Action != types.ALLOW {
		t.Errorf("L0 action = %d, want ALLOW", decision.Action)
	}
	if decision.RuleID != "R99" {
		t.Errorf("RuleID = %q, want R99", decision.RuleID)
	}
}

func TestDispatch_WithEngine_StaticRisk_L1_Audit(t *testing.T) {
	store := newTestStore(t)
	dm := NewDispatchManager(DispatcherConfig{
		Policy: PoolPolicy{
			MinWorkers:           2,
			MaxWorkers:           8,
			MaxQueueSize:         64,
			HealthCheckIntervalSec: 5,
		},
		Store: store,
		DecisionFn: func(ctx *types.ConnectionContext, history []*types.ConnectionSummary, riskLevel types.RiskLevel) *types.Decision {
			for i := 0; i < 4; i++ {
				ctx.RecordEvent("GET /api/cloud/public/images")
			}
			ctx.RecordEvent("POST /api/vms/start")
			return decision.NewEngine(portrait.NewStore(store)).Evaluate(ctx, history, riskLevel)
		},
	})
	defer dm.Shutdown()

	parsed := newTestParsedRequest("c-l1", "POST", "/api/vms/start")
	decision := dm.Enqueue(parsed, types.L1)

	if decision.Action != types.AUDIT {
		t.Errorf("L1 action = %d, want AUDIT (R99)", decision.Action)
	}
}

func TestDispatch_WithEngine_StaticRisk_L2_Alert(t *testing.T) {
	store := newTestStore(t)
	decisionFn := newEngineDecisionFn(store)
	dm := NewDispatchManager(DispatcherConfig{
		Policy: PoolPolicy{
			MinWorkers:           2,
			MaxWorkers:           8,
			MaxQueueSize:         64,
			HealthCheckIntervalSec: 5,
		},
		Store:      store,
		DecisionFn: decisionFn,
	})
	defer dm.Shutdown()

	parsed := newTestParsedRequest("c-l2", "DELETE", "/api/cloud/public/images")
	decision := dm.Enqueue(parsed, types.L2)

	if decision.Action != types.ALERT {
		t.Errorf("L2 action = %d, want ALERT (R99)", decision.Action)
	}
}

func TestDispatch_WithEngine_R07_BulkDelete(t *testing.T) {
	store := newTestStore(t)
	ps := portrait.NewStore(store)
	engine := decision.NewEngine(ps)
	dm := NewDispatchManager(DispatcherConfig{
		Policy: PoolPolicy{
			MinWorkers:           1,
			MaxWorkers:           2,
			MaxQueueSize:         64,
			HealthCheckIntervalSec: 5,
		},
		Store: store,
		DecisionFn: func(ctx *types.ConnectionContext, history []*types.ConnectionSummary, riskLevel types.RiskLevel) *types.Decision {
			for i := 0; i < 4; i++ {
				ctx.RecordEvent("image.delete")
			}
			return engine.Evaluate(ctx, history, riskLevel)
		},
	})
	defer dm.Shutdown()

	parsed := newTestParsedRequest("c-del", "DELETE", "/api/cloud/public/images")
	decision := dm.Enqueue(parsed, types.L1)

	if decision.Action != types.BLOCK_DEVICE {
		t.Errorf("action = %d, want BLOCK_DEVICE", decision.Action)
	}
	if decision.RuleID != "R07_BULK_DELETE" {
		t.Errorf("RuleID = %q, want R07_BULK_DELETE", decision.RuleID)
	}
}

func TestDispatch_WithEngine_R08_UploadThenStart(t *testing.T) {
	store := newTestStore(t)
	ps := portrait.NewStore(store)
	engine := decision.NewEngine(ps)
	dm := NewDispatchManager(DispatcherConfig{
		Policy: PoolPolicy{
			MinWorkers:           1,
			MaxWorkers:           2,
			MaxQueueSize:         64,
			HealthCheckIntervalSec: 5,
		},
		Store: store,
		DecisionFn: func(ctx *types.ConnectionContext, history []*types.ConnectionSummary, riskLevel types.RiskLevel) *types.Decision {
			ctx.RecordEvent("image.upload")
			ctx.RecordEvent("vm.start")
			return engine.Evaluate(ctx, history, riskLevel)
		},
	})
	defer dm.Shutdown()

	parsed := newTestParsedRequest("c-upload", "POST", "/api/cloud/public/images")
	decision := dm.Enqueue(parsed, types.L1)

	if decision.Action != types.QUARANTINE_AND_ALERT {
		t.Errorf("action = %d, want QUARANTINE_AND_ALERT", decision.Action)
	}
}

func TestDispatch_WithEngine_NormalGet_Allow(t *testing.T) {
	store := newTestStore(t)
	decisionFn := newEngineDecisionFn(store)
	dm := NewDispatchManager(DispatcherConfig{
		Policy: PoolPolicy{
			MinWorkers:           2,
			MaxWorkers:           8,
			MaxQueueSize:         64,
			HealthCheckIntervalSec: 5,
		},
		Store:      store,
		DecisionFn: decisionFn,
	})
	defer dm.Shutdown()

	parsed := newTestParsedRequest("c-get", "GET", "/api/cloud/public/images")
	decision := dm.Enqueue(parsed, types.L0)

	if decision.Action != types.ALLOW {
		t.Errorf("action = %d, want ALLOW", decision.Action)
	}
}

func TestDispatch_WithEngine_ConcurrentMixedRisk(t *testing.T) {
	store := newTestStore(t)
	decisionFn := newEngineDecisionFn(store)
	dm := NewDispatchManager(DispatcherConfig{
		Policy: PoolPolicy{
			MinWorkers:           4,
			MaxWorkers:           8,
			MaxQueueSize:         128,
			HealthCheckIntervalSec: 5,
		},
		Store:      store,
		DecisionFn: decisionFn,
	})
	defer dm.Shutdown()

	var mu sync.Mutex
	results := make(map[types.Action]int)

	var wg sync.WaitGroup
	n := 50
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(idx int) {
			defer wg.Done()
			var parsed *types.ParsedRequest
			var risk types.RiskLevel
			switch idx % 4 {
			case 0:
				parsed = newTestParsedRequest("c", "GET", "/api/cloud/public/images")
				risk = types.L0
			case 1:
				parsed = newTestParsedRequest("c", "POST", "/api/vms/start")
				risk = types.L1
			case 2:
				parsed = newTestParsedRequest("c", "DELETE", "/api/cloud/public/images")
				risk = types.L2
			case 3:
				parsed = newTestParsedRequest("c", "POST", "/api/unknown")
				risk = types.L1
			}
			decision := dm.Enqueue(parsed, risk)
			mu.Lock()
			results[decision.Action]++
			mu.Unlock()
		}(i)
	}
	wg.Wait()

	if results[types.ALLOW] == 0 {
		t.Error("expected some ALLOW decisions from L0 GET")
	}
	if results[types.ALERT] == 0 {
		t.Error("expected some ALERT decisions from L2 DELETE")
	}

	total := 0
	for _, v := range results {
		total += v
	}
	if total != n {
		t.Errorf("total decisions = %d, want %d", total, n)
	}
}

// TestDispatch_WithEngine_OverflowPreservesDecision
// 决策函数加延迟 -> 队列打满 -> 溢出到 bbolt -> 回捞 -> 决策结果不变
func TestDispatch_WithEngine_OverflowPreservesDecision(t *testing.T) {
	store := newTestStore(t)
	decisionFn := newEngineDecisionFn(store)

	dm := NewDispatchManager(DispatcherConfig{
		Policy: PoolPolicy{
			MinWorkers:           1,
			MaxWorkers:           2,
			MaxQueueSize:         4,
			HealthCheckIntervalSec: 1,
		},
		Store: store,
		DecisionFn: func(ctx *types.ConnectionContext, history []*types.ConnectionSummary, riskLevel types.RiskLevel) *types.Decision {
			time.Sleep(20 * time.Millisecond)
			return decisionFn(ctx, history, riskLevel)
		},
	})
	defer dm.Shutdown()

	var wg sync.WaitGroup
	var mu sync.Mutex
	decisions := make(map[types.Action]int)
	n := 10
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			parsed := newTestParsedRequest("c", "DELETE", "/api/cloud/public/images")
			decision := dm.Enqueue(parsed, types.L2)
			mu.Lock()
			decisions[decision.Action]++
			mu.Unlock()
		}()
	}
	wg.Wait()

	stats := dm.GetStats()
	if stats.Overflowed == 0 {
		t.Error("expected overflow to storage")
	}

	if decisions[types.ALERT] != n {
		t.Errorf("ALERT decisions = %d, want %d (overflow must not change decision)", decisions[types.ALERT], n)
	}
}
