package router

import (
	"sync"
	"testing"

	"Threshold/pkg/types"
	"Threshold/server/output"
)

// mockDispatcher 模拟 DispatchManager
type mockDispatcher struct {
	mu        sync.Mutex
	enqueued  bool
	lastLevel types.RiskLevel
}

func (m *mockDispatcher) Enqueue(parsed *types.ParsedRequest, riskLevel types.RiskLevel) *types.Decision {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.enqueued = true
	m.lastLevel = riskLevel
	return &types.Decision{Action: types.ALLOW, RuleID: "mock"}
}

func TestOperationRiskTable_ExactMatch(t *testing.T) {
	table := NewOperationRiskTable()
	tests := []struct {
		method string
		path   string
		want   types.RiskLevel
	}{
		{"GET", "/api/cloud/public/images", types.L0},
		{"GET", "/api/vms/status", types.L0},
		{"POST", "/api/cloud/public/images", types.L1},
		{"POST", "/api/vms/start", types.L1},
		{"PUT", "/api/vms/config", types.L1},
		{"DELETE", "/api/cloud/public/images", types.L2},
		{"DELETE", "/api/local/images", types.L2},
	}
	for _, tt := range tests {
		got := table.Lookup(tt.method, tt.path)
		if got != tt.want {
			t.Errorf("Lookup(%q, %q) = %d, want %d", tt.method, tt.path, got, tt.want)
		}
	}
}

func TestOperationRiskTable_WildcardMatch(t *testing.T) {
	table := NewOperationRiskTable()
	tests := []struct {
		method string
		path   string
		want   types.RiskLevel
	}{
		{"POST", "/api/vms/reboot", types.L1},
		{"POST", "/api/vms/migrate", types.L1},
		{"DELETE", "/api/some/other/path", types.L2},
	}
	for _, tt := range tests {
		got := table.Lookup(tt.method, tt.path)
		if got != tt.want {
			t.Errorf("Lookup(%q, %q) = %d, want %d", tt.method, tt.path, got, tt.want)
		}
	}
}

func TestOperationRiskTable_DefaultL1(t *testing.T) {
	table := NewOperationRiskTable()
	got := table.Lookup("POST", "/api/unknown/endpoint")
	if got != types.L1 {
		t.Errorf("Lookup(POST, /api/unknown/endpoint) = %d, want L1", got)
	}
}

func TestClassifyByMethod(t *testing.T) {
	tests := []struct {
		method string
		want   types.RiskLevel
	}{
		{"GET", types.L0}, {"HEAD", types.L0}, {"OPTIONS", types.L0},
		{"POST", types.L1}, {"PUT", types.L1}, {"PATCH", types.L1},
		{"DELETE", types.L2},
	}
	for _, tt := range tests {
		got := ClassifyByMethod(tt.method)
		if got != tt.want {
			t.Errorf("ClassifyByMethod(%q) = %d, want %d", tt.method, got, tt.want)
		}
	}
}

func TestRouter_Classify(t *testing.T) {
	table := NewOperationRiskTable()
	out := output.NewOutputBuffer()
	dispatch := &mockDispatcher{}
	r := NewRouter(table, out, dispatch, 1, 64)
	defer r.Shutdown()

	parsed := &types.ParsedRequest{Method: "GET", Path: "/api/cloud/public/images"}
	if got := r.Classify(parsed); got != types.L0 {
		t.Errorf("Classify(GET ...) = %d, want L0", got)
	}

	parsed2 := &types.ParsedRequest{Method: "DELETE", Path: "/api/cloud/public/images"}
	if got := r.Classify(parsed2); got != types.L2 {
		t.Errorf("Classify(DELETE ...) = %d, want L2", got)
	}
}

func TestRouter_RouteAsync_L0(t *testing.T) {
	table := NewOperationRiskTable()
	out := output.NewOutputBuffer()
	dispatch := &mockDispatcher{}
	r := NewRouter(table, out, dispatch, 2, 64)
	defer r.Shutdown()

	parsed := &types.ParsedRequest{ConnectionID: "c1", Method: "GET", Path: "/api/cloud/public/images"}
	decision, err := r.RouteAsync(parsed)
	if err != nil {
		t.Fatalf("RouteAsync error: %v", err)
	}
	if decision.Action != types.ALLOW {
		t.Errorf("L0 action = %d, want ALLOW", decision.Action)
	}
	if dispatch.enqueued {
		t.Error("L0 should not be enqueued")
	}
}

func TestRouter_RouteAsync_L1(t *testing.T) {
	table := NewOperationRiskTable()
	out := output.NewOutputBuffer()
	dispatch := &mockDispatcher{}
	r := NewRouter(table, out, dispatch, 2, 64)
	defer r.Shutdown()

	parsed := &types.ParsedRequest{ConnectionID: "c2", Method: "POST", Path: "/api/vms/start"}
	_, err := r.RouteAsync(parsed)
	if err != nil {
		t.Fatalf("RouteAsync error: %v", err)
	}
	dispatch.mu.Lock()
	defer dispatch.mu.Unlock()
	if !dispatch.enqueued {
		t.Error("L1 should be enqueued")
	}
	if dispatch.lastLevel != types.L1 {
		t.Errorf("dispatcher got level %d, want L1", dispatch.lastLevel)
	}
}

func TestRouter_RouteAsync_L2(t *testing.T) {
	table := NewOperationRiskTable()
	out := output.NewOutputBuffer()
	dispatch := &mockDispatcher{}
	r := NewRouter(table, out, dispatch, 2, 64)
	defer r.Shutdown()

	parsed := &types.ParsedRequest{ConnectionID: "c3", Method: "DELETE", Path: "/api/cloud/public/images"}
	_, err := r.RouteAsync(parsed)
	if err != nil {
		t.Fatalf("RouteAsync error: %v", err)
	}
	dispatch.mu.Lock()
	defer dispatch.mu.Unlock()
	if !dispatch.enqueued {
		t.Error("L2 should be enqueued")
	}
	if dispatch.lastLevel != types.L2 {
		t.Errorf("dispatcher got level %d, want L2", dispatch.lastLevel)
	}
}

func TestRouter_RouteAsync_Backpressure(t *testing.T) {
	table := NewOperationRiskTable()
	out := output.NewOutputBuffer()
	dispatch := &mockDispatcher{}
	r := NewRouter(table, out, dispatch, 1, 2)
	defer r.Shutdown()

	parsed := &types.ParsedRequest{ConnectionID: "c4", Method: "POST", Path: "/api/vms/start"}
	for i := 0; i < 2; i++ {
		r.inputCh <- routeRequest{parsed: parsed, resultCh: make(chan *types.Decision, 1)}
	}
	_, err := r.RouteAsync(parsed)
	if err == nil {
		t.Error("expected backpressure error")
	}
}

func TestRouter_Concurrent(t *testing.T) {
	table := NewOperationRiskTable()
	out := output.NewOutputBuffer()
	dispatch := &mockDispatcher{}
	r := NewRouter(table, out, dispatch, 4, 256)
	defer r.Shutdown()

	var wg sync.WaitGroup
	n := 200
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			parsed := &types.ParsedRequest{
				ConnectionID: "c",
				Method:       "GET",
				Path:         "/api/cloud/public/images",
			}
			_, err := r.RouteAsync(parsed)
			if err != nil {
				t.Errorf("RouteAsync error: %v", err)
			}
		}()
	}
	wg.Wait()

	msgs := out.Pull()
	if len(msgs) != n {
		t.Errorf("OutputBuffer got %d messages, want %d", len(msgs), n)
	}
}

func TestRouter_MultiConsumer(t *testing.T) {
	table := NewOperationRiskTable()
	out := output.NewOutputBuffer()
	dispatch := &mockDispatcher{}
	nConsumers := 8
	r := NewRouter(table, out, dispatch, nConsumers, 256)
	defer r.Shutdown()

	var wg sync.WaitGroup
	n := 500
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			parsed := &types.ParsedRequest{
				ConnectionID: "c",
				Method:       "GET",
				Path:         "/api/cloud/public/images",
			}
			_, err := r.RouteAsync(parsed)
			if err != nil {
				t.Errorf("RouteAsync error: %v", err)
			}
		}()
	}
	wg.Wait()

	msgs := out.Pull()
	if len(msgs) != n {
		t.Errorf("OutputBuffer got %d messages, want %d", len(msgs), n)
	}
}

func TestRouter_Shutdown(t *testing.T) {
	table := NewOperationRiskTable()
	out := output.NewOutputBuffer()
	dispatch := &mockDispatcher{}
	r := NewRouter(table, out, dispatch, 2, 64)
	r.Shutdown()

	parsed := &types.ParsedRequest{ConnectionID: "c", Method: "GET", Path: "/api/cloud/public/images"}
	_, err := r.RouteAsync(parsed)
	if err == nil {
		t.Error("expected error after shutdown")
	}
}

func TestRouter_QueueLen(t *testing.T) {
	table := NewOperationRiskTable()
	out := output.NewOutputBuffer()
	dispatch := &mockDispatcher{}
	r := NewRouter(table, out, dispatch, 2, 64)
	defer r.Shutdown()

	if r.QueueLen() != 0 {
		t.Errorf("QueueLen() = %d, want 0", r.QueueLen())
	}
}
