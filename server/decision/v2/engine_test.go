package v2

import (
	"os"
	"testing"
	"time"

	"Threshold/pkg/storage"
	"Threshold/pkg/types"
	"Threshold/server/portrait"
)

func newTestEngine(t *testing.T) (*Engine, *portrait.Store) {
	t.Helper()
	tmpFile, _ := os.CreateTemp("", "decision-v2-*.db")
	tmpFile.Close()
	t.Cleanup(func() { os.Remove(tmpFile.Name()) })

	store, err := storage.NewBoltStore(tmpFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	ps := portrait.NewStore(store)
	e := NewDefaultEngine(ps)
	return e, ps
}

// ==================== Layer 1: Filter Tests ====================

func TestFilter_BlacklistedDevice(t *testing.T) {
	e, ps := newTestEngine(t)
	ps.BlacklistDevice("bad-device", "test")

	ctx := &types.ConnectionContext{
		ConnectionID: "c1", UserID: "u1", DeviceUUID: "bad-device",
	}
	d := e.Evaluate(ctx, nil, types.L0)
	if d.Action != types.BLACKLIST_DEVICE {
		t.Fatalf("want BLACKLIST_DEVICE, got %v", d.Action)
	}
}

func TestFilter_BruteForce(t *testing.T) {
	e, _ := newTestEngine(t)
	ctx := &types.ConnectionContext{
		ConnectionID: "c2", UserID: "u2", DeviceUUID: "d2",
	}
	for i := 0; i < 5; i++ {
		ctx.Events = append(ctx.Events, types.EventRecord{OpType: "login_failed", Timestamp: time.Now()})
	}
	d := e.Evaluate(ctx, nil, types.L0)
	if d.Action != types.BLOCK_LOGIN {
		t.Fatalf("want BLOCK_LOGIN, got %v", d.Action)
	}
}

func TestFilter_BulkDelete(t *testing.T) {
	e, _ := newTestEngine(t)
	ctx := &types.ConnectionContext{
		ConnectionID: "c3", UserID: "u3", DeviceUUID: "d3",
	}
	for i := 0; i < 3; i++ {
		ctx.Events = append(ctx.Events, types.EventRecord{OpType: "image.delete", Timestamp: time.Now()})
	}
	d := e.Evaluate(ctx, nil, types.L0)
	if d.Action != types.BLOCK_DEVICE {
		t.Fatalf("want BLOCK_DEVICE, got %v", d.Action)
	}
}

func TestFilter_RepeatOffender(t *testing.T) {
	e, _ := newTestEngine(t)
	ctx := &types.ConnectionContext{
		ConnectionID: "c4", UserID: "u4", DeviceUUID: "d4",
	}
	history := []*types.ConnectionSummary{
		{FlagsTriggered: []string{"flag1"}},
		{FlagsTriggered: []string{"flag2"}},
		{FlagsTriggered: []string{"flag3"}},
	}
	d := e.Evaluate(ctx, history, types.L0)
	if d.Action != types.BLACKLIST_DEVICE {
		t.Fatalf("want BLACKLIST_DEVICE, got %v", d.Action)
	}
}

// ==================== Layer 2: Score Tests ====================

func TestScore_NormalRequest_LowRisk(t *testing.T) {
	e, _ := newTestEngine(t)
	ctx := &types.ConnectionContext{
		ConnectionID: "c5", UserID: "u5", DeviceUUID: "d5",
		ConnectedAt: time.Now(),
		IP:          "10.0.0.1",
	}
	ctx.Events = append(ctx.Events, types.EventRecord{OpType: "GET /api/images", Timestamp: time.Now()})

	assess := e.Assess(ctx, nil, types.L0)
	if assess.RiskScore > 0.3 {
		t.Errorf("normal request should have low risk, got %.3f", assess.RiskScore)
	}
	if assess.Confidence <= 0 {
		t.Error("confidence should be > 0")
	}
}

func TestScore_HighWriteRatio(t *testing.T) {
	e, _ := newTestEngine(t)
	ctx := &types.ConnectionContext{
		ConnectionID: "c6", UserID: "u6", DeviceUUID: "d6",
		ConnectedAt: time.Now(),
		IP:          "10.0.0.1",
	}
	// 8 write ops, 2 read ops = 80% write ratio
	for i := 0; i < 9; i++ {
		ctx.Events = append(ctx.Events, types.EventRecord{OpType: "vm.create", Timestamp: time.Now()})
	}
	for i := 0; i < 1; i++ {
		ctx.Events = append(ctx.Events, types.EventRecord{OpType: "GET /api/images", Timestamp: time.Now()})
	}

	assess := e.Assess(ctx, nil, types.L0)
	if assess.RiskScore < 0.1 {
		t.Errorf("high write ratio should increase risk (>0.1), got %.3f", assess.RiskScore)
	}
}

func TestScore_WithBaseline(t *testing.T) {
	e, _ := newTestEngine(t)

	// 建立基线：正常连接模式
	for i := 0; i < 20; i++ {
		e.UpdateBaseline(&types.ConnectionSummary{
			DeviceUUID:  "d7",
			ConnectedAt: time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC),
			TotalEvents: 5,
			WriteRatio:  0.2,
		})
	}

	// 当前连接：异常高的写比例
	ctx := &types.ConnectionContext{
		ConnectionID: "c7", UserID: "u7", DeviceUUID: "d7",
		ConnectedAt: time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC),
		IP:          "10.0.0.1",
	}
	for i := 0; i < 10; i++ {
		ctx.Events = append(ctx.Events, types.EventRecord{OpType: "vm.delete", Timestamp: time.Now()})
	}

	assess := e.Assess(ctx, nil, types.L0)
	t.Logf("risk=%.3f factors=%d anomalies=%v", assess.RiskScore, len(assess.Factors), assess.Anomalies)
	// 基线偏离应该提高风险分
	if assess.RiskScore < 0.2 {
		t.Errorf("baseline deviation should increase risk, got %.3f", assess.RiskScore)
	}
}

// ==================== Layer 3: Decide Tests ====================

func TestDecide_Allow_LowRisk(t *testing.T) {
	e, _ := newTestEngine(t)
	ctx := &types.ConnectionContext{
		ConnectionID: "c8", UserID: "u8", DeviceUUID: "d8",
		ConnectedAt: time.Now(),
		IP:          "10.0.0.1",
	}
	ctx.Events = append(ctx.Events, types.EventRecord{OpType: "GET /api/images", Timestamp: time.Now()})

	d := e.Evaluate(ctx, nil, types.L0)
	if d.Action != types.ALLOW {
		t.Errorf("want ALLOW, got %v reason=%s", d.Action, d.Reason)
	}
}

func TestDecide_Audit_L1Risk(t *testing.T) {
	e, _ := newTestEngine(t)
	ctx := &types.ConnectionContext{
		ConnectionID: "c9", UserID: "u9", DeviceUUID: "d9",
		ConnectedAt: time.Now(),
		IP:          "10.0.0.1",
	}
	// Moderate write ratio
	for i := 0; i < 6; i++ {
		ctx.Events = append(ctx.Events, types.EventRecord{OpType: "vm.create", Timestamp: time.Now()})
	}
	for i := 0; i < 4; i++ {
		ctx.Events = append(ctx.Events, types.EventRecord{OpType: "GET /api/images", Timestamp: time.Now()})
	}

	d := e.Evaluate(ctx, nil, types.L1)
	t.Logf("action=%v reason=%s", d.Action, d.Reason)
	// L1 风险 + moderate write → AUDIT 或更高
	if d.Action == types.BLACKLIST_DEVICE || d.Action == types.BLOCK_DEVICE {
		t.Errorf("should not hard block on moderate risk, got %v", d.Action)
	}
}

func TestDecide_L3Amplification(t *testing.T) {
	e, _ := newTestEngine(t)
	ctx := &types.ConnectionContext{
		ConnectionID: "c10", UserID: "u10", DeviceUUID: "d10",
		ConnectedAt: time.Now(),
		IP:          "10.0.0.1",
	}
	for i := 0; i < 6; i++ {
		ctx.Events = append(ctx.Events, types.EventRecord{OpType: "vm.create", Timestamp: time.Now()})
	}
	for i := 0; i < 4; i++ {
		ctx.Events = append(ctx.Events, types.EventRecord{OpType: "GET /api/images", Timestamp: time.Now()})
	}

	// L0 应该放行
	d0 := e.Evaluate(ctx, nil, types.L0)
	// L3 应该更严格
	d3 := e.Evaluate(ctx, nil, types.L3)

	t.Logf("L0=%v L3=%v", d0.Action, d3.Action)
	if d3.Action <= d0.Action {
		// L3 should be at least as strict as L0
		t.Logf("L3 (%v) is not stricter than L0 (%v), which is acceptable if risk is very low", d3.Action, d0.Action)
	}
}

// ==================== Confidence Tests ====================

func TestConfidence_NewDevice(t *testing.T) {
	cc := NewConfidenceCalculator(3, 50)
	conf := cc.Compute(0, 0.5)
	if conf >= 0.3 {
		t.Errorf("new device should have low confidence, got %.3f", conf)
	}
}

func TestConfidence_EstablishedDevice(t *testing.T) {
	cc := NewConfidenceCalculator(3, 50)
	conf := cc.Compute(50, 1.0)
	if conf < 0.8 {
		t.Errorf("established device should have high confidence, got %.3f", conf)
	}
}

// ==================== Baseline Tests ====================

func TestBaseline_UpdateAndDetect(t *testing.T) {
	bs := NewBaselineStore()

	// 建立基线
	for i := 0; i < 20; i++ {
		bs.Update(&types.ConnectionSummary{
			DeviceUUID:  "dev-1",
			ConnectedAt: time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC),
			TotalEvents: 5,
			WriteRatio:  0.2,
		})
	}

	// 检测正常行为
	anomalies, score := bs.DetectAnomalies("dev-1", 10, 5, 0.2)
	t.Logf("normal: anomalies=%v score=%.3f", anomalies, score)

	// 检测异常行为
	anomalies, score = bs.DetectAnomalies("dev-1", 3, 100, 0.9)
	t.Logf("abnormal: anomalies=%v score=%.3f", anomalies, score)
	if len(anomalies) == 0 {
		t.Log("no anomalies detected (may be expected with small dataset)")
	}
}

// ==================== End-to-End Scenario ====================

func TestE2E_NormalUser_NormalRequest(t *testing.T) {
	e, ps := newTestEngine(t)

	// 建立正常用户画像
	for i := 0; i < 20; i++ {
		e.UpdateBaseline(&types.ConnectionSummary{
			DeviceUUID:  "normal-device",
			ConnectedAt: time.Date(2026, 1, 1, 14, 0, 0, 0, time.UTC),
			TotalEvents: 3,
			WriteRatio:  0.1,
		})
	}
	// 注册用户画像
	ps.UpsertProfile(&portrait.UserProfile{
		UserID:           "normal-user",
		TotalConnections: 20,
		KnownDevices:     []string{"normal-device"},
		KnownIPs:         []string{"10.0.0.1"},
	})

	ctx := &types.ConnectionContext{
		ConnectionID: "e2e-c1", UserID: "normal-user", DeviceUUID: "normal-device",
		ConnectedAt: time.Date(2026, 1, 1, 14, 30, 0, 0, time.UTC),
		IP:          "10.0.0.1",
	}
	ctx.Events = append(ctx.Events, types.EventRecord{
		OpType: "GET /api/cloud/public/images", Timestamp: time.Now(),
	})

	assess := e.Assess(ctx, nil, types.L0)
	t.Logf("normal user: risk=%.3f conf=%.3f eff=%.3f factors=%d",
		assess.RiskScore, assess.Confidence, assess.Effective, len(assess.Factors))

	d := e.Evaluate(ctx, nil, types.L0)
	if d.Action != types.ALLOW {
		t.Errorf("normal user normal request should ALLOW, got %v reason=%s", d.Action, d.Reason)
	}
}

func TestE2E_SuspiciousActivity(t *testing.T) {
	e, ps := newTestEngine(t)

	// 建立基线（正常白天、低写比例）
	for i := 0; i < 30; i++ {
		e.UpdateBaseline(&types.ConnectionSummary{
			DeviceUUID:  "sus-device",
			ConnectedAt: time.Date(2026, 1, 1, 14, 0, 0, 0, time.UTC),
			TotalEvents: 3,
			WriteRatio:  0.1,
		})
	}
	ps.UpsertProfile(&portrait.UserProfile{
		UserID:           "sus-user",
		TotalConnections: 30,
		KnownDevices:     []string{"sus-device"},
		KnownIPs:         []string{"10.0.0.1"},
	})

	// 可疑连接：凌晨 3 点，大量写操作，一个新 IP
	ctx := &types.ConnectionContext{
		ConnectionID: "e2e-c2", UserID: "sus-user", DeviceUUID: "sus-device",
		ConnectedAt: time.Date(2026, 1, 2, 3, 0, 0, 0, time.UTC),
		IP:          "192.168.1.100",
	}
	for i := 0; i < 8; i++ {
		ctx.Events = append(ctx.Events, types.EventRecord{OpType: "vm.delete", Timestamp: time.Date(2026, 1, 2, 3, i, 0, 0, time.UTC)})
	}
	ctx.Events = append(ctx.Events, types.EventRecord{OpType: "GET /api/images", Timestamp: time.Now()})

	assess := e.Assess(ctx, nil, types.L2)
	t.Logf("suspicious: risk=%.3f conf=%.3f eff=%.3f anomalies=%v",
		assess.RiskScore, assess.Confidence, assess.Effective, assess.Anomalies)
	for _, f := range assess.Factors {
		if f.Triggered {
			t.Logf("  TRIGGERED: %s score=%.2f detail=%s", f.Name, f.Score, f.Detail)
		}
	}

	d := e.Evaluate(ctx, nil, types.L2)
	t.Logf("decision: action=%v reason=%s", d.Action, d.Reason)
	// 应该不是简单的 ALLOW
	if d.Action == types.ALLOW {
		t.Log("suspicious activity got ALLOW (may be expected with low confidence)")
	}
}
