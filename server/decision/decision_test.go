package decision

import (
	"os"

	"testing"

	"time"

	"Threshold/pkg/storage"

	"Threshold/pkg/types"

	"Threshold/server/portrait"
)

func newTestEngine(t *testing.T) *Engine {

	t.Helper()

	tmpFile, _ := os.CreateTemp("", "decision-scripts-*.db")

	tmpFile.Close()

	t.Cleanup(func() { os.Remove(tmpFile.Name()) })

	store, err := storage.NewBoltStore(tmpFile.Name())

	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { store.Close() })

	return NewEngine(portrait.NewStore(store))
}

func TestEvaluate_R06_BruteForceLogin(t *testing.T) {

	e := newTestEngine(t)

	ctx := &types.ConnectionContext{ConnectionID: "c1", UserID: "u1", DeviceUUID: "d1", IP: "10.0.0.1"}

	for i := 0; i < 6; i++ {

		ctx.Events = append(ctx.Events, types.EventRecord{OpType: "login_failed", Timestamp: time.Now()})

	}

	d := e.Evaluate(ctx, nil, types.L0)

	if d.Action != types.BLOCK_LOGIN {
		t.Errorf("got %d, want BLOCK_LOGIN", d.Action)
	}

	if d.RuleID != "R06_BRUTE_FORCE_LOGIN" {
		t.Errorf("got %s, want R06", d.RuleID)
	}
}

func TestEvaluate_R07_BulkDelete(t *testing.T) {

	e := newTestEngine(t)

	ctx := &types.ConnectionContext{ConnectionID: "c2", UserID: "u2", DeviceUUID: "d2", IP: "10.0.0.2"}

	for i := 0; i < 4; i++ {

		ctx.Events = append(ctx.Events, types.EventRecord{OpType: "image.delete", Timestamp: time.Now()})

	}

	d := e.Evaluate(ctx, nil, types.L0)

	if d.Action != types.BLOCK_DEVICE {
		t.Errorf("got %d, want BLOCK_DEVICE", d.Action)
	}
}

func TestEvaluate_R08_UploadThenStart(t *testing.T) {

	e := newTestEngine(t)

	ctx := &types.ConnectionContext{ConnectionID: "c3", UserID: "u3", DeviceUUID: "d3", IP: "10.0.0.3"}

	ctx.Events = append(ctx.Events, types.EventRecord{OpType: "image.upload", Timestamp: time.Now()})

	ctx.Events = append(ctx.Events, types.EventRecord{OpType: "vm.start", Timestamp: time.Now()})

	d := e.Evaluate(ctx, nil, types.L0)

	if d.Action != types.QUARANTINE_AND_ALERT {
		t.Errorf("got %d, want QUARANTINE_AND_ALERT", d.Action)
	}
}

func TestEvaluate_StaticRisk_L1(t *testing.T) {

	e := newTestEngine(t)

	ctx := &types.ConnectionContext{ConnectionID: "c4", UserID: "u4", DeviceUUID: "d4", IP: "10.0.0.1"}

	// no events, no rules triggered, falls to R99

	d := e.Evaluate(ctx, nil, types.L1)

	if d.Action != types.AUDIT {
		t.Errorf("got %d, want AUDIT", d.Action)
	}

	if d.RuleID != "R99" {
		t.Errorf("got %s, want R99", d.RuleID)
	}
}

func TestEvaluate_StaticRisk_L2(t *testing.T) {

	e := newTestEngine(t)

	ctx := &types.ConnectionContext{ConnectionID: "c5", UserID: "u5", DeviceUUID: "d5", IP: "10.0.0.1"}

	d := e.Evaluate(ctx, nil, types.L2)

	if d.Action != types.ALERT {
		t.Errorf("got %d, want ALERT", d.Action)
	}
}

func TestEvaluate_StaticRisk_L0(t *testing.T) {

	e := newTestEngine(t)

	ctx := &types.ConnectionContext{ConnectionID: "c6", UserID: "u6", DeviceUUID: "d6", IP: "10.0.0.1"}

	d := e.Evaluate(ctx, nil, types.L0)

	if d.Action != types.ALLOW {
		t.Errorf("got %d, want ALLOW", d.Action)
	}
}

func TestEvaluate_NormalGet_Allow(t *testing.T) {

	e := newTestEngine(t)

	ctx := &types.ConnectionContext{ConnectionID: "c7", UserID: "u7", DeviceUUID: "d7", IP: "10.0.0.1"}

	ctx.Events = append(ctx.Events, types.EventRecord{OpType: "GET /api/cloud/public/images", Timestamp: time.Now()})

	d := e.Evaluate(ctx, nil, types.L0)

	if d.Action != types.ALLOW {
		t.Errorf("got %d, want ALLOW", d.Action)
	}
}
