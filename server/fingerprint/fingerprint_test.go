package fingerprint

import (
	"os"
	"path/filepath"
	"testing"

	"Threshold/pkg/config"
	"Threshold/pkg/storage"
	"Threshold/pkg/types"
)

// ============================================================
// 辅助
// ============================================================

func strPtr(s string) *string {
	return &s
}

func newTestTree(t *testing.T, matchMode string) (*Tree, func()) {
	t.Helper()
	dir, err := os.MkdirTemp("", "fp-tree-*")
	if err != nil {
		t.Fatalf("mkdir temp: %v", err)
	}

	store, err := storage.NewBoltStore(filepath.Join(dir, "test.db"))
	if err != nil {
		os.RemoveAll(dir)
		t.Fatalf("new bolt: %v", err)
	}

	wal, err := storage.NewWAL(dir)
	if err != nil {
		store.Close()
		os.RemoveAll(dir)
		t.Fatalf("new wal: %v", err)
	}

	cfg := config.FingerprintConfig{
		DBPath:    filepath.Join(dir, "fp.db"),
		MatchMode: matchMode,
	}

	tree, err := NewTree(store, wal, cfg)
	if err != nil {
		wal.Close()
		store.Close()
		os.RemoveAll(dir)
		t.Fatalf("new tree: %v", err)
	}

	cleanup := func() {
		wal.Close()
		store.Close()
		os.RemoveAll(dir)
	}
	return tree, cleanup
}

// ============================================================
// 空树
// ============================================================

func TestMatch_EmptyTree(t *testing.T) {
	tree, cleanup := newTestTree(t, "strict")
	defer cleanup()

	fp := types.DeviceFingerprint{
		OS:   strPtr("linux"),
		UUID: strPtr("device-001"),
		IP:   strPtr("192.168.1.1"),
	}
	result := tree.Match(fp)
	if result.Matched {
		t.Error("empty tree should not match")
	}
	if !result.Blocked {
		t.Error("empty tree should be blocked")
	}
}

// ============================================================
// strict 模式：等同于原行为，树精确匹配
// ============================================================

func TestMatch_Strict_SimpleRegister(t *testing.T) {
	tree, cleanup := newTestTree(t, "strict")
	defer cleanup()

	fp := types.DeviceFingerprint{
		OS:       strPtr("linux"),
		IP:       strPtr("192.168.1.100"),
		Port:     strPtr("54321"),
		Protocol: strPtr("https"),
		UUID:     strPtr("device-abc-123"),
	}
	if err := tree.Register("conn-001", fp); err != nil {
		t.Fatalf("register: %v", err)
	}

	// 完全匹配 → 树命中
	result := tree.Match(fp)
	if !result.Matched {
		t.Error("should match exact fingerprint")
	}
	if result.MatchPath != "tree" {
		t.Errorf("match path = %s, want tree", result.MatchPath)
	}
	if len(result.AuditDiffs) != 0 {
		t.Errorf("audit diffs = %d, want 0", len(result.AuditDiffs))
	}
}

func TestMatch_Strict_DifferentOS(t *testing.T) {
	tree, cleanup := newTestTree(t, "strict")
	defer cleanup()

	fp := types.DeviceFingerprint{
		OS:       strPtr("linux"),
		IP:       strPtr("192.168.1.100"),
		Port:     strPtr("54321"),
		Protocol: strPtr("https"),
		UUID:     strPtr("device-abc-123"),
	}
	tree.Register("conn-001", fp)

	// 不同 OS → strict 模式下不走兜底，直接 BLOCKED
	noMatch := types.DeviceFingerprint{
		OS:       strPtr("windows"),
		IP:       strPtr("192.168.1.100"),
		Port:     strPtr("54321"),
		Protocol: strPtr("https"),
		UUID:     strPtr("device-abc-123"),
	}
	result := tree.Match(noMatch)
	if result.Matched {
		t.Error("strict: different OS should not match")
	}
	if !result.Blocked {
		t.Error("strict: different OS should be blocked")
	}
}

func TestMatch_Strict_DifferentIP(t *testing.T) {
	tree, cleanup := newTestTree(t, "strict")
	defer cleanup()

	fp := types.DeviceFingerprint{
		OS:       strPtr("linux"),
		IP:       strPtr("192.168.1.100"),
		Port:     strPtr("54321"),
		Protocol: strPtr("https"),
		UUID:     strPtr("device-abc-123"),
	}
	tree.Register("conn-001", fp)

	// 不同 IP → strict 模式下 BLOCKED
	differentIP := types.DeviceFingerprint{
		OS:       strPtr("linux"),
		IP:       strPtr("10.0.0.1"),
		Port:     strPtr("54321"),
		Protocol: strPtr("https"),
		UUID:     strPtr("device-abc-123"),
	}
	result := tree.Match(differentIP)
	if result.Matched {
		t.Error("strict: different IP should not match")
	}
	if !result.Blocked {
		t.Error("strict: different IP should be blocked")
	}
}

func TestMatch_Strict_DifferentUUID(t *testing.T) {
	tree, cleanup := newTestTree(t, "strict")
	defer cleanup()

	fp := types.DeviceFingerprint{
		OS:       strPtr("linux"),
		IP:       strPtr("192.168.1.100"),
		Port:     strPtr("54321"),
		Protocol: strPtr("https"),
		UUID:     strPtr("device-abc-123"),
	}
	tree.Register("conn-001", fp)

	noMatch := types.DeviceFingerprint{
		OS:       strPtr("linux"),
		IP:       strPtr("192.168.1.100"),
		Port:     strPtr("54321"),
		Protocol: strPtr("https"),
		UUID:     strPtr("device-xyz-999"),
	}
	result := tree.Match(noMatch)
	if result.Matched {
		t.Error("different UUID should not match")
	}
}

// ============================================================
// standard 模式：OS=block, IP/Port/Protocol=audit
// ============================================================

func TestMatch_Standard_IPDrift(t *testing.T) {
	tree, cleanup := newTestTree(t, "standard")
	defer cleanup()

	fp := types.DeviceFingerprint{
		OS:       strPtr("linux"),
		IP:       strPtr("192.168.1.100"),
		Port:     strPtr("54321"),
		Protocol: strPtr("https"),
		UUID:     strPtr("device-001"),
	}
	tree.Register("conn-001", fp)

	// IP 漂移 → UUID 兜底命中，IP=audit → 放行 + 审计
	drifted := types.DeviceFingerprint{
		OS:       strPtr("linux"),
		IP:       strPtr("10.0.0.99"),
		Port:     strPtr("54321"),
		Protocol: strPtr("https"),
		UUID:     strPtr("device-001"),
	}
	result := tree.Match(drifted)
	if !result.Matched {
		t.Error("standard: IP drift should be allowed (audit)")
	}
	if result.Blocked {
		t.Error("standard: IP drift should not block")
	}
	if result.MatchPath != "dimension_fallback" {
		t.Errorf("match path = %s, want dimension_fallback", result.MatchPath)
	}
	if len(result.AuditDiffs) != 1 {
		t.Fatalf("audit diffs = %d, want 1", len(result.AuditDiffs))
	}
	if result.AuditDiffs[0].Dimension != "ip" {
		t.Errorf("audit dim = %s, want ip", result.AuditDiffs[0].Dimension)
	}
	if result.AuditDiffs[0].Registered != "192.168.1.100" {
		t.Errorf("registered = %s", result.AuditDiffs[0].Registered)
	}
	if result.AuditDiffs[0].Actual != "10.0.0.99" {
		t.Errorf("actual = %s", result.AuditDiffs[0].Actual)
	}
}

func TestMatch_Standard_OSDrift(t *testing.T) {
	tree, cleanup := newTestTree(t, "standard")
	defer cleanup()

	fp := types.DeviceFingerprint{
		OS:   strPtr("linux"),
		IP:   strPtr("10.0.0.1"),
		UUID: strPtr("device-001"),
	}
	tree.Register("conn-001", fp)

	// OS 变化 → standard 模式下 OS=block → BLOCKED
	drifted := types.DeviceFingerprint{
		OS:   strPtr("windows"),
		IP:   strPtr("10.0.0.1"),
		UUID: strPtr("device-001"),
	}
	result := tree.Match(drifted)
	if result.Matched {
		t.Error("standard: OS drift should be blocked")
	}
	if !result.Blocked {
		t.Error("standard: OS drift should set Blocked=true")
	}
	if len(result.BlockDiffs) != 1 {
		t.Fatalf("block diffs = %d, want 1", len(result.BlockDiffs))
	}
	if result.BlockDiffs[0].Dimension != "os" {
		t.Errorf("block dim = %s, want os", result.BlockDiffs[0].Dimension)
	}
}

func TestMatch_Standard_PortDrift(t *testing.T) {
	tree, cleanup := newTestTree(t, "standard")
	defer cleanup()

	fp := types.DeviceFingerprint{
		OS:       strPtr("linux"),
		IP:       strPtr("10.0.0.1"),
		Port:     strPtr("8080"),
		Protocol: strPtr("https"),
		UUID:     strPtr("device-001"),
	}
	tree.Register("conn-001", fp)

	// Port 漂移 → standard 模式下 port=audit → 放行
	drifted := types.DeviceFingerprint{
		OS:       strPtr("linux"),
		IP:       strPtr("10.0.0.1"),
		Port:     strPtr("9999"),
		Protocol: strPtr("https"),
		UUID:     strPtr("device-001"),
	}
	result := tree.Match(drifted)
	if !result.Matched {
		t.Error("standard: port drift should be allowed")
	}
	if len(result.AuditDiffs) != 1 {
		t.Fatalf("audit diffs = %d, want 1", len(result.AuditDiffs))
	}
	if result.AuditDiffs[0].Dimension != "port" {
		t.Errorf("audit dim = %s, want port", result.AuditDiffs[0].Dimension)
	}
}

func TestMatch_Standard_MultipleDrifts(t *testing.T) {
	tree, cleanup := newTestTree(t, "standard")
	defer cleanup()

	fp := types.DeviceFingerprint{
		OS:       strPtr("linux"),
		IP:       strPtr("10.0.0.1"),
		Port:     strPtr("8080"),
		Protocol: strPtr("https"),
		UUID:     strPtr("device-001"),
	}
	tree.Register("conn-001", fp)

	// IP + Port 同时漂移 → 两条审计，仍然放行
	drifted := types.DeviceFingerprint{
		OS:       strPtr("linux"),
		IP:       strPtr("10.0.0.99"),
		Port:     strPtr("9999"),
		Protocol: strPtr("https"),
		UUID:     strPtr("device-001"),
	}
	result := tree.Match(drifted)
	if !result.Matched {
		t.Error("standard: IP+Port drift should be allowed")
	}
	if len(result.AuditDiffs) != 2 {
		t.Errorf("audit diffs = %d, want 2", len(result.AuditDiffs))
	}
}

func TestMatch_Standard_ExactMatch(t *testing.T) {
	tree, cleanup := newTestTree(t, "standard")
	defer cleanup()

	fp := types.DeviceFingerprint{
		OS:       strPtr("linux"),
		IP:       strPtr("10.0.0.1"),
		Port:     strPtr("8080"),
		Protocol: strPtr("https"),
		UUID:     strPtr("device-001"),
	}
	tree.Register("conn-001", fp)

	// 完全匹配 → 树命中，无 diff
	result := tree.Match(fp)
	if !result.Matched {
		t.Error("exact match should succeed")
	}
	if result.MatchPath != "tree" {
		t.Errorf("match path = %s, want tree", result.MatchPath)
	}
	if len(result.AuditDiffs) != 0 {
		t.Errorf("exact match should have 0 diffs, got %d", len(result.AuditDiffs))
	}
}

// ============================================================
// relaxed 模式：全部 audit
// ============================================================

func TestMatch_Relaxed_AllAudit(t *testing.T) {
	tree, cleanup := newTestTree(t, "relaxed")
	defer cleanup()

	fp := types.DeviceFingerprint{
		OS:       strPtr("linux"),
		IP:       strPtr("10.0.0.1"),
		Port:     strPtr("8080"),
		Protocol: strPtr("https"),
		UUID:     strPtr("device-001"),
	}
	tree.Register("conn-001", fp)

	// OS 变了 → relaxed 模式下 OS=audit，不阻断
	drifted := types.DeviceFingerprint{
		OS:       strPtr("windows"),
		IP:       strPtr("10.0.0.1"),
		Port:     strPtr("8080"),
		Protocol: strPtr("https"),
		UUID:     strPtr("device-001"),
	}
	result := tree.Match(drifted)
	if !result.Matched {
		t.Error("relaxed: OS drift should be allowed")
	}
	if result.Blocked {
		t.Error("relaxed: OS drift should not block")
	}
	if len(result.AuditDiffs) != 1 {
		t.Errorf("audit diffs = %d, want 1", len(result.AuditDiffs))
	}
}

// ============================================================
// custom 模式
// ============================================================

func TestMatch_Custom_IgnorePort(t *testing.T) {
	dir, _ := os.MkdirTemp("", "fp-custom-*")
	defer os.RemoveAll(dir)

	store, _ := storage.NewBoltStore(filepath.Join(dir, "test.db"))
	defer store.Close()
	wal, _ := storage.NewWAL(dir)
	defer wal.Close()

	cfg := config.FingerprintConfig{
		DBPath:    filepath.Join(dir, "fp.db"),
		MatchMode: "custom",
		Dimensions: []config.DimensionPolicy{
			{Name: "os", Action: "block"},
			{Name: "ip", Action: "block"},
			{Name: "port", Action: "ignore"},
			{Name: "protocol", Action: "audit"},
		},
	}
	tree, _ := NewTree(store, wal, cfg)

	fp := types.DeviceFingerprint{
		OS:       strPtr("linux"),
		IP:       strPtr("10.0.0.1"),
		Port:     strPtr("8080"),
		Protocol: strPtr("https"),
		UUID:     strPtr("device-001"),
	}
	tree.Register("conn-001", fp)

	// Port 变了 → ignore，不记入任何 diff
	portChanged := types.DeviceFingerprint{
		OS:       strPtr("linux"),
		IP:       strPtr("10.0.0.1"),
		Port:     strPtr("9999"),
		Protocol: strPtr("https"),
		UUID:     strPtr("device-001"),
	}
	result := tree.Match(portChanged)
	if !result.Matched {
		t.Error("custom: port change should be ignored")
	}
	if len(result.AuditDiffs) != 0 {
		t.Errorf("port=ignore should produce 0 audit diffs, got %d", len(result.AuditDiffs))
	}
	if len(result.BlockDiffs) != 0 {
		t.Errorf("port=ignore should produce 0 block diffs, got %d", len(result.BlockDiffs))
	}
}

func TestMatch_Custom_IPBlock(t *testing.T) {
	dir, _ := os.MkdirTemp("", "fp-custom-*")
	defer os.RemoveAll(dir)

	store, _ := storage.NewBoltStore(filepath.Join(dir, "test.db"))
	defer store.Close()
	wal, _ := storage.NewWAL(dir)
	defer wal.Close()

	cfg := config.FingerprintConfig{
		DBPath:    filepath.Join(dir, "fp.db"),
		MatchMode: "custom",
		Dimensions: []config.DimensionPolicy{
			{Name: "os", Action: "audit"},
			{Name: "ip", Action: "block"},
			{Name: "port", Action: "ignore"},
			{Name: "protocol", Action: "ignore"},
		},
	}
	tree, _ := NewTree(store, wal, cfg)

	fp := types.DeviceFingerprint{
		OS:       strPtr("linux"),
		IP:       strPtr("10.0.0.1"),
		Port:     strPtr("8080"),
		Protocol: strPtr("https"),
		UUID:     strPtr("device-001"),
	}
	tree.Register("conn-001", fp)

	// IP 变了 → block
	drifted := types.DeviceFingerprint{
		OS:       strPtr("linux"),
		IP:       strPtr("10.0.0.99"),
		Port:     strPtr("8080"),
		Protocol: strPtr("https"),
		UUID:     strPtr("device-001"),
	}
	result := tree.Match(drifted)
	if result.Matched {
		t.Error("custom: IP block should reject")
	}
	if !result.Blocked {
		t.Error("custom: IP block should set Blocked=true")
	}
}

// ============================================================
// UUID 未注册
// ============================================================

func TestMatch_UnregisteredUUID(t *testing.T) {
	tree, cleanup := newTestTree(t, "standard")
	defer cleanup()

	fp := types.DeviceFingerprint{
		UUID: strPtr("unknown-device"),
		OS:   strPtr("linux"),
		IP:   strPtr("10.0.0.1"),
	}
	result := tree.Match(fp)
	if result.Matched {
		t.Error("unregistered UUID should not match")
	}
	if !result.Blocked {
		t.Error("unregistered UUID should be blocked")
	}
}

func TestMatch_NoUUID(t *testing.T) {
	tree, cleanup := newTestTree(t, "standard")
	defer cleanup()

	fp := types.DeviceFingerprint{
		OS: strPtr("linux"),
		IP: strPtr("10.0.0.1"),
	}
	result := tree.Match(fp)
	if result.Matched {
		t.Error("no UUID should not match")
	}
	if !result.Blocked {
		t.Error("no UUID should be blocked")
	}
}

// ============================================================
// 注册时部分维度为空
// ============================================================

func TestMatch_NullDimensionSkip(t *testing.T) {
	tree, cleanup := newTestTree(t, "standard")
	defer cleanup()

	// 注册时 OS 和 Protocol 缺省
	fp := types.DeviceFingerprint{
		IP:   strPtr("10.0.0.1"),
		Port: strPtr("8080"),
		UUID: strPtr("device-null"),
	}
	tree.Register("conn-001", fp)

	// 匹配时也缺省 → 树精确命中
	result := tree.Match(fp)
	if !result.Matched {
		t.Error("should match with null dimensions")
	}
	if result.MatchPath != "tree" {
		t.Errorf("match path = %s, want tree", result.MatchPath)
	}
}

func TestMatch_RegisteredEmpty_QueryWithOS(t *testing.T) {
	tree, cleanup := newTestTree(t, "standard")
	defer cleanup()

	// 注册时没有 OS
	fp := types.DeviceFingerprint{
		IP:   strPtr("10.0.0.1"),
		Port: strPtr("8080"),
		UUID: strPtr("device-null"),
	}
	tree.Register("conn-001", fp)

	// 查询时带了 OS → 树不匹配
	withOS := types.DeviceFingerprint{
		OS:   strPtr("linux"),
		IP:   strPtr("10.0.0.1"),
		Port: strPtr("8080"),
		UUID: strPtr("device-null"),
	}
	result := tree.Match(withOS)
	// 树匹配失败，但 UUID 兜底命中
	// 注册时 OS 为空 → diffDimensions 跳过 OS（regVal==""）
	if !result.Matched {
		t.Error("UUID fallback should match even when query has extra OS")
	}
	if result.MatchPath != "dimension_fallback" {
		t.Errorf("match path = %s, want dimension_fallback", result.MatchPath)
	}
	// 注册时 OS 为空，不算维度漂移，0 个 diff
	if len(result.AuditDiffs) != 0 {
		t.Errorf("registered OS empty should not produce diff, got %d", len(result.AuditDiffs))
	}
}

// ============================================================
// Unregister
// ============================================================

func TestUnregister(t *testing.T) {
	tree, cleanup := newTestTree(t, "standard")
	defer cleanup()

	fp := types.DeviceFingerprint{
		OS:       strPtr("linux"),
		IP:       strPtr("10.0.0.1"),
		Port:     strPtr("8080"),
		Protocol: strPtr("https"),
		UUID:     strPtr("device-unreg"),
	}
	tree.Register("conn-001", fp)

	if !tree.Match(fp).Matched {
		t.Fatal("should match before unregister")
	}

	tree.Unregister("conn-001", fp)

	result := tree.Match(fp)
	if result.Matched {
		t.Error("should not match after unregister")
	}
	if !result.Blocked {
		t.Error("should be blocked after unregister")
	}
}

// ============================================================
// 多设备
// ============================================================

func TestMultipleDevices(t *testing.T) {
	tree, cleanup := newTestTree(t, "standard")
	defer cleanup()

	fp1 := types.DeviceFingerprint{OS: strPtr("linux"), IP: strPtr("10.0.0.1"), UUID: strPtr("device-A")}
	fp2 := types.DeviceFingerprint{OS: strPtr("linux"), IP: strPtr("10.0.0.2"), UUID: strPtr("device-B")}
	fp3 := types.DeviceFingerprint{OS: strPtr("windows"), IP: strPtr("10.0.0.3"), UUID: strPtr("device-C")}

	tree.Register("conn-001", fp1)
	tree.Register("conn-002", fp2)
	tree.Register("conn-003", fp3)

	if !tree.Match(fp1).Matched {
		t.Error("fp1 should match")
	}
	if !tree.Match(fp2).Matched {
		t.Error("fp2 should match")
	}
	if !tree.Match(fp3).Matched {
		t.Error("fp3 should match")
	}

	// fp1 和 fp2 共享 OS=linux，但 UUID 不同
	// device-B 走 device-A 的路径 → 树不匹配，UUID 兜底命中 device-B
	// device-B 注册时 IP=10.0.0.2，实际 IP=10.0.0.1 → IP audit diff
	cross := types.DeviceFingerprint{OS: strPtr("linux"), IP: strPtr("10.0.0.1"), UUID: strPtr("device-B")}
	result := tree.Match(cross)
	if !result.Matched {
		t.Error("device-B UUID should match via fallback")
	}
	if result.MatchPath != "dimension_fallback" {
		t.Errorf("cross-device should use UUID fallback")
	}
	if len(result.AuditDiffs) != 1 {
		t.Errorf("should have 1 IP audit diff, got %d", len(result.AuditDiffs))
	}
}

// ============================================================
// 持久化 + WAL 恢复
// ============================================================

func TestPersistence(t *testing.T) {
	dir, _ := os.MkdirTemp("", "fp-persist-*")
	defer os.RemoveAll(dir)

	fp := types.DeviceFingerprint{
		OS:   strPtr("linux"),
		IP:   strPtr("10.0.0.1"),
		UUID: strPtr("device-persist"),
	}

	// 第一个实例：注册 + Flush（确保写入 bbolt）
	{
		store, _ := storage.NewBoltStore(filepath.Join(dir, "test.db"))
		wal, _ := storage.NewWAL(dir)
		tree, _ := NewTree(store, wal, config.FingerprintConfig{
			MatchMode: "standard",
		})
		tree.Register("conn-001", fp)
		wal.Flush() // WAL → bbolt
		wal.Close()
		store.Close()
	}

	// 第二个实例：从 bbolt 快照加载
	{
		store, _ := storage.NewBoltStore(filepath.Join(dir, "test.db"))
		wal, _ := storage.NewWAL(dir)
		tree, _ := NewTree(store, wal, config.FingerprintConfig{
			MatchMode: "standard",
		})

		result := tree.Match(fp)
		if !result.Matched {
			t.Error("should match after reload from bbolt")
		}
		if result.MatchPath != "tree" {
			t.Errorf("match path = %s, want tree", result.MatchPath)
		}
		wal.Close()
		store.Close()
	}
}

func TestPersistence_WALReplay(t *testing.T) {
	dir, _ := os.MkdirTemp("", "fp-replay-*")
	defer os.RemoveAll(dir)

	fp := types.DeviceFingerprint{
		OS:   strPtr("linux"),
		IP:   strPtr("10.0.0.1"),
		UUID: strPtr("device-wal-replay"),
	}

	// 第一个实例：注册但不 Flush（模拟崩溃）
	{
		store, _ := storage.NewBoltStore(filepath.Join(dir, "test.db"))
		wal, _ := storage.NewWAL(dir)
		tree, _ := NewTree(store, wal, config.FingerprintConfig{
			MatchMode: "standard",
		})
		tree.Register("conn-001", fp)
		// 不 Flush，直接关 → WAL 完整保留
		wal.Close()
		store.Close()
	}

	// 第二个实例：应通过 WAL 回放恢复
	{
		store, _ := storage.NewBoltStore(filepath.Join(dir, "test.db"))
		wal, _ := storage.NewWAL(dir)
		tree, _ := NewTree(store, wal, config.FingerprintConfig{
			MatchMode: "standard",
		})

		result := tree.Match(fp)
		if !result.Matched {
			t.Error("should match after WAL replay")
		}
		if result.MatchPath != "tree" {
			t.Errorf("match path = %s, want tree", result.MatchPath)
		}
		wal.Close()
		store.Close()
	}
}

func TestPersistence_Unregister_WALReplay(t *testing.T) {
	dir, _ := os.MkdirTemp("", "fp-unreg-replay-*")
	defer os.RemoveAll(dir)

	fp := types.DeviceFingerprint{
		OS:   strPtr("linux"),
		IP:   strPtr("10.0.0.1"),
		UUID: strPtr("device-unreg-replay"),
	}

	// 第一个实例：注册 + Unregister，不 Flush
	{
		store, _ := storage.NewBoltStore(filepath.Join(dir, "test.db"))
		wal, _ := storage.NewWAL(dir)
		tree, _ := NewTree(store, wal, config.FingerprintConfig{
			MatchMode: "standard",
		})
		tree.Register("conn-001", fp)
		tree.Unregister("conn-002", fp)
		wal.Close()
		store.Close()
	}

	// 第二个实例：WAL 回放后应不存在
	{
		store, _ := storage.NewBoltStore(filepath.Join(dir, "test.db"))
		wal, _ := storage.NewWAL(dir)
		tree, _ := NewTree(store, wal, config.FingerprintConfig{
			MatchMode: "standard",
		})

		result := tree.Match(fp)
		if result.Matched {
			t.Error("should not match after unregister + WAL replay")
		}
		wal.Close()
		store.Close()
	}
}

// ============================================================
// MatchResult 字段完整性
// ============================================================

func TestMatchResult_DevicePopulated(t *testing.T) {
	tree, cleanup := newTestTree(t, "standard")
	defer cleanup()

	fp := types.DeviceFingerprint{
		OS:   strPtr("linux"),
		IP:   strPtr("10.0.0.1"),
		UUID: strPtr("device-001"),
	}
	tree.Register("conn-001", fp)

	// 树精确命中
	result := tree.Match(fp)
	if result.Device == nil {
		t.Fatal("Device should be populated on match")
	}
	if result.Device.UUID == nil || *result.Device.UUID != "device-001" {
		t.Errorf("Device.UUID = %v, want device-001", result.Device.UUID)
	}
}

func TestMatchResult_DevicePopulated_Fallback(t *testing.T) {
	tree, cleanup := newTestTree(t, "standard")
	defer cleanup()

	fp := types.DeviceFingerprint{
		OS:       strPtr("linux"),
		IP:       strPtr("10.0.0.1"),
		Port:     strPtr("8080"),
		Protocol: strPtr("https"),
		UUID:     strPtr("device-001"),
	}
	tree.Register("conn-001", fp)

	// IP 漂移 → UUID 兜底
	drifted := types.DeviceFingerprint{
		OS:       strPtr("linux"),
		IP:       strPtr("10.0.0.99"),
		Port:     strPtr("8080"),
		Protocol: strPtr("https"),
		UUID:     strPtr("device-001"),
	}
	result := tree.Match(drifted)
	if result.Device == nil {
		t.Fatal("Device should be populated on UUID fallback")
	}
	// Device 应该是注册时的完整指纹
	if result.Device.IP == nil || *result.Device.IP != "10.0.0.1" {
		t.Errorf("Device.IP = %v, want 10.0.0.1", result.Device.IP)
	}
}

// ============================================================
// Print
// ============================================================

func TestPrint(t *testing.T) {
	tree, cleanup := newTestTree(t, "strict")
	defer cleanup()

	fp := types.DeviceFingerprint{
		OS:   strPtr("linux"),
		IP:   strPtr("10.0.0.1"),
		UUID: strPtr("device-print"),
	}
	tree.Register("conn-001", fp)

	output := tree.Print()
	if output == "" {
		t.Error("Print() should return non-empty string")
	}
	t.Logf("Tree:\n%s", output)
}
