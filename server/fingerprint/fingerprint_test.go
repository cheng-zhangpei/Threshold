package fingerprint

import (
	"os"
	"testing"

	"Threshold/pkg/storage"
	"Threshold/pkg/types"
)

func strPtr(s string) *string {
	return &s
}

func newTestTree(t *testing.T) (*Tree, func()) {
	t.Helper()
	tmpFile, err := os.CreateTemp("", "fp-scripts-*.db")
	if err != nil {
		t.Fatalf("create temp: %v", err)
	}
	tmpFile.Close()
	store, err := storage.NewBoltStore(tmpFile.Name())
	if err != nil {
		os.Remove(tmpFile.Name())
		t.Fatalf("new bolt: %v", err)
	}
	wal := storage.NewWAL(store)
	tree, err := NewTree(store, wal)
	if err != nil {
		store.Close()
		os.Remove(tmpFile.Name())
		t.Fatalf("new tree: %v", err)
	}
	cleanup := func() {
		store.Close()
		os.Remove(tmpFile.Name())
	}
	return tree, cleanup
}

func TestMatch_EmptyTree(t *testing.T) {
	tree, cleanup := newTestTree(t)
	defer cleanup()

	fp := types.DeviceFingerprint{
		OS:   strPtr("linux"),
		UUID: strPtr("device-001"),
		IP:   strPtr("192.168.1.1"),
	}
	if tree.Match(fp) {
		t.Error("empty tree should not match")
	}
}

func TestMatch_SimpleRegister(t *testing.T) {
	tree, cleanup := newTestTree(t)
	defer cleanup()

	fp := types.DeviceFingerprint{
		OS:       strPtr("linux"),
		IP:       strPtr("192.168.1.100"),
		Port:     strPtr("54321"),
		Protocol: strPtr("https"),
		UUID:     strPtr("device-abc-123"),
	}
	err := tree.Register("conn-001", fp)
	if err != nil {
		t.Fatalf("device-tool: %v", err)
	}

	// 完全匹配
	if !tree.Match(fp) {
		t.Error("should match after device-tool")
	}

	// 不同 OS 不匹配
	noMatch := types.DeviceFingerprint{
		OS:       strPtr("windows"),
		IP:       strPtr("192.168.1.100"),
		Port:     strPtr("54321"),
		Protocol: strPtr("https"),
		UUID:     strPtr("device-abc-123"),
	}
	if tree.Match(noMatch) {
		t.Error("should not match with different OS")
	}

	// 不同 UUID 不匹配
	noMatch2 := types.DeviceFingerprint{
		OS:       strPtr("linux"),
		IP:       strPtr("192.168.1.100"),
		Port:     strPtr("54321"),
		Protocol: strPtr("https"),
		UUID:     strPtr("device-xyz-999"),
	}
	if tree.Match(noMatch2) {
		t.Error("should not match with different UUID")
	}
}

func TestMatch_NullDimensionSkip(t *testing.T) {
	tree, cleanup := newTestTree(t)
	defer cleanup()

	// 注册时 OS 和 Protocol 缺省
	fp := types.DeviceFingerprint{
		IP:   strPtr("10.0.0.1"),
		Port: strPtr("8080"),
		UUID: strPtr("device-null-scripts"),
	}
	err := tree.Register("conn-001", fp)
	if err != nil {
		t.Fatalf("device-tool: %v", err)
	}

	// 匹配时也省略 OS 和 Protocol → 应该命中 null 分支
	if !tree.Match(fp) {
		t.Error("should match with null dimensions")
	}

	// 匹配时传了 OS → 应该不命中（null 分支下没有 linux）
	withOS := types.DeviceFingerprint{
		OS:   strPtr("linux"),
		IP:   strPtr("10.0.0.1"),
		Port: strPtr("8080"),
		UUID: strPtr("device-null-scripts"),
	}
	if tree.Match(withOS) {
		t.Error("should not match: registered without OS but queried with OS")
	}
}

func TestMatch_PartialRegistration(t *testing.T) {
	tree, cleanup := newTestTree(t)
	defer cleanup()

	// 只注册到 IP 层，叶节点在 IP 层
	fp := types.DeviceFingerprint{
		OS: strPtr("linux"),
		IP: strPtr("10.0.0.1"),
	}
	err := tree.Register("conn-001", fp)
	if err != nil {
		t.Fatalf("device-tool: %v", err)
	}

	// 只传 OS + IP，应该匹配（叶节点在 IP 层）
	if !tree.Match(fp) {
		t.Error("should match at IP level")
	}

	// 传更多维度，叶节点已经在 IP 层，应该也匹配
	extra := types.DeviceFingerprint{
		OS:       strPtr("linux"),
		IP:       strPtr("10.0.0.1"),
		Port:     strPtr("9999"),
		Protocol: strPtr("http"),
	}
	if !tree.Match(extra) {
		t.Error("should match with extra dimensions beyond leaf")
	}
}

func TestMatch_LeafAtFirstLevel(t *testing.T) {
	tree, cleanup := newTestTree(t)
	defer cleanup()

	// 只注册 OS 维度，叶节点在第一层
	fp := types.DeviceFingerprint{
		OS: strPtr("linux"),
	}
	err := tree.Register("conn-001", fp)
	if err != nil {
		t.Fatalf("device-tool: %v", err)
	}

	// 任意传 OS=linux 就应该匹配
	if !tree.Match(fp) {
		t.Error("should match at OS level")
	}

	// 传完整指纹，OS=linux 也能匹配
	full := types.DeviceFingerprint{
		OS:   strPtr("linux"),
		IP:   strPtr("1.2.3.4"),
		UUID: strPtr("any-uuid"),
	}
	if !tree.Match(full) {
		t.Error("should match with full fp when leaf at OS level")
	}
}

func TestUnregister(t *testing.T) {
	tree, cleanup := newTestTree(t)
	defer cleanup()

	fp := types.DeviceFingerprint{
		OS:       strPtr("linux"),
		IP:       strPtr("10.0.0.1"),
		Port:     strPtr("8080"),
		Protocol: strPtr("https"),
		UUID:     strPtr("device-unreg"),
	}
	err := tree.Register("conn-001", fp)
	if err != nil {
		t.Fatalf("device-tool: %v", err)
	}

	if !tree.Match(fp) {
		t.Fatal("should match before unregister")
	}

	err = tree.Unregister("conn-001", fp)
	if err != nil {
		t.Fatalf("unregister: %v", err)
	}

	if tree.Match(fp) {
		t.Error("should not match after unregister")
	}
}

func TestMultipleDevices(t *testing.T) {
	tree, cleanup := newTestTree(t)
	defer cleanup()

	fp1 := types.DeviceFingerprint{
		OS:   strPtr("linux"),
		IP:   strPtr("10.0.0.1"),
		UUID: strPtr("device-A"),
	}
	fp2 := types.DeviceFingerprint{
		OS:   strPtr("linux"),
		IP:   strPtr("10.0.0.2"),
		UUID: strPtr("device-B"),
	}
	fp3 := types.DeviceFingerprint{
		OS:   strPtr("windows"),
		IP:   strPtr("10.0.0.3"),
		UUID: strPtr("device-C"),
	}

	tree.Register("conn-001", fp1)
	tree.Register("conn-002", fp2)
	tree.Register("conn-003", fp3)

	if !tree.Match(fp1) {
		t.Error("fp1 should match")
	}
	if !tree.Match(fp2) {
		t.Error("fp2 should match")
	}
	if !tree.Match(fp3) {
		t.Error("fp3 should match")
	}

	// fp1 和 fp2 共享 OS=linux，但 IP 不同，不应互串
	if tree.Match(types.DeviceFingerprint{OS: strPtr("linux"), IP: strPtr("10.0.0.1"), UUID: strPtr("device-B")}) {
		t.Error("device-B UUID should not match device-A path")
	}
}

func TestPersistence(t *testing.T) {
	tmpFile, _ := os.CreateTemp("", "fp-persist-*.db")
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	fp := types.DeviceFingerprint{
		OS:   strPtr("linux"),
		IP:   strPtr("10.0.0.1"),
		UUID: strPtr("device-persist"),
	}

	// 第一个实例：注册
	{
		store, _ := storage.NewBoltStore(tmpFile.Name())
		wal := storage.NewWAL(store)
		tree, _ := NewTree(store, wal)
		tree.Register("conn-001", fp)
		store.Close()
	}

	// 第二个实例：重新加载后应该能匹配
	{
		store, _ := storage.NewBoltStore(tmpFile.Name())
		wal := storage.NewWAL(store)
		tree, _ := NewTree(store, wal)

		if !tree.Match(fp) {
			t.Error("should match after reload from bbolt")
		}
		store.Close()
	}
}

func TestPrint(t *testing.T) {
	tree, cleanup := newTestTree(t)
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
