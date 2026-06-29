package fingerprint

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"Threshold/pkg/config"
	"Threshold/pkg/proto/pb"
	"Threshold/pkg/storage"
	"Threshold/pkg/types"
)

const (
	LayerCount   = 6
	NullKey      = "null"
	ActionBlock  = "block"
	ActionAudit  = "audit"
	ActionIgnore = "ignore"
)

var LayerOrder = [LayerCount]string{
	"os", "ip", "port", "protocol", "uuid", "reserved",
}

// ============================================================
// 匹配结果
// ============================================================

type MatchResult struct {
	Matched    bool                     // 设备合法 → true（UUID 命中 + 无 block 冲突）
	Blocked    bool                     // 有 block 维度冲突 → true
	Device     *types.DeviceFingerprint // 匹配到的注册指纹快照
	AuditDiffs []DimensionDiff          // audit 维度差异（不影响放行）
	BlockDiffs []DimensionDiff          // block 维度差异（导致阻断）
	MatchPath  string                   // "tree" | "dimension_fallback" | ""
}

type DimensionDiff struct {
	Dimension  string
	Registered string
	Actual     string
}

// ============================================================
// 维度策略
// ============================================================

type dimensionPolicies map[string]string

var presetModes = map[string]map[string]string{
	"strict": {
		"os": ActionBlock, "ip": ActionBlock, "port": ActionBlock, "protocol": ActionBlock,
	},
	"standard": {
		"os": ActionBlock, "ip": ActionAudit, "port": ActionAudit, "protocol": ActionAudit,
	},
	"relaxed": {
		"os": ActionAudit, "ip": ActionAudit, "port": ActionAudit, "protocol": ActionAudit,
	},
}

func buildPolicies(cfg config.FingerprintConfig) dimensionPolicies {
	policies := make(dimensionPolicies)

	// 预设
	if preset, ok := presetModes[cfg.MatchMode]; ok {
		for dim, action := range preset {
			policies[dim] = action
		}
	}

	// custom 模式覆盖
	for _, dp := range cfg.Dimensions {
		policies[dp.Name] = dp.Action
	}

	// 未配置的维度默认 audit
	for _, dim := range []string{"os", "ip", "port", "protocol"} {
		if _, ok := policies[dim]; !ok {
			policies[dim] = ActionAudit
		}
	}

	return policies
}

// ============================================================
// 树节点（不变）
// ============================================================

type Node struct {
	children map[string]*Node
	isLeaf   bool
}

func newNode() *Node {
	return &Node{children: make(map[string]*Node)}
}

func (n *Node) getChild(key string) *Node    { return n.children[key] }
func (n *Node) setChild(key string, c *Node) { n.children[key] = c }
func (n *Node) hasChildren() bool            { return len(n.children) > 0 }

// ============================================================
// Tree
// ============================================================

type Tree struct {
	root     *Node
	store    storage.Store
	wal      *storage.WAL
	uuidMap  map[string]types.DeviceFingerprint
	policies dimensionPolicies
}

func NewTree(store storage.Store, wal *storage.WAL, cfg config.FingerprintConfig) (*Tree, error) {
	policies := buildPolicies(cfg)

	t := &Tree{
		root:     newNode(),
		store:    store,
		wal:      wal,
		uuidMap:  make(map[string]types.DeviceFingerprint),
		policies: policies,
	}
	if err := t.loadFromStore(); err != nil {
		return nil, fmt.Errorf("load fingerprint tree: %w", err)
	}

	log.Printf("[FP] loaded, match_mode=%s", cfg.MatchMode)
	for _, dim := range []string{"os", "ip", "port", "protocol"} {
		log.Printf("[FP]   %-10s → %s", dim, policies[dim])
	}

	return t, nil
}

// ============================================================
// Match（核心改动）
// ============================================================

func (t *Tree) Match(fp types.DeviceFingerprint) MatchResult {
	// ====== 第一轮：树精确匹配（原有逻辑不改） ======
	if t.treeMatch(fp) {
		uuid := deref(fp.UUID)
		registered := t.uuidMap[uuid]
		return MatchResult{
			Matched:   true,
			Device:    &registered,
			MatchPath: "tree",
		}
	}

	// ====== 第二轮：UUID 兜底 + 逐维度策略 ======
	if fp.UUID == nil || *fp.UUID == "" {
		return MatchResult{Matched: false, Blocked: true}
	}

	uuid := *fp.UUID
	registered, ok := t.uuidMap[uuid]
	if !ok {
		log.Printf("[FP] rejected: UUID %s not registered", uuid)
		return MatchResult{Matched: false, Blocked: true}
	}

	return t.dimensionMatch(registered, fp)
}

// treeMatch 提取自原 Match 逻辑
func (t *Tree) treeMatch(fp types.DeviceFingerprint) bool {
	dims := []*string{fp.OS, fp.IP, fp.Port, fp.Protocol, fp.UUID, fp.Reserved}
	current := t.root
	for level, val := range dims {
		key := dimKey(val)
		next := current.getChild(key)
		if next == nil {
			return false
		}
		if next.isLeaf {
			return true
		}
		if level == LayerCount-1 {
			return false
		}
		current = next
	}
	return false
}

// dimensionMatch UUID 命中后逐维度按策略判定
func (t *Tree) dimensionMatch(registered, actual types.DeviceFingerprint) MatchResult {
	result := MatchResult{
		Matched:   true,
		Device:    &registered,
		MatchPath: "dimension_fallback",
	}

	checks := []struct {
		dim string
		reg *string
		act *string
	}{
		{"os", registered.OS, actual.OS},
		{"ip", registered.IP, actual.IP},
		{"port", registered.Port, actual.Port},
		{"protocol", registered.Protocol, actual.Protocol},
	}

	for _, c := range checks {
		regVal := deref(c.reg)
		actVal := deref(c.act)

		// 注册时为空 → 该维度未设置，跳过
		if regVal == "" {
			continue
		}
		// 值相同 → 无差异，跳过
		if regVal == actVal {
			continue
		}
		// 值不同就要进入审计环节了
		diff := DimensionDiff{
			Dimension:  c.dim,
			Registered: regVal,
			Actual:     actVal,
		}

		switch t.policies[c.dim] {
		case ActionBlock:
			result.Blocked = true
			result.Matched = false
			result.BlockDiffs = append(result.BlockDiffs, diff)
			log.Printf("[FP-BLOCK] UUID=%s %s: %s → %s",
				deref(actual.UUID), c.dim, regVal, actVal)

		case ActionAudit:
			result.AuditDiffs = append(result.AuditDiffs, diff)
			log.Printf("[FP-AUDIT] UUID=%s %s: %s → %s",
				deref(actual.UUID), c.dim, regVal, actVal)

		case ActionIgnore:
			// 静默跳过
		}
	}

	return result
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// ============================================================
// Register / Unregister（不变）
// ============================================================

func (t *Tree) Register(connID string, fp types.DeviceFingerprint) error {
	t.registerInMemory(fp)

	record := fpToRecord(fp)
	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("marshal record: %w", err)
	}
	key := string(recordKey(fp))

	seq, err := t.wal.Begin(connID, storage.WLOpPut, storage.BucketFingerprints, key, data)
	if err != nil {
		return fmt.Errorf("wal begin: %w", err)
	}
	return t.wal.Commit(connID, seq, storage.WLOpPut, storage.BucketFingerprints, key, data)
}
func (t *Tree) Unregister(connID string, fp types.DeviceFingerprint) error {
	uuid := ""
	if fp.UUID != nil {
		uuid = *fp.UUID
	}
	if stored, ok := t.uuidMap[uuid]; ok {
		fp = stored
	}

	dims := []*string{fp.OS, fp.IP, fp.Port, fp.Protocol, fp.UUID, fp.Reserved}
	if !t.deleteLeaf(t.root, dims, 0) {
		log.Printf("[WARN] leaf not found in memory for uuid=%s", uuid)
	}
	delete(t.uuidMap, uuid)

	// ↓↓↓ 删掉原来的 t.store.Update 直接写 bbolt ↓↓↓
	// 改为只写 WAL，bbolt 由 flusher 异步更新
	key := recordKey(fp)
	seq, err := t.wal.Begin(connID, storage.WLOpDelete, storage.BucketFingerprints, string(key), nil)
	if err != nil {
		return fmt.Errorf("wal begin: %w", err)
	}
	return t.wal.Commit(connID, seq, storage.WLOpDelete, storage.BucketFingerprints, string(key), nil)
}

// ============================================================
// 内部方法（不变）
// ============================================================

func dimKey(val *string) string {
	if val == nil || *val == "" {
		return NullKey
	}
	return *val
}

func (t *Tree) registerInMemory(fp types.DeviceFingerprint) {
	dims := []*string{fp.OS, fp.IP, fp.Port, fp.Protocol, fp.UUID, fp.Reserved}
	lastNonNil := -1
	for i, d := range dims {
		if d != nil && *d != "" {
			lastNonNil = i
		}
	}
	if fp.UUID != nil && *fp.UUID != "" {
		t.uuidMap[*fp.UUID] = fp
	}
	current := t.root
	for i, val := range dims {
		key := dimKey(val)
		next := current.getChild(key)
		if next == nil {
			next = newNode()
			current.setChild(key, next)
		}
		if i == lastNonNil {
			next.isLeaf = true
			return
		}
		current = next
	}
}

func (t *Tree) deleteLeaf(node *Node, dims []*string, level int) bool {
	if level >= len(dims) {
		return false
	}
	key := dimKey(dims[level])
	child := node.getChild(key)
	if child == nil {
		return false
	}
	if child.isLeaf {
		delete(node.children, key)
		return true
	}
	if t.deleteLeaf(child, dims, level+1) {
		if !child.hasChildren() && !child.isLeaf {
			delete(node.children, key)
		}
		return true
	}
	return false
}

// ============================================================
// 持久化（不变）
// ============================================================

type FingerprintRecord struct {
	OS       *string `json:"os,omitempty"`
	IP       *string `json:"ip,omitempty"`
	Port     *string `json:"port,omitempty"`
	Protocol *string `json:"protocol,omitempty"`
	UUID     *string `json:"uuid,omitempty"`
	Reserved *string `json:"reserved,omitempty"`
}

func fpToRecord(fp types.DeviceFingerprint) FingerprintRecord {
	return FingerprintRecord{
		OS: fp.OS, IP: fp.IP, Port: fp.Port,
		Protocol: fp.Protocol, UUID: fp.UUID, Reserved: fp.Reserved,
	}
}

func recordToFingerprint(r FingerprintRecord) types.DeviceFingerprint {
	return types.DeviceFingerprint{
		OS: r.OS, IP: r.IP, Port: r.Port,
		Protocol: r.Protocol, UUID: r.UUID, Reserved: r.Reserved,
	}
}

func recordKey(fp types.DeviceFingerprint) []byte {
	if fp.UUID != nil {
		return []byte("fp:" + *fp.UUID)
	}
	return []byte("fp:" + fpDimStr(fp))
}

func fpDimStr(fp types.DeviceFingerprint) string {
	s := ""
	for _, p := range []*string{fp.OS, fp.IP, fp.Port, fp.Protocol, fp.UUID, fp.Reserved} {
		if p != nil {
			s += *p + ":"
		} else {
			s += "_"
		}
	}
	return s
}
func (t *Tree) loadFromStore() error {
	// 1. 从 bbolt 快照加载（最后一次 flush 的状态）
	if err := t.store.View(func(tx storage.Tx) error {
		return tx.ForEach(storage.BucketFingerprints, func(k, v []byte) error {
			var record FingerprintRecord
			if err := json.Unmarshal(v, &record); err != nil {
				return nil
			}
			t.registerInMemory(recordToFingerprint(record))
			return nil
		})
	}); err != nil {
		return fmt.Errorf("load from bbolt: %w", err)
	}

	// 2. 回放 WAL 中 checkpoint 之后的操作（补齐增量）
	return t.wal.Replay(func(op, key string, data []byte) error {
		switch op {
		case storage.WLOpPut:
			var record FingerprintRecord
			if err := json.Unmarshal(data, &record); err != nil {
				log.Printf("[WAL-REPLAY] skip invalid PUT key=%s: %v", key, err)
				return nil
			}
			t.registerInMemory(recordToFingerprint(record))

		case storage.WLOpDelete:
			uuid := strings.TrimPrefix(key, "fp:")
			if fp, ok := t.uuidMap[uuid]; ok {
				t.removeFromMemory(fp)
				delete(t.uuidMap, uuid)
			}
		}
		return nil
	})
}

// removeFromMemory 从内存树中删除指定指纹路径
// 用于 WAL 回放 DELETE 操作
// 与 deleteLeaf 的区别：不限定在叶子节点删除，
// 而是沿整条路径递归清理空节点
func (t *Tree) removeFromMemory(fp types.DeviceFingerprint) {
	dims := []*string{fp.OS, fp.IP, fp.Port, fp.Protocol, fp.UUID, fp.Reserved}
	t.deletePath(t.root, dims, 0)
}

func (t *Tree) deletePath(node *Node, dims []*string, level int) bool {
	if level >= len(dims) {
		return false
	}
	key := dimKey(dims[level])
	child := node.getChild(key)
	if child == nil {
		return false
	}
	if child.isLeaf {
		delete(node.children, key)
		return true
	}
	if t.deletePath(child, dims, level+1) {
		if !child.hasChildren() && !child.isLeaf {
			delete(node.children, key)
		}
		return true
	}
	return false
}

// ============================================================
// ListDevices / Print（不变）
// ============================================================

func (t *Tree) ListDevices(limit int) []*pb.DeviceInfo {
	var devices []*pb.DeviceInfo
	path := make([]string, LayerCount)
	t.collectLeaves(t.root, path, 0, limit, &devices)
	return devices
}

func (t *Tree) collectLeaves(node *Node, path []string, level int, limit int, devices *[]*pb.DeviceInfo) {
	if limit > 0 && len(*devices) >= limit {
		return
	}
	if node.isLeaf {
		info := &pb.DeviceInfo{}
		if level > 0 {
			info.OsType = path[0]
		}
		if level > 1 {
			info.Ip = path[1]
		}
		if info.OsType == NullKey {
			info.OsType = ""
		}
		if info.Ip == NullKey {
			info.Ip = ""
		}
		if level > 4 {
			uuidVal := path[4]
			if uuidVal != NullKey {
				info.DeviceUuid = uuidVal
			}
		}
		if info.DeviceUuid == "" {
			for i := 0; i < level; i++ {
				if i == 4 && path[i] != NullKey {
					info.DeviceUuid = path[i]
					break
				}
			}
		}
		*devices = append(*devices, info)
		return
	}
	for key, child := range node.children {
		if level < LayerCount {
			path[level] = key
		}
		t.collectLeaves(child, path, level+1, limit, devices)
		if limit > 0 && len(*devices) >= limit {
			return
		}
	}
}

func (t *Tree) Print() string {
	var buf bytes.Buffer
	buf.WriteString("FingerprintTree:\n")
	printNode(&buf, t.root, "", true)
	return buf.String()
}

func printNode(buf *bytes.Buffer, node *Node, prefix string, isLast bool) {
	idx := 0
	total := len(node.children)
	for key, child := range node.children {
		idx++
		isLastChild := idx == total
		connector := "\u251c\u2500\u2500 "
		if isLastChild {
			connector = "\u2514\u2500\u2500 "
		}
		leafMark := ""
		if child.isLeaf {
			leafMark = " [LEAF]"
		}
		buf.WriteString(prefix + connector + key + leafMark + "\n")
		newPrefix := prefix
		if isLastChild {
			newPrefix += "    "
		} else {
			newPrefix += "\u2502   "
		}
		printNode(buf, child, newPrefix, isLastChild)
	}
}
