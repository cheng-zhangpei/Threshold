package fingerprint

import (
	"bytes"
	"encoding/json"
	"fmt"

	"Threshold/pkg/storage"
	"Threshold/pkg/types"
)

const (
	LayerCount = 6
	NullKey    = "null"
)

var LayerOrder = [LayerCount]string{
	"os", "ip", "port", "protocol", "uuid", "reserved",
}

type Node struct {
	children map[string]*Node
	isLeaf   bool
}

func newNode() *Node {
	return &Node{children: make(map[string]*Node)}
}

func (n *Node) getChild(key string) *Node {
	return n.children[key]
}

func (n *Node) setChild(key string, child *Node) {
	n.children[key] = child
}

func (n *Node) hasChildren() bool {
	return len(n.children) > 0
}

type Tree struct {
	root  *Node
	store storage.Store
	wal   *storage.WAL
}

func NewTree(store storage.Store, wal *storage.WAL) (*Tree, error) {
	t := &Tree{
		root:  newNode(),
		store: store,
		wal:   wal,
	}
	if err := t.loadFromStore(); err != nil {
		return nil, fmt.Errorf("load fingerprint tree: %w", err)
	}
	return t, nil
}

func (t *Tree) Match(fp types.DeviceFingerprint) bool {
	dims := []*string{fp.OS, fp.IP, fp.Port, fp.Protocol, fp.UUID, fp.Reserved}
	current := t.root
	for level, val := range dims {
		var key string
		if val == nil {
			key = NullKey
		} else {
			key = *val
		}
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

// ============================================================
// Register/Unregister：内存更新 + WAL 持久化
// 叶节点标记在最后一个非 nil 维度处
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
	t.removeFromMemory(fp)
	key := string(recordKey(fp))
	seq, err := t.wal.Begin(connID, storage.WLOpDelete, storage.BucketFingerprints, key, nil)
	if err != nil {
		return fmt.Errorf("wal begin: %w", err)
	}
	return t.wal.Commit(connID, seq, storage.WLOpDelete, storage.BucketFingerprints, key, nil)
}

// registerInMemory
// 遍历所有维度，nil 维度用 null 键继续下探，
// 到达最后一个非 nil 维度时标记叶节点并停止。
func (t *Tree) registerInMemory(fp types.DeviceFingerprint) {
	dims := []*string{fp.OS, fp.IP, fp.Port, fp.Protocol, fp.UUID, fp.Reserved}
	lastNonNil := -1
	for i, d := range dims {
		if d != nil {
			lastNonNil = i
		}
	}
	current := t.root
	for i, val := range dims {
		var key string
		if val == nil {
			key = NullKey
		} else {
			key = *val
		}
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

// removeFromMemory
// 沿路径找到叶节点，标记非叶，自底向上清理空节点。
func (t *Tree) removeFromMemory(fp types.DeviceFingerprint) {
	dims := []*string{fp.OS, fp.IP, fp.Port, fp.Protocol, fp.UUID, fp.Reserved}
	path := make([]*Node, 0, LayerCount+1)
	path = append(path, t.root)
	current := t.root
	for _, val := range dims {
		var key string
		if val == nil {
			key = NullKey
		} else {
			key = *val
		}
		next := current.getChild(key)
		if next == nil {
			return
		}
		path = append(path, next)
		if next.isLeaf {
			next.isLeaf = false
			t.cleanupPath(path, dims)
			return
		}
		current = next
	}
	current.isLeaf = false
	t.cleanupPath(path, dims)
}

func (t *Tree) cleanupPath(path []*Node, dims []*string) {
	for i := len(path) - 1; i > 0; i-- {
		node := path[i]
		if !node.isLeaf && !node.hasChildren() {
			parent := path[i-1]
			var key string
			if dims[i-1] == nil {
				key = NullKey
			} else {
				key = *dims[i-1]
			}
			delete(parent.children, key)
		} else {
			break
		}
	}
}

// ============================================================
// 持久化辅助
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
	return t.store.View(func(tx storage.Tx) error {
		return tx.ForEach(storage.BucketFingerprints, func(k, v []byte) error {
			var record FingerprintRecord
			if err := json.Unmarshal(v, &record); err != nil {
				return nil
			}
			t.registerInMemory(recordToFingerprint(record))
			return nil
		})
	})
}

// ============================================================
// Print 格式化打印树结构
// ============================================================

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
