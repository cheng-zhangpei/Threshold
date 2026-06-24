package fingerprint

import (
	"Threshold/pkg/proto/pb"
	"bytes"
	"encoding/json"
	"fmt"
	"log"

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
	root    *Node
	store   storage.Store
	wal     *storage.WAL
	uuidMap map[string]types.DeviceFingerprint // UUID → 完整指纹

}

func NewTree(store storage.Store, wal *storage.WAL) (*Tree, error) {
	t := &Tree{
		root:    newNode(),
		store:   store,
		wal:     wal,
		uuidMap: make(map[string]types.DeviceFingerprint),
	}
	if err := t.loadFromStore(); err != nil {
		return nil, fmt.Errorf("load fingerprint tree: %w", err)
	}
	return t, nil
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

func dimKey(val *string) string {
	if val == nil || *val == "" {
		return NullKey
	}
	return *val
}

// removeFromMemory 从内存树中删除指定指纹的叶子节点（递归版本）
func (t *Tree) removeFromMemory(fp types.DeviceFingerprint) {
	dims := []*string{fp.OS, fp.IP, fp.Port, fp.Protocol, fp.UUID, fp.Reserved}
	t.deletePath(t.root, dims, 0)
}

// deletePath 递归查找并删除路径上的叶子节点，返回是否删除成功
func (t *Tree) deletePath(node *Node, dims []*string, level int) bool {
	if level >= len(dims) {
		return false
	}
	key := NullKey
	if dims[level] != nil {
		key = *dims[level]
	}
	child := node.getChild(key)
	if child == nil {
		return false
	}
	// 如果 child 是叶子节点，删除它
	if child.isLeaf {
		delete(node.children, key)
		return true
	}
	// 否则继续深入
	if t.deletePath(child, dims, level+1) {
		// 如果子节点被删除后变为空且不是叶子，则删除该子节点（可选，但有助于清理）
		if !child.hasChildren() && !child.isLeaf {
			delete(node.children, key)
		}
		return true
	}
	return false
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

// ListDevices 遍历指纹树，收集所有已注册设备
func (t *Tree) ListDevices(limit int) []*pb.DeviceInfo {
	var devices []*pb.DeviceInfo
	path := make([]string, LayerCount)
	t.collectLeaves(t.root, path, 0, limit, &devices)
	return devices
}
func treeKey(val *string) string {
	if val == nil || *val == "" {
		return NullKey
	}
	return *val
}
func (t *Tree) collectLeaves(node *Node, path []string, level int, limit int, devices *[]*pb.DeviceInfo) {
	if limit > 0 && len(*devices) >= limit {
		return
	}

	if node.isLeaf {
		info := &pb.DeviceInfo{}
		// 根据 LayerOrder 填充字段
		// LayerOrder: os, ip, port, protocol, uuid, reserved
		if level > 0 {
			info.OsType = path[0] // os
		}
		if level > 1 {
			info.Ip = path[1] // ip
		}
		// 只把有实际值的维度填入（排除 "null" 占位）
		if info.OsType == NullKey {
			info.OsType = ""
		}
		if info.Ip == NullKey {
			info.Ip = ""
		}

		// 从路径中提取 uuid（LayerOrder[4] = "uuid"）
		if level > 4 {
			uuidVal := path[4]
			if uuidVal != NullKey {
				info.DeviceUuid = uuidVal
			}
		}
		// 如果 uuid 层没到，试试从整条路径中找
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
func (t *Tree) Match(fp types.DeviceFingerprint) bool {
	dims := []*string{fp.OS, fp.IP, fp.Port, fp.Protocol, fp.UUID, fp.Reserved}
	current := t.root
	for level, val := range dims {
		key := dimKey(val)

		log.Printf("[FP-DEBUG] Match level=%d key=%q (raw=%v)", level, key, val)

		next := current.getChild(key)
		if next == nil {
			log.Printf("[FP-DEBUG] Match FAILED at level=%d, key=%q NOT FOUND", level, key)
			return false
		}
		if next.isLeaf {
			log.Printf("[FP-DEBUG] Match SUCCESS at level=%d", level)
			return true
		}
		if level == LayerCount-1 {
			return false
		}
		current = next
	}
	return false
}
func (t *Tree) registerInMemory(fp types.DeviceFingerprint) {
	dims := []*string{fp.OS, fp.IP, fp.Port, fp.Protocol, fp.UUID, fp.Reserved}
	lastNonNil := -1
	for i, d := range dims {
		if d != nil && *d != "" {
			lastNonNil = i
		}
	}

	// 记录 UUID → 完整指纹映射
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
func (t *Tree) Unregister(connID string, fp types.DeviceFingerprint) error {
	// 按 UUID 查回注册时的完整指纹
	uuid := ""
	if fp.UUID != nil {
		uuid = *fp.UUID
	}
	if stored, ok := t.uuidMap[uuid]; ok {
		fp = stored
	}

	// 从内存树中删除
	dims := []*string{fp.OS, fp.IP, fp.Port, fp.Protocol, fp.UUID, fp.Reserved}
	if !t.deleteLeaf(t.root, dims, 0) {
		log.Printf("[WARN] fingerprint leaf not found in memory for uuid=%s", uuid)
	}

	// 从 uuidMap 中删除
	delete(t.uuidMap, uuid)

	// 从存储中删除
	key := recordKey(fp)
	if err := t.store.Update(func(tx storage.Tx) error {
		return tx.Delete(storage.BucketFingerprints, key)
	}); err != nil {
		return fmt.Errorf("store delete: %w", err)
	}

	// WAL 日志
	seq, err := t.wal.Begin(connID, storage.WLOpDelete, storage.BucketFingerprints, string(key), nil)
	if err != nil {
		return fmt.Errorf("wal begin: %w", err)
	}
	return t.wal.Commit(connID, seq, storage.WLOpDelete, storage.BucketFingerprints, string(key), nil)
}
func (t *Tree) loadFromStore() error {
	return t.store.View(func(tx storage.Tx) error {
		return tx.ForEach(storage.BucketFingerprints, func(k, v []byte) error {
			var record FingerprintRecord
			if err := json.Unmarshal(v, &record); err != nil {
				return nil
			}
			fp := recordToFingerprint(record)
			t.registerInMemory(fp)
			return nil
		})
	})
}
