package storage

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// WLOpPut    写入操作（与原接口保持一致）
	// WLOpDelete 删除操作（与原接口保持一致）
	WLOpPut    = "PUT"
	WLOpDelete = "DELETE"
)

// WAL 内部条目状态
const (
	walPending    = "p" // 已写入，未确认
	walCommitted  = "c" // 已确认，待刷盘
	walCheckpoint = "k" // 刷盘点（标记此 seq 之前的数据已持久化到 bbolt）
)

const (
	walFileName     = "wal.log"
	walBufSize      = 64 * 1024   // 写缓冲 64KB
	walMaxEntrySize = 1024 * 1024 // 单条目上限 1MB
)

// walEntry 单条 WAL 日志条目
// 使用短字段名减少磁盘占用
type walEntry struct {
	Seq    uint64 `json:"s"`            // 全局递增序号
	Status string `json:"t"`            // p=pending, c=committed, k=checkpoint
	ConnID string `json:"id,omitempty"` // 仅 pending：连接标识
	Op     string `json:"o,omitempty"`  // 仅 pending：PUT | DELETE
	Bucket string `json:"b,omitempty"`  // 仅 pending：目标 bucket
	Key    string `json:"k,omitempty"`  // 仅 pending：key
	Data   []byte `json:"d,omitempty"`  // 仅 pending：value
}

// WAL Write-Ahead Log（LSM 风格）
//
// 写入路径（无 bbolt I/O）：
//
//	Begin()  → 顺序追加 pending 条目（~数百字节）
//	Commit() → 顺序追加 committed 标记（~20 字节）
//
// 刷盘路径（后台）：
//
//	Flush()  → 读取已提交条目 → 批量写入 bbolt → 写 checkpoint → 截断旧条目
//
// 恢复路径：
//
//	loadFromStore() 加载 bbolt 快照
//	Replay() 回放 checkpoint 之后的已提交操作
type WAL struct {
	mu      sync.Mutex
	file    *os.File
	writer  *bufio.Writer
	seq     atomic.Uint64
	logPath string

	// 刷盘
	store       Store
	flushTicker *time.Ticker
	flushDone   chan struct{}
}

// NewWAL 创建 WAL 实例，自动恢复最大序号
func NewWAL(dir string) (*WAL, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create wal dir %s: %w", dir, err)
	}

	logPath := filepath.Join(dir, walFileName)
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0600)
	if err != nil {
		return nil, fmt.Errorf("open wal %s: %w", logPath, err)
	}

	w := &WAL{
		file:      f,
		writer:    bufio.NewWriterSize(f, walBufSize),
		logPath:   logPath,
		flushDone: make(chan struct{}),
	}

	maxSeq, err := w.scanMaxSeq()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("scan wal: %w", err)
	}
	w.seq.Store(maxSeq)

	log.Printf("[WAL] initialized, path=%s, next_seq=%d", logPath, maxSeq+1)
	return w, nil
}

// ============================================================
// 接口不变：Begin / Commit
// ============================================================

// Begin 追加 pending 条目，返回分配的序号
// 签名与原实现完全一致
func (w *WAL) Begin(connID, op, bucket, key string, data []byte) (uint64, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	seq := w.seq.Add(1)
	entry := walEntry{
		Seq:    seq,
		Status: walPending,
		ConnID: connID,
		Op:     op,
		Bucket: bucket,
		Key:    key,
		Data:   data,
	}
	if err := w.writeEntry(entry); err != nil {
		return 0, err
	}
	return seq, nil
}

// Commit 追加 committed 标记（仅 seq + status，约 20 字节）
// 签名与原实现完全一致，多余参数不使用，仅为保持接口兼容
// 不触发 bbolt 写入，bbolt 写入由后台 Flush 负责
func (w *WAL) Commit(connID string, seq uint64, op, bucket, key string, data []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	return w.writeEntry(walEntry{
		Seq:    seq,
		Status: walCommitted,
	})
}

// ============================================================
// Close
// ============================================================

func (w *WAL) Close() error {
	w.StopFlusher()
	w.mu.Lock()
	defer w.mu.Unlock()

	if err := w.writer.Flush(); err != nil {
		return err
	}
	return w.file.Close()
}

// ============================================================
// 后台刷盘：WAL → bbolt
// ============================================================

// StartFlusher 启动后台定时刷盘
func (w *WAL) StartFlusher(store Store, interval time.Duration) {
	w.store = store
	w.flushTicker = time.NewTicker(interval)
	go func() {
		for {
			select {
			case <-w.flushTicker.C:
				if err := w.Flush(); err != nil {
					log.Printf("[WAL] flush error: %v", err)
				}
			case <-w.flushDone:
				return
			}
		}
	}()
	log.Printf("[WAL] flusher started, interval=%v", interval)
}

// StopFlusher 停止刷盘并执行最后一次 flush
func (w *WAL) StopFlusher() {
	if w.flushTicker != nil {
		w.flushTicker.Stop()
	}
	select {
	case <-w.flushDone:
	default:
		close(w.flushDone)
	}
	if err := w.Flush(); err != nil {
		log.Printf("[WAL] final flush error: %v", err)
	}
	log.Printf("[WAL] flusher stopped")
}

// 新增方法：设置刷盘目标存储
func (w *WAL) SetStore(store Store) {
	w.store = store
}

// 修改 Flush：store 未设置时直接返回，不写 checkpoint、不截断
func (w *WAL) Flush() error {
	entries, lastSeq, err := w.readCommittedSinceCheckpoint()
	if err != nil {
		return fmt.Errorf("read committed: %w", err)
	}
	if len(entries) == 0 {
		return nil
	}

	// ---- 新增：store 未设置时跳过（保持 WAL 完整） ----
	if w.store == nil {
		return nil
	}

	// 批量写入 bbolt
	if err := w.store.Update(func(tx Tx) error {
		for _, e := range entries {
			switch e.Op {
			case WLOpPut:
				if err := tx.Put(e.Bucket, []byte(e.Key), e.Data); err != nil {
					return err
				}
			case WLOpDelete:
				if err := tx.Delete(e.Bucket, []byte(e.Key)); err != nil {
					return err
				}
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("batch apply to store: %w", err)
	}

	// checkpoint + 截断
	w.mu.Lock()
	defer w.mu.Unlock()

	if err := w.writeEntry(walEntry{
		Seq:    lastSeq,
		Status: walCheckpoint,
	}); err != nil {
		return fmt.Errorf("write checkpoint: %w", err)
	}

	log.Printf("[WAL] flushed %d entries, checkpoint_seq=%d", len(entries), lastSeq)
	return w.truncateBefore(lastSeq)
}

// ============================================================
// 恢复：启动时回放 WAL
// ============================================================

// Replay 回放 checkpoint 之后的所有已提交操作
// fn(op, key, data) 由调用方实现（注册到内存树 / 删除内存节点）
func (w *WAL) Replay(fn func(op, key string, data []byte) error) error {
	entries, _, err := w.readCommittedSinceCheckpoint()
	if err != nil {
		return fmt.Errorf("replay read: %w", err)
	}

	for _, e := range entries {
		if err := fn(e.Op, e.Key, e.Data); err != nil {
			return fmt.Errorf("replay seq=%d op=%s key=%s: %w", e.Seq, e.Op, e.Key, err)
		}
	}

	if len(entries) > 0 {
		log.Printf("[WAL] replayed %d operations", len(entries))
	}
	return nil
}

// ============================================================
// 内部方法
// ============================================================

func (w *WAL) writeEntry(entry walEntry) error {
	raw, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal entry: %w", err)
	}
	raw = append(raw, '\n')
	if _, err := w.writer.Write(raw); err != nil {
		return fmt.Errorf("write entry: %w", err)
	}
	return w.writer.Flush()
}

// scanMaxSeq 扫描 WAL 文件中最大的 seq（启动时调用）
func (w *WAL) scanMaxSeq() (uint64, error) {
	var maxSeq uint64
	err := w.scanFile(func(entry walEntry) bool {
		if entry.Seq > maxSeq {
			maxSeq = entry.Seq
		}
		return true
	})
	return maxSeq, err
}

// scanFile 用独立 fd 扫描 WAL 文件，callback 返回 false 提前终止
func (w *WAL) scanFile(fn func(walEntry) bool) error {
	f, err := os.Open(w.logPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, walBufSize), walMaxEntrySize)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var entry walEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			log.Printf("[WAL] skip malformed entry: %.80s...", string(line))
			continue
		}
		if !fn(entry) {
			break
		}
	}
	return scanner.Err()
}

// readCommittedSinceCheckpoint 单次扫描，返回 checkpoint 之后的所有已提交操作
func (w *WAL) readCommittedSinceCheckpoint() ([]walEntry, uint64, error) {
	var checkpointSeq uint64
	pending := make(map[uint64]walEntry)
	committed := make(map[uint64]bool)

	err := w.scanFile(func(entry walEntry) bool {
		switch entry.Status {
		case walCheckpoint:
			// checkpoint 之前的数据已刷盘，丢弃累积状态
			checkpointSeq = entry.Seq
			pending = make(map[uint64]walEntry)
			committed = make(map[uint64]bool)

		case walPending:
			if entry.Seq > checkpointSeq {
				pending[entry.Seq] = entry
			}

		case walCommitted:
			if entry.Seq > checkpointSeq {
				committed[entry.Seq] = true
			}
		}
		return true
	})
	if err != nil {
		return nil, 0, err
	}

	// 收集 pending+committed 配对成功的条目
	var result []walEntry
	var maxSeq uint64
	for seq, entry := range pending {
		if committed[seq] {
			result = append(result, entry)
			if seq > maxSeq {
				maxSeq = seq
			}
		}
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Seq < result[j].Seq
	})

	return result, maxSeq, nil
}

// truncateBefore 截断 WAL，移除 seq <= maxSeq 的所有条目
func (w *WAL) truncateBefore(maxSeq uint64) error {
	// 收集需要保留的条目
	var remaining []walEntry
	err := w.scanFile(func(entry walEntry) bool {
		if entry.Seq > maxSeq && entry.Status != walCheckpoint {
			remaining = append(remaining, entry)
		}
		return true
	})
	if err != nil {
		return fmt.Errorf("scan for truncate: %w", err)
	}

	// 刷写 + 关闭当前文件
	if err := w.writer.Flush(); err != nil {
		return err
	}
	if err := w.file.Close(); err != nil {
		return err
	}

	// 重写文件（只保留 checkpoint 之后的条目）
	f, err := os.Create(w.logPath)
	if err != nil {
		return fmt.Errorf("recreate wal: %w", err)
	}

	writer := bufio.NewWriterSize(f, walBufSize)
	for _, entry := range remaining {
		raw, _ := json.Marshal(entry)
		raw = append(raw, '\n')
		writer.Write(raw)
	}
	if err := writer.Flush(); err != nil {
		f.Close()
		return fmt.Errorf("flush remaining: %w", err)
	}

	w.file = f
	w.writer = writer
	return nil
}
