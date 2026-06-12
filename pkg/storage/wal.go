package storage

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"time"
)

// ============================================================
// WALEntry WAL 日志条目
// 每条记录描述一次待持久化的写操作，用于崩溃恢复。
// ============================================================

type WALEntry struct {
	ConnectionID string    `json:"connection_id"` // 关联的连接标识
	Sequence     uint64    `json:"sequence"`      // 序列号，保证同一连接内有序
	Operation    WLOpType  `json:"operation"`     // 操作类型
	Bucket       string    `json:"bucket"`        // 目标 bucket
	Key          string    `json:"key"`           // 目标 key
	Value        []byte    `json:"value"`         // 目标 value（PUT 操作时有值）
	Timestamp    time.Time `json:"timestamp"`     // 操作时间
	Status       WLStatus  `json:"status"`        // 条目状态
}

// WLOpType WAL 操作类型
type WLOpType string

const (
	WLOpPut    WLOpType = "PUT"    // 写入操作
	WLOpDelete WLOpType = "DELETE" // 删除操作
)

// WLStatus WAL 条目状态
type WLStatus string

const (
	WLStatusPending   WLStatus = "PENDING"   // 写入中，尚未提交
	WLStatusCommitted WLStatus = "COMMITTED" // 已提交，等待清理
)

// WAL WAL 预写日志
// 所有持久化操作通过 WAL 统一管理：
//   1. 写操作前：写入 PENDING 日志
//   2. 执行实际写操作（同一事务内）
//   3. 标记 COMMITTED
//   4. 定期清理已提交的日志
// 崩溃恢复时扫描残留的 PENDING 记录并重放。
// ============================================================

type WAL struct {
	store Store
}

// NewWAL 创建 WAL 实例
func NewWAL(store Store) *WAL {
	return &WAL{store: store}
}

// ============================================================
// WAL 键格式
// bucket: wal
// key:    {connection_id}:{sequence_number:big_endian_uint64}
// 这样 PrefixScan(conn_id) 就能取出某个连接的所有 WAL 记录，
// 且按 sequence 自然排序。
// ============================================================

// walKey 组装 WAL 键
func walKey(connID string, seq uint64) []byte {
	buf := make([]byte, len(connID)+8)
	copy(buf, connID)
	binary.BigEndian.PutUint64(buf[len(connID):], seq)
	return buf
}

// nextSeq 获取连接的下一个 WAL 序列号
func (w *WAL) nextSeq(tx Tx, connID string) (uint64, error) {
	val, err := tx.Get(BucketSeq, []byte(connID))
	if err != nil {
		return 0, err
	}
	if val == nil {
		return 1, nil
	}
	return binary.BigEndian.Uint64(val) + 1, nil
}

// setSeq 更新连接的当前序列号
func (w *WAL) setSeq(tx Tx, connID string, seq uint64) error {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, seq)
	return tx.Put(BucketSeq, []byte(connID), buf)
}

// ============================================================
// Begin 开始一次 WAL 保护的写操作
// 返回 WAL 序列号，后续 Commit 需要使用此序列号。
// 日志条目状态为 PENDING。
// ============================================================

func (w *WAL) Begin(connID string, op WLOpType, bucket, key string, value []byte) (seq uint64, err error) {
	err = w.store.Update(func(tx Tx) error {
		var err error
		seq, err = w.nextSeq(tx, connID)
		if err != nil {
			return fmt.Errorf("get next seq: %w", err)
		}

		entry := WALEntry{
			ConnectionID: connID,
			Sequence:     seq,
			Operation:    op,
			Bucket:       bucket,
			Key:          key,
			Value:        value,
			Timestamp:    time.Now(),
			Status:       WLStatusPending,
		}

		data, err := json.Marshal(entry)
		if err != nil {
			return fmt.Errorf("marshal wal entry: %w", err)
		}

		if err := tx.Put(BucketWAL, walKey(connID, seq), data); err != nil {
			return fmt.Errorf("write wal entry: %w", err)
		}

		if err := w.setSeq(tx, connID, seq); err != nil {
			return fmt.Errorf("update seq: %w", err)
		}

		return nil
	})
	return
}

// ============================================================
// Commit 提交 WAL 保护的写操作
// 1. 执行实际的数据写入/删除（在同一事务内）
// 2. 标记 WAL 条目为 COMMITTED
// 3. 清理该连接所有已提交的 WAL 条目
// ============================================================

func (w *WAL) Commit(connID string, seq uint64, op WLOpType, bucket, key string, value []byte) error {
	return w.store.Update(func(tx Tx) error {
		// 1. 执行实际操作
		switch op {
		case WLOpPut:
			if err := tx.Put(bucket, []byte(key), value); err != nil {
				return fmt.Errorf("data put: %w", err)
			}
		case WLOpDelete:
			if err := tx.Delete(bucket, []byte(key)); err != nil {
				return fmt.Errorf("data delete: %w", err)
			}
		}

		// 2. 标记 WAL 条目为 COMMITTED
		walData, err := tx.Get(BucketWAL, walKey(connID, seq))
		if err != nil {
			return fmt.Errorf("get wal entry: %w", err)
		}
		if walData != nil {
			var entry WALEntry
			if err := json.Unmarshal(walData, &entry); err == nil {
				entry.Status = WLStatusCommitted
				committed, _ := json.Marshal(entry)
				tx.Put(BucketWAL, walKey(connID, seq), committed)
			}
		}

		// 3. 清理已提交的 WAL 条目
		w.cleanupCommitted(tx, connID)

		return nil
	})
}

// cleanupCommitted 清理指定连接的已提交 WAL 条目
// 先收集待删除的 key 列表，再统一删除，避免在遍历中修改 bucket。
func (w *WAL) cleanupCommitted(tx Tx, connID string) {
	var toDelete [][]byte

	// 第一遍：扫描收集所有已提交的 key
	tx.ForEach(BucketWAL, func(k, v []byte) error {
		// 只处理属于当前连接的条目
		if len(k) < len(connID)+8 || string(k[:len(connID)]) != connID {
			return nil
		}
		var entry WALEntry
		if err := json.Unmarshal(v, &entry); err != nil {
			return nil
		}
		if entry.Status == WLStatusCommitted {
			ck := make([]byte, len(k))
			copy(ck, k)
			toDelete = append(toDelete, ck)
		}
		return nil
	})

	// 第二遍：统一删除
	for _, dk := range toDelete {
		tx.Delete(BucketWAL, dk)
	}
}

// ============================================================
// Recover 崩溃恢复
// 扫描 WAL bucket 中所有 PENDING 状态的条目，逐条重放。
// 先收集再处理，避免 ForEach 期间修改 bucket。
// ============================================================

func (w *WAL) Recover() (int, error) {
	var pending []struct {
		key   []byte
		entry WALEntry
	}

	// 1. 收集所有 PENDING 条目
	err := w.store.View(func(tx Tx) error {
		return tx.ForEach(BucketWAL, func(k, v []byte) error {
			var entry WALEntry
			if err := json.Unmarshal(v, &entry); err != nil {
				return nil
			}
			if entry.Status == WLStatusPending {
				ck := make([]byte, len(k))
				copy(ck, k)
				pending = append(pending, struct {
					key   []byte
					entry WALEntry
				}{ck, entry})
			}
			return nil
		})
	})
	if err != nil {
		return 0, fmt.Errorf("scan wal: %w", err)
	}

	if len(pending) == 0 {
		return 0, nil
	}

	// 2. 在事务中逐条重放
	replayed := 0
	err = w.store.Update(func(tx Tx) error {
		for _, p := range pending {
			switch p.entry.Operation {
			case WLOpPut:
				if err := tx.Put(p.entry.Bucket, []byte(p.entry.Key), p.entry.Value); err != nil {
					return fmt.Errorf("replay put: %w", err)
				}
			case WLOpDelete:
				if err := tx.Delete(p.entry.Bucket, []byte(p.entry.Key)); err != nil {
					return fmt.Errorf("replay delete: %w", err)
				}
			}

			// 标记为 COMMITTED 并清理
			p.entry.Status = WLStatusCommitted
			committed, _ := json.Marshal(p.entry)
			tx.Put(BucketWAL, p.key, committed)
			replayed++
		}

		// 清理所有已提交的 WAL 条目
		w.cleanupAllCommitted(tx)
		return nil
	})
	return replayed, err
}

// ============================================================
// CleanupAll 清理所有已提交的 WAL 条目
// 可由后台定时任务调用
// ============================================================

func (w *WAL) CleanupAll() (int, error) {
	cleaned := 0
	err := w.store.Update(func(tx Tx) error {
		var toDelete [][]byte
		tx.ForEach(BucketWAL, func(k, v []byte) error {
			var entry WALEntry
			if err := json.Unmarshal(v, &entry); err != nil {
				return nil
			}
			if entry.Status == WLStatusCommitted {
				ck := make([]byte, len(k))
				copy(ck, k)
				toDelete = append(toDelete, ck)
			}
			return nil
		})
		for _, dk := range toDelete {
			tx.Delete(BucketWAL, dk)
			cleaned++
		}
		return nil
	})
	return cleaned, err
}

// cleanupAllCommitted 清理所有已提交的 WAL 条目（事务内调用）
func (w *WAL) cleanupAllCommitted(tx Tx) {
	var toDelete [][]byte
	tx.ForEach(BucketWAL, func(k, v []byte) error {
		var entry WALEntry
		if err := json.Unmarshal(v, &entry); err != nil {
			return nil
		}
		if entry.Status == WLStatusCommitted {
			ck := make([]byte, len(k))
			copy(ck, k)
			toDelete = append(toDelete, ck)
		}
		return nil
	})
	for _, dk := range toDelete {
		tx.Delete(BucketWAL, dk)
	}
}

// ============================================================
// GetPending 获取指定连接的所有 PENDING WAL 条目
// 用于调试和审计
// ============================================================

func (w *WAL) GetPending(connID string) ([]WALEntry, error) {
	var entries []WALEntry
	err := w.store.View(func(tx Tx) error {
		return tx.ForEach(BucketWAL, func(k, v []byte) error {
			if len(k) < len(connID)+8 || string(k[:len(connID)]) != connID {
				return nil
			}
			var entry WALEntry
			if err := json.Unmarshal(v, &entry); err != nil {
				return nil
			}
			if entry.Status == WLStatusPending {
				entries = append(entries, entry)
			}
			return nil
		})
	})
	return entries, err
}
