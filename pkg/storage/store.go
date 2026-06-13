package storage

import "fmt"

// ============================================================
// Store 存储接口
// ============================================================

type Store interface {
	Update(fn func(tx Tx) error) error
	View(fn func(tx Tx) error) error
	Close() error
}

type Tx interface {
	Get(bucket string, key []byte) ([]byte, error)
	Put(bucket string, key, value []byte) error
	Delete(bucket string, key []byte) error
	Exist(bucket string, key []byte) (bool, error)
	PrefixScan(bucket string, prefix []byte) ([][]byte, [][]byte, error)
	ForEach(bucket string, fn func(k, v []byte) error) error
	Commit() error
	Rollback() error
}

// ============================================================
// 预定义 bucket 名称
// ============================================================

const (
	BucketFingerprints  = "fingerprints"   // 六层 Hash 树指纹节点
	BucketPortraits     = "portraits"      // 用户历史画像摘要
	BucketBlacklist     = "blacklist"      // 被拉黑设备记录
	BucketWAL           = "wal"            // WAL 预写日志
	BucketSeq           = "seq"            // WAL 序列号计数器
	BucketDispatchTasks = "dispatch_tasks" // DispatchManager 溢出持久化任务
)

// ============================================================
// Error
// ============================================================

var (
	ErrKeyNotFound  = fmt.Errorf("key not found")
	ErrTxNotStarted = fmt.Errorf("transaction not started")
	ErrTxCommitted  = fmt.Errorf("transaction already committed")
)
