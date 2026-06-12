package storage

import "fmt"

// ============================================================
// Store 存储接口
// 定义事务化的持久化操作，所有业务层写操作必须通过此接口。
// 原型阶段由 bbolt 实现，生产阶段可替换为分布式数据库，
// 上层逻辑无需修改（接口不变，仅换后端）。
// ============================================================

type Store interface {
	// Update 在可写事务中执行 fn，成功自动提交，失败自动回滚
	Update(fn func(tx Tx) error) error

	// View 在只读事务中执行 fn
	View(fn func(tx Tx) error) error

	// Close 关闭存储后端
	Close() error
}

// Tx 事务接口
// 封装单次事务内的所有读写操作，保证原子性。
// 后续分布式扩展时可对接分布式事务协议（如 2PC / Saga）。
// ============================================================

type Tx interface {
	// Get 从指定 bucket 读取 key 对应的值
	// bucket 不存在或 key 不存在时返回 (nil, nil)
	Get(bucket string, key []byte) ([]byte, error)

	// Put 向指定 bucket 写入 key-value 对
	// 如果 bucket 不存在会自动创建
	Put(bucket string, key, value []byte) error

	// Delete 从指定 bucket 删除指定 key
	// key 不存在时视为成功操作
	Delete(bucket string, key []byte) error

	// Exist 检查指定 bucket 中是否存在某个 key
	Exist(bucket string, key []byte) (bool, error)

	// PrefixScan 扫描指定 bucket 中以 prefix 开头的所有 key-value 对
	// 返回结果按 key 字典序排列
	PrefixScan(bucket string, prefix []byte) ([][]byte, [][]byte, error)

	// ForEach 遍历指定 bucket 中的所有 key-value 对
	ForEach(bucket string, fn func(k, v []byte) error) error

	// Commit 提交事务
	Commit() error

	// Rollback 回滚事务
	Rollback() error
}

// ============================================================
// 预定义 bucket 名称
// 按业务域划分，类似 Column Family / Namespace 的隔离效果。
// ============================================================

const (
	BucketFingerprints = "fingerprints" // 六层 Hash 树指纹节点
	BucketPortraits    = "portraits"    // 用户历史画像摘要
	BucketBlacklist    = "blacklist"    // 被拉黑设备记录
	BucketWAL          = "wal"          // WAL 预写日志
	BucketSeq          = "seq"          // WAL 序列号计数器
)

// ============================================================
// Error 定义存储层通用错误
// ============================================================

var (
	ErrKeyNotFound  = fmt.Errorf("key not found")
	ErrTxNotStarted = fmt.Errorf("transaction not started")
	ErrTxCommitted  = fmt.Errorf("transaction already committed")
)
