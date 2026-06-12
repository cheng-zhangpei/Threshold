package storage

import (
	"bytes"
	"fmt"

	"go.etcd.io/bbolt"
)

// BoltStore bbolt 实现的 Store
// 使用 bbolt 的原生事务保证原子性，
// 所有 bucket 作为独立的 key-value 命名空间。
// ============================================================

type BoltStore struct {
	db *bbolt.DB
}

// NewBoltStore 创建或打开 bbolt 数据库
func NewBoltStore(path string) (*BoltStore, error) {
	db, err := bbolt.Open(path, 0600, nil)
	if err != nil {
		return nil, fmt.Errorf("open bolt db %s: %w", path, err)
	}
	// 初始化所有预定义 bucket
	err = db.Update(func(tx *bbolt.Tx) error {
		for _, name := range []string{
			BucketFingerprints,
			BucketPortraits,
			BucketBlacklist,
			BucketWAL,
			BucketSeq,
		} {
			if _, err := tx.CreateBucketIfNotExists([]byte(name)); err != nil {
				return fmt.Errorf("create bucket %s: %w", name, err)
			}
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	return &BoltStore{db: db}, nil
}

func (s *BoltStore) Update(fn func(tx Tx) error) error {
	return s.db.Update(func(boltTx *bbolt.Tx) error {
		w := &boltTxWrapper{tx: boltTx, closed: false, readOnly: false}
		err := fn(w)
		w.closed = true
		return err
	})
}

func (s *BoltStore) View(fn func(tx Tx) error) error {
	return s.db.View(func(boltTx *bbolt.Tx) error {
		w := &boltTxWrapper{tx: boltTx, closed: false, readOnly: true}
		err := fn(w)
		w.closed = true
		return err
	})
}

func (s *BoltStore) Close() error {
	return s.db.Close()
}

// ============================================================
// boltTxWrapper 封装 bbolt 事务为 Tx 接口
// closed: 事务已结束（提交或回滚），不能再操作
// readOnly: 只读事务（View），不允许写操作
// ============================================================

type boltTxWrapper struct {
	tx       *bbolt.Tx
	closed   bool
	readOnly bool
}

func (w *boltTxWrapper) checkWrite() error {
	if w.closed {
		return ErrTxCommitted
	}
	if w.readOnly {
		return fmt.Errorf("read-only transaction")
	}
	return nil
}

func (w *boltTxWrapper) Get(bucket string, key []byte) ([]byte, error) {
	if w.closed {
		return nil, ErrTxCommitted
	}
	b := w.tx.Bucket([]byte(bucket))
	if b == nil {
		return nil, nil
	}
	val := b.Get(key)
	if val == nil {
		return nil, nil
	}
	// bbolt 返回的 value 在事务结束前有效，需要拷贝
	ret := make([]byte, len(val))
	copy(ret, val)
	return ret, nil
}

func (w *boltTxWrapper) Put(bucket string, key, value []byte) error {
	if err := w.checkWrite(); err != nil {
		return err
	}
	b, err := w.tx.CreateBucketIfNotExists([]byte(bucket))
	if err != nil {
		return fmt.Errorf("create bucket %s: %w", bucket, err)
	}
	return b.Put(key, value)
}

func (w *boltTxWrapper) Delete(bucket string, key []byte) error {
	if err := w.checkWrite(); err != nil {
		return err
	}
	b := w.tx.Bucket([]byte(bucket))
	if b == nil {
		return nil
	}
	return b.Delete(key)
}

func (w *boltTxWrapper) Exist(bucket string, key []byte) (bool, error) {
	val, err := w.Get(bucket, key)
	if err != nil {
		return false, err
	}
	return val != nil, nil
}

func (w *boltTxWrapper) PrefixScan(bucket string, prefix []byte) ([][]byte, [][]byte, error) {
	if w.closed {
		return nil, nil, ErrTxCommitted
	}
	b := w.tx.Bucket([]byte(bucket))
	if b == nil {
		return nil, nil, nil
	}

	var keys, values [][]byte
	c := b.Cursor()
	for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
		ck := make([]byte, len(k))
		copy(ck, k)
		cv := make([]byte, len(v))
		copy(cv, v)
		keys = append(keys, ck)
		values = append(values, cv)
	}
	return keys, values, nil
}

func (w *boltTxWrapper) ForEach(bucket string, fn func(k, v []byte) error) error {
	if w.closed {
		return ErrTxCommitted
	}
	b := w.tx.Bucket([]byte(bucket))
	if b == nil {
		return nil
	}
	return b.ForEach(func(k, v []byte) error {
		ck := make([]byte, len(k))
		copy(ck, k)
		cv := make([]byte, len(v))
		copy(cv, v)
		return fn(ck, cv)
	})
}

func (w *boltTxWrapper) Commit() error {
	if w.closed {
		return ErrTxCommitted
	}
	w.closed = true
	// bbolt 的 Commit 由上层 Update/View 管理
	return nil
}

func (w *boltTxWrapper) Rollback() error {
	if w.closed {
		return ErrTxCommitted
	}
	w.closed = true
	return w.tx.Rollback()
}
