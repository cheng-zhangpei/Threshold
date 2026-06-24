package storage

import "fmt"

// Store storage interface
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

const (
	BucketFingerprints  = "fingerprints"
	BucketPortraits     = "portraits"
	BucketProfiles      = "profiles"
	BucketBlacklist     = "blacklist"
	BucketWAL           = "wal"
	BucketSeq           = "seq"
	BucketDispatchTasks = "dispatch_tasks"
	BucketAdminTokens   = "admin_tokens"
	BucketAdminCreds    = "admin_credentials"
)

var (
	ErrKeyNotFound  = fmt.Errorf("key not found")
	ErrTxNotStarted = fmt.Errorf("transaction not started")
	ErrTxCommitted  = fmt.Errorf("transaction already committed")
)
