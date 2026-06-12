package storage

import (
	"bytes"
	"encoding/json"
	"log"
	"os"
	"testing"
)

func newTestStore(t *testing.T) Store {
	t.Helper()
	tmpFile, err := os.CreateTemp("", "wal-test-*.db")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	tmpFile.Close()

	store, err := NewBoltStore(tmpFile.Name())
	if err != nil {
		os.Remove(tmpFile.Name())
		t.Fatalf("new bolt store: %v", err)
	}
	t.Cleanup(func() {
		store.Close()
		os.Remove(tmpFile.Name())
	})
	return store
}

func TestWAL_BeginCommit(t *testing.T) {
	store := newTestStore(t)
	wal := NewWAL(store)

	// Begin 一条 WAL 记录
	seq, err := wal.Begin("conn-001", WLOpPut, BucketFingerprints, "node:abc", []byte("data"))
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if seq != 1 {
		t.Errorf("seq = %d, want 1", seq)
	}

	// 验证 PENDING 记录存在
	pending, err := wal.GetPending("conn-001")
	if err != nil {
		t.Fatalf("get pending: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("pending count = %d, want 1", len(pending))
	}
	if pending[0].Status != WLStatusPending {
		t.Errorf("status = %s, want PENDING", pending[0].Status)
	}
	if pending[0].Bucket != BucketFingerprints {
		t.Errorf("bucket = %s, want %s", pending[0].Bucket, BucketFingerprints)
	}
	if pending[0].Key != "node:abc" {
		t.Errorf("key = %s, want node:abc", pending[0].Key)
	}
	// 验证 PENDING 记录中的 value 正确保存
	log.Print(string(pending[0].Value))
	if !bytes.Equal(pending[0].Value, []byte("data")) {
		t.Errorf("pending value = %v, want [100 97 116 97]", pending[0].Value)
	}

	// Commit
	err = wal.Commit("conn-001", seq, WLOpPut, BucketFingerprints, "node:abc", []byte("data"))
	if err != nil {
		t.Fatalf("commit: %v", err)
	}

	// 验证数据已写入，使用 bytes.Equal 严格校验
	err = store.View(func(tx Tx) error {
		val, err := tx.Get(BucketFingerprints, []byte("node:abc"))
		if err != nil {
			return err
		}
		if val == nil {
			t.Fatal("val is nil, expected data to be written")
		}
		if !bytes.Equal(val, []byte("data")) {
			t.Errorf("val = %v (len=%d), want [100 97 116 97] (len=4)", val, len(val))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("view: %v", err)
	}

	// 验证 WAL 条目已清理
	pending, err = wal.GetPending("conn-001")
	if err != nil {
		t.Fatalf("get pending after commit: %v", err)
	}
	if len(pending) != 0 {
		t.Errorf("pending count after commit = %d, want 0", len(pending))
	}
}

func TestWAL_SequenceIncrement(t *testing.T) {
	store := newTestStore(t)
	wal := NewWAL(store)

	seq1, _ := wal.Begin("conn-001", WLOpPut, "test", "k1", []byte("v1"))
	seq2, _ := wal.Begin("conn-001", WLOpPut, "test", "k2", []byte("v2"))
	seq3, _ := wal.Begin("conn-002", WLOpPut, "test", "k3", []byte("v3"))

	if seq1 != 1 || seq2 != 2 || seq3 != 1 {
		t.Errorf("seqs = %d, %d, %d; want 1, 2, 1", seq1, seq2, seq3)
	}
}

func TestWAL_Delete(t *testing.T) {
	store := newTestStore(t)
	wal := NewWAL(store)

	// 先写入数据
	store.Update(func(tx Tx) error {
		return tx.Put(BucketBlacklist, []byte("dev-001"), []byte("reason"))
	})

	// 验证数据已写入
	store.View(func(tx Tx) error {
		val, _ := tx.Get(BucketBlacklist, []byte("dev-001"))
		if !bytes.Equal(val, []byte("reason")) {
			t.Errorf("before delete: val = %v, want [114 101 97 115 111 110]", val)
		}
		return nil
	})

	// 通过 WAL 删除
	seq, err := wal.Begin("conn-001", WLOpDelete, BucketBlacklist, "dev-001", nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}

	err = wal.Commit("conn-001", seq, WLOpDelete, BucketBlacklist, "dev-001", nil)
	if err != nil {
		t.Fatalf("commit: %v", err)
	}

	// 验证数据已删除
	store.View(func(tx Tx) error {
		val, _ := tx.Get(BucketBlacklist, []byte("dev-001"))
		if val != nil {
			t.Errorf("after delete: val = %v (len=%d), want nil", val, len(val))
		}
		return nil
	})
}

func TestWAL_Recover(t *testing.T) {
	tmpFile, _ := os.CreateTemp("", "wal-recover-*.db")
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	// 第一个实例：写入 PENDING 记录但不 commit（模拟崩溃）
	{
		store, err := NewBoltStore(tmpFile.Name())
		if err != nil {
			t.Fatal(err)
		}
		wal := NewWAL(store)

		store.Update(func(tx Tx) error {
			seq, _ := wal.nextSeq(tx, "conn-crash")
			entry := WALEntry{
				ConnectionID: "conn-crash",
				Sequence:     seq,
				Operation:    WLOpPut,
				Bucket:       BucketFingerprints,
				Key:          "recovered-key",
				Value:        []byte("recovered-value"),
				Status:       WLStatusPending,
			}
			data, _ := json.Marshal(entry)
			tx.Put(BucketWAL, walKey("conn-crash", seq), data)
			wal.setSeq(tx, "conn-crash", seq)
			return nil
		})
		store.Close()
	}

	// 第二个实例：恢复
	{
		store, err := NewBoltStore(tmpFile.Name())
		if err != nil {
			t.Fatal(err)
		}
		wal := NewWAL(store)

		count, err := wal.Recover()
		if err != nil {
			t.Fatalf("recover: %v", err)
		}
		if count != 1 {
			t.Errorf("replayed = %d, want 1", count)
		}

		// 用 bytes.Equal 严格校验恢复的数据
		store.View(func(tx Tx) error {
			val, err := tx.Get(BucketFingerprints, []byte("recovered-key"))
			if err != nil {
				return err
			}
			if val == nil {
				t.Fatal("val is nil, expected recovered data")
			}
			if !bytes.Equal(val, []byte("recovered-value")) {
				t.Errorf("val = %v (len=%d), want [114 101 99 111 118 101 114 101 100 45 118 97 108 117 101] (len=16)", val, len(val))
			}
			return nil
		})

		// 验证 WAL 已清理
		pending, _ := wal.GetPending("conn-crash")
		if len(pending) != 0 {
			t.Errorf("pending after recover = %d, want 0", len(pending))
		}

		store.Close()
	}
}

func TestWAL_MultipleOpsInSequence(t *testing.T) {
	store := newTestStore(t)
	wal := NewWAL(store)

	// 写入多条数据
	for i := 0; i < 10; i++ {
		key := bytes.Repeat([]byte("k"), 1)
		key = []byte{byte(i + 65)}  // A, B, C ...
		val := []byte{byte(i + 97)} // a, b, c ...

		seq, err := wal.Begin("conn-seq", WLOpPut, BucketFingerprints, string(key), val)
		if err != nil {
			t.Fatalf("begin %d: %v", i, err)
		}
		if int(seq) != i+1 {
			t.Errorf("seq = %d, want %d", seq, i+1)
		}

		err = wal.Commit("conn-seq", seq, WLOpPut, BucketFingerprints, string(key), val)
		if err != nil {
			t.Fatalf("commit %d: %v", i, err)
		}
	}

	// 验证所有数据都正确写入
	store.View(func(tx Tx) error {
		for i := 0; i < 10; i++ {
			key := []byte{byte(i + 65)}
			expected := []byte{byte(i + 97)}
			val, err := tx.Get(BucketFingerprints, key)
			if err != nil {
				t.Errorf("get %s: %v", key, err)
				continue
			}
			if val == nil {
				t.Errorf("key %s: val is nil, want %v", key, expected)
				continue
			}
			if !bytes.Equal(val, expected) {
				t.Errorf("key %s: val = %v, want %v", key, val, expected)
			}
		}
		return nil
	})

	// 验证 WAL 已清理
	pending, _ := wal.GetPending("conn-seq")
	if len(pending) != 0 {
		t.Errorf("pending = %d, want 0", len(pending))
	}
}
