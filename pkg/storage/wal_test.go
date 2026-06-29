package storage

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ============================================================
// 辅助
// ============================================================

func newTestWAL(t *testing.T) (*WAL, string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "wal-test-*")
	if err != nil {
		t.Fatalf("mkdir temp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	wal, err := NewWAL(dir)
	if err != nil {
		t.Fatalf("new wal: %v", err)
	}
	t.Cleanup(func() { wal.Close() })

	return wal, dir
}

func newTestStore(t *testing.T, dir string) Store {
	t.Helper()
	store, err := NewBoltStore(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("new bolt store: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

// ============================================================
// 基础读写
// ============================================================

func TestWAL_BeginCommit(t *testing.T) {
	wal, _ := newTestWAL(t)

	// Begin 一条记录
	seq, err := wal.Begin("conn-001", WLOpPut, BucketFingerprints, "node:abc", []byte("data"))
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if seq != 1 {
		t.Errorf("seq = %d, want 1", seq)
	}

	// Commit
	err = wal.Commit("conn-001", seq, WLOpPut, BucketFingerprints, "node:abc", []byte("data"))
	if err != nil {
		t.Fatalf("commit: %v", err)
	}

	// Commit 后读已提交条目（不涉及 bbolt）
	entries, lastSeq, err := wal.readCommittedSinceCheckpoint()
	if err != nil {
		t.Fatalf("read committed: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("committed entries = %d, want 1", len(entries))
	}
	if entries[0].Key != "node:abc" {
		t.Errorf("key = %s, want node:abc", entries[0].Key)
	}
	if string(entries[0].Data) != "data" {
		t.Errorf("data = %s, want data", string(entries[0].Data))
	}
	if lastSeq != 1 {
		t.Errorf("lastSeq = %d, want 1", lastSeq)
	}
}

func TestWAL_PendingNotFlushed(t *testing.T) {
	wal, _ := newTestWAL(t)

	// Begin 但不 Commit（模拟请求还在处理中）
	_, err := wal.Begin("conn-001", WLOpPut, BucketFingerprints, "node:abc", []byte("data"))
	if err != nil {
		t.Fatalf("begin: %v", err)
	}

	// 未 Commit 的条目不应被当作已提交
	entries, _, err := wal.readCommittedSinceCheckpoint()
	if err != nil {
		t.Fatalf("read committed: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("committed entries = %d, want 0 (only pending)", len(entries))
	}
}

// ============================================================
// 序列号递增（全局）
// ============================================================

func TestWAL_SequenceIncrement(t *testing.T) {
	wal, _ := newTestWAL(t)

	seq1, _ := wal.Begin("conn-001", WLOpPut, "scripts", "k1", []byte("v1"))
	seq2, _ := wal.Begin("conn-001", WLOpPut, "scripts", "k2", []byte("v2"))
	seq3, _ := wal.Begin("conn-002", WLOpPut, "scripts", "k3", []byte("v3"))

	if seq1 != 1 {
		t.Errorf("seq1 = %d, want 1", seq1)
	}
	if seq2 != 2 {
		t.Errorf("seq2 = %d, want 2", seq2)
	}
	if seq3 != 3 {
		t.Errorf("seq3 = %d, want 3", seq3)
	}
}

// ============================================================
// Flush：WAL → bbolt 批量刷盘
// ============================================================

func TestWAL_Flush(t *testing.T) {
	wal, dir := newTestWAL(t)
	store := newTestStore(t, dir)
	wal.SetStore(store)

	// 写 3 条并全部 Commit
	for i := 0; i < 3; i++ {
		key := "key-" + string(rune('A'+i))
		val := []byte{byte(i + 97)}

		seq, err := wal.Begin("conn-001", WLOpPut, BucketFingerprints, key, val)
		if err != nil {
			t.Fatalf("begin %d: %v", i, err)
		}
		err = wal.Commit("conn-001", seq, WLOpPut, BucketFingerprints, key, val)
		if err != nil {
			t.Fatalf("commit %d: %v", i, err)
		}
	}

	// Flush：写入 bbolt + checkpoint + 截断
	if err := wal.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}

	// 验证 bbolt 中有数据
	store.View(func(tx Tx) error {
		for i := 0; i < 3; i++ {
			key := "key-" + string(rune('A'+i))
			expected := []byte{byte(i + 97)}
			val, _ := tx.Get(BucketFingerprints, []byte(key))
			if val == nil {
				t.Errorf("key %s: val is nil", key)
				continue
			}
			if string(val) != string(expected) {
				t.Errorf("key %s: val = %s, want %s", key, val, expected)
			}
		}
		return nil
	})

	// 验证 Flush 后无待提交条目
	entries, _, _ := wal.readCommittedSinceCheckpoint()
	if len(entries) != 0 {
		t.Errorf("committed after flush = %d, want 0", len(entries))
	}
}

func TestWAL_FlushDelete(t *testing.T) {
	wal, dir := newTestWAL(t)
	store := newTestStore(t, dir)
	wal.SetStore(store)

	// 先直接写入 bbolt
	store.Update(func(tx Tx) error {
		return tx.Put(BucketBlacklist, []byte("dev-001"), []byte("reason"))
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

	// Flush
	if err := wal.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}

	// 验证已删除
	store.View(func(tx Tx) error {
		val, _ := tx.Get(BucketBlacklist, []byte("dev-001"))
		if val != nil {
			t.Errorf("dev-001 should be deleted, got %v", val)
		}
		return nil
	})
}

// ============================================================
// 多轮 Flush（增量刷盘）
// ============================================================

func TestWAL_MultipleFlushRounds(t *testing.T) {
	wal, dir := newTestWAL(t)
	store := newTestStore(t, dir)
	wal.SetStore(store)

	// 第一轮
	for i := 0; i < 3; i++ {
		key := string(rune('A' + i))
		seq, _ := wal.Begin("c", WLOpPut, BucketFingerprints, key, []byte("v"))
		wal.Commit("c", seq, WLOpPut, BucketFingerprints, key, []byte("v"))
	}
	if err := wal.Flush(); err != nil {
		t.Fatalf("flush round 1: %v", err)
	}

	// 第二轮
	for i := 3; i < 6; i++ {
		key := string(rune('A' + i))
		seq, _ := wal.Begin("c", WLOpPut, BucketFingerprints, key, []byte("v"))
		wal.Commit("c", seq, WLOpPut, BucketFingerprints, key, []byte("v"))
	}
	if err := wal.Flush(); err != nil {
		t.Fatalf("flush round 2: %v", err)
	}

	// 验证 bbolt 中有 6 条
	store.View(func(tx Tx) error {
		for i := 0; i < 6; i++ {
			key := string(rune('A' + i))
			val, _ := tx.Get(BucketFingerprints, []byte(key))
			if val == nil {
				t.Errorf("key %s: missing after 2 flush rounds", key)
			}
		}
		return nil
	})
}

// ============================================================
// 批量操作
// ============================================================

func TestWAL_MultipleOps(t *testing.T) {
	wal, dir := newTestWAL(t)
	store := newTestStore(t, dir)
	wal.SetStore(store)

	for i := 0; i < 10; i++ {
		key := string(rune(i + 65))
		val := []byte{byte(i + 97)}

		seq, err := wal.Begin("conn-seq", WLOpPut, BucketFingerprints, key, val)
		if err != nil {
			t.Fatalf("begin %d: %v", i, err)
		}
		if int(seq) != i+1 {
			t.Errorf("seq = %d, want %d", seq, i+1)
		}
		err = wal.Commit("conn-seq", seq, WLOpPut, BucketFingerprints, key, val)
		if err != nil {
			t.Fatalf("commit %d: %v", i, err)
		}
	}

	if err := wal.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}

	store.View(func(tx Tx) error {
		for i := 0; i < 10; i++ {
			key := []byte{byte(i + 65)}
			expected := []byte{byte(i + 97)}
			val, _ := tx.Get(BucketFingerprints, key)
			if val == nil {
				t.Errorf("key %s: val is nil", key)
				continue
			}
			if string(val) != string(expected) {
				t.Errorf("key %s: val = %v, want %v", key, val, expected)
			}
		}
		return nil
	})
}

// ============================================================
// 崩溃恢复：Replay
// 关键：不设置 store → Flush 为 no-op → WAL 完整保留
// ============================================================

func TestWAL_Replay_AfterCrash(t *testing.T) {
	dir, _ := os.MkdirTemp("", "wal-replay-*")
	defer os.RemoveAll(dir)

	// ---- 第一个实例：写入数据但不 Flush（模拟崩溃） ----
	{
		wal, err := NewWAL(dir)
		if err != nil {
			t.Fatal(err)
		}

		// 3 条已提交（应被恢复）
		for i := 0; i < 3; i++ {
			key := "recovered-" + string(rune('A'+i))
			seq, _ := wal.Begin("conn-crash", WLOpPut, BucketFingerprints, key, []byte("val"))
			wal.Commit("conn-crash", seq, WLOpPut, BucketFingerprints, key, []byte("val"))
		}

		// 1 条未提交（不应被恢复）
		wal.Begin("conn-crash", WLOpPut, BucketFingerprints, "lost-key", []byte("lost-val"))

		// 不设 store，Close → Flush 为 no-op，WAL 保留
		wal.Close()
	}

	// ---- 第二个实例：恢复 ----
	{
		wal, err := NewWAL(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer wal.Close()

		count := 0
		err = wal.Replay(func(op, key string, data []byte) error {
			count++
			if op != WLOpPut {
				t.Errorf("op = %s, want PUT", op)
			}
			if key == "lost-key" {
				t.Error("uncommitted entry should not be replayed")
			}
			return nil
		})
		if err != nil {
			t.Fatalf("replay: %v", err)
		}
		if count != 3 {
			t.Errorf("replayed = %d, want 3", count)
		}
	}
}

func TestWAL_Replay_OnlyCommitted(t *testing.T) {
	dir, _ := os.MkdirTemp("", "wal-replay-committed-*")
	defer os.RemoveAll(dir)

	{
		wal, _ := NewWAL(dir)

		// 5 条全部 Commit
		for i := 0; i < 5; i++ {
			key := "commit-" + string(rune('A'+i))
			seq, _ := wal.Begin("c", WLOpPut, BucketFingerprints, key, []byte("v"))
			wal.Commit("c", seq, WLOpPut, BucketFingerprints, key, []byte("v"))
		}

		// 2 条只 Begin 不 Commit
		wal.Begin("c", WLOpPut, BucketFingerprints, "pending-1", []byte("v"))
		wal.Begin("c", WLOpPut, BucketFingerprints, "pending-2", []byte("v"))

		// 不设 store → Close 不截断 WAL
		wal.Close()
	}

	{
		wal, _ := NewWAL(dir)
		defer wal.Close()

		count := 0
		wal.Replay(func(op, key string, data []byte) error {
			count++
			return nil
		})
		if count != 5 {
			t.Errorf("replayed = %d, want 5 (only committed)", count)
		}
	}
}

func TestWAL_Replay_AfterFlush(t *testing.T) {
	dir, _ := os.MkdirTemp("", "wal-replay-after-flush-*")
	defer os.RemoveAll(dir)

	// ---- 第一轮：写 3 条 + Flush（真正刷到 bbolt） ----
	{
		wal, _ := NewWAL(dir)
		store := newTestStore(t, dir)
		wal.SetStore(store)

		for i := 0; i < 3; i++ {
			key := "first-" + string(rune('A'+i))
			seq, _ := wal.Begin("c", WLOpPut, BucketFingerprints, key, []byte("v"))
			wal.Commit("c", seq, WLOpPut, BucketFingerprints, key, []byte("v"))
		}
		wal.Flush() // 写入 bbolt + checkpoint + 截断
		wal.Close()
	}

	// ---- 第二轮：再写 2 条，不 Flush（模拟崩溃） ----
	{
		wal, _ := NewWAL(dir)
		// 不设 store → Close 不截断

		for i := 0; i < 2; i++ {
			key := "second-" + string(rune('A'+i))
			seq, _ := wal.Begin("c", WLOpPut, BucketFingerprints, key, []byte("v"))
			wal.Commit("c", seq, WLOpPut, BucketFingerprints, key, []byte("v"))
		}
		wal.Close()
	}

	// ---- 第三轮：Replay 应只恢复第二轮的 2 条 ----
	{
		wal, _ := NewWAL(dir)
		defer wal.Close()

		count := 0
		wal.Replay(func(op, key string, data []byte) error {
			count++
			return nil
		})
		if count != 2 {
			t.Errorf("replayed = %d, want 2 (only post-checkpoint)", count)
		}
	}
}

// ============================================================
// Flush 后新条目不丢失
// ============================================================

func TestWAL_FlushThenNewWrites(t *testing.T) {
	wal, dir := newTestWAL(t)
	store := newTestStore(t, dir)
	wal.SetStore(store)

	// 第一批
	for i := 0; i < 3; i++ {
		key := "batch1-" + string(rune('A'+i))
		seq, _ := wal.Begin("c", WLOpPut, BucketFingerprints, key, []byte("v"))
		wal.Commit("c", seq, WLOpPut, BucketFingerprints, key, []byte("v"))
	}
	wal.Flush()

	// Flush 后再写
	for i := 0; i < 3; i++ {
		key := "batch2-" + string(rune('A'+i))
		seq, _ := wal.Begin("c", WLOpPut, BucketFingerprints, key, []byte("v"))
		wal.Commit("c", seq, WLOpPut, BucketFingerprints, key, []byte("v"))
	}

	// Flush 后新条目应可读
	entries, _, _ := wal.readCommittedSinceCheckpoint()
	if len(entries) != 3 {
		t.Errorf("new entries after flush = %d, want 3", len(entries))
	}

	// 再次 Flush → 全部在 bbolt
	wal.Flush()
	store.View(func(tx Tx) error {
		for i := 0; i < 3; i++ {
			key := "batch2-" + string(rune('A'+i))
			val, _ := tx.Get(BucketFingerprints, []byte(key))
			if val == nil {
				t.Errorf("batch2 key %s: missing", key)
			}
		}
		return nil
	})
}

// ============================================================
// 后台 flusher
// ============================================================

func TestWAL_BackgroundFlusher(t *testing.T) {
	wal, dir := newTestWAL(t)
	store := newTestStore(t, dir)

	// StartFlusher 内部会 SetStore
	wal.StartFlusher(store, 100*time.Millisecond)

	for i := 0; i < 3; i++ {
		key := "bg-" + string(rune('A'+i))
		seq, _ := wal.Begin("c", WLOpPut, BucketFingerprints, key, []byte("v"))
		wal.Commit("c", seq, WLOpPut, BucketFingerprints, key, []byte("v"))
	}

	time.Sleep(300 * time.Millisecond)

	store.View(func(tx Tx) error {
		for i := 0; i < 3; i++ {
			key := "bg-" + string(rune('A'+i))
			val, _ := tx.Get(BucketFingerprints, []byte(key))
			if val == nil {
				t.Errorf("bg key %s: not flushed", key)
			}
		}
		return nil
	})

	wal.StopFlusher()
}

// ============================================================
// 边界
// ============================================================

func TestWAL_FlushEmpty(t *testing.T) {
	wal, _ := newTestWAL(t)

	// 无数据时 Flush 应无错误
	if err := wal.Flush(); err != nil {
		t.Fatalf("flush empty: %v", err)
	}
}

func TestWAL_FlushWithoutStore(t *testing.T) {
	wal, _ := newTestWAL(t)

	// 不设 store，写入数据
	for i := 0; i < 3; i++ {
		key := "no-store-" + string(rune('A'+i))
		seq, _ := wal.Begin("c", WLOpPut, BucketFingerprints, key, []byte("v"))
		wal.Commit("c", seq, WLOpPut, BucketFingerprints, key, []byte("v"))
	}

	// Flush 应 no-op（不截断 WAL）
	if err := wal.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}

	// WAL 完整保留
	entries, _, _ := wal.readCommittedSinceCheckpoint()
	if len(entries) != 3 {
		t.Errorf("entries after no-store flush = %d, want 3 (WAL preserved)", len(entries))
	}
}
