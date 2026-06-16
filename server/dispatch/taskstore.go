package dispatch

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"Threshold/pkg/storage"
	"Threshold/pkg/types"
)

// storedTask 溢出到 bbolt 的序列化格式
type storedTask struct {
	ConnectionID string `json:"connection_id"`
	DeviceUUID   string `json:"device_uuid"`
	UserID       string `json:"user_id"`
	Timestamp    int64  `json:"timestamp"`
	Method       string `json:"method"`
	Path         string `json:"path"`
	OpKey        string `json:"op_key"`
	RiskLevel    int    `json:"risk_level"`
	OverflowKey  string `json:"overflow_key"`
}

// OverflowTask 待溢出的任务输入
type OverflowTask struct {
	Parsed      *types.ParsedRequest
	Risk        types.RiskLevel
	OverflowKey string // 用于匹配 pending map 中的 resultCh
}

// ReloadedTask 从 bbolt 回捞的任务
type ReloadedTask struct {
	Parsed      *types.ParsedRequest
	Risk        types.RiskLevel
	Key         []byte
	OverflowKey string
}

// TaskStore 封装 DispatchManager 的溢出持久化层
type TaskStore struct {
	store storage.Store
	seq   atomic.Uint64
	mu    sync.Mutex
}

func NewTaskStore(store storage.Store) *TaskStore {
	return &TaskStore{store: store}
}

// Overflow 将任务持久化到 bbolt
type OverflowResult struct{}

func (ts *TaskStore) Overflow(task OverflowTask) (*OverflowResult, error) {
	if ts.store == nil {
		return nil, fmt.Errorf("no storage configured")
	}

	st := storedTask{
		ConnectionID: task.Parsed.ConnectionID,
		DeviceUUID:   task.Parsed.DeviceUUID,
		UserID:       task.Parsed.UserID,
		Timestamp:    task.Parsed.Timestamp.UnixMilli(),
		Method:       task.Parsed.Method,
		Path:         task.Parsed.Path,
		OpKey:        task.Parsed.OpKey,
		RiskLevel:    int(task.Risk),
		OverflowKey:  task.OverflowKey,
	}

	data, err := json.Marshal(st)
	if err != nil {
		return nil, fmt.Errorf("marshal task: %w", err)
	}

	seq := ts.seq.Add(1)
	key := make([]byte, 8)
	binary.BigEndian.PutUint64(key, seq)

	err = ts.store.Update(func(tx storage.Tx) error {
		return tx.Put(storage.BucketDispatchTasks, key, data)
	})

	if err != nil {
		return nil, fmt.Errorf("overflow write: %w", err)
	}
	return &OverflowResult{}, nil
}

// Reload 从 bbolt 批量读取溢出任务（只读，不删除）
type ReloadResult struct {
	Tasks []ReloadedTask
}

func (ts *TaskStore) Reload(batch int) (*ReloadResult, error) {
	if ts.store == nil {
		return &ReloadResult{}, nil
	}

	ts.mu.Lock()
	defer ts.mu.Unlock()

	var result ReloadResult

	err := ts.store.View(func(tx storage.Tx) error {
		log.Printf("dispatch: reloading from storage")
		keys, values, err := tx.PrefixScan(storage.BucketDispatchTasks, nil)
		if err != nil {
			return err
		}

		if len(keys) > batch {
			keys = keys[:batch]
			values = values[:batch]
		}

		result.Tasks = make([]ReloadedTask, 0, len(keys))
		for i, val := range values {
			var st storedTask
			if err := json.Unmarshal(val, &st); err != nil {
				continue
			}

			parsed := &types.ParsedRequest{
				ConnectionID: st.ConnectionID,
				DeviceUUID:   st.DeviceUUID,
				UserID:       st.UserID,
				Timestamp:    time.UnixMilli(st.Timestamp),
				Method:       st.Method,
				Path:         st.Path,
				OpKey:        st.OpKey,
			}

			result.Tasks = append(result.Tasks, ReloadedTask{
				Parsed:      parsed,
				Risk:        types.RiskLevel(st.RiskLevel),
				Key:         keys[i],
				OverflowKey: st.OverflowKey,
			})
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("reload: %w", err)
	}
	return &result, nil
}

// Cleanup 删除已成功回捞的溢出任务
type CleanupResult struct {
	Deleted int
}

func (ts *TaskStore) Cleanup(keys [][]byte) (*CleanupResult, error) {
	if ts.store == nil || len(keys) == 0 {
		return &CleanupResult{}, nil
	}

	ts.mu.Lock()
	defer ts.mu.Unlock()

	var deleted int
	err := ts.store.Update(func(tx storage.Tx) error {
		for _, key := range keys {
			if err := tx.Delete(storage.BucketDispatchTasks, key); err != nil {
				continue
			}
			deleted++
		}
		return nil
	})

	return &CleanupResult{Deleted: deleted}, err
}

// PendingCount 返回 bbolt 中待回捞的任务数量
type PendingResult struct {
	Count int
}

func (ts *TaskStore) PendingCount() (*PendingResult, error) {
	if ts.store == nil {
		return &PendingResult{}, nil
	}

	var count int
	err := ts.store.View(func(tx storage.Tx) error {
		keys, _, err := tx.PrefixScan(storage.BucketDispatchTasks, nil)
		if err != nil {
			return err
		}
		count = len(keys)
		return nil
	})

	return &PendingResult{Count: count}, err
}
