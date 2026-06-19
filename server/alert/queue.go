package alert

import (
	"sync"

	"Threshold/pkg/types"
)

// AlertEntry 告警队列中的条目
type AlertEntry struct {
	Request  *types.ParsedRequest
	Decision *types.Decision
}

// AlertSubscriber 告警订阅者
type AlertSubscriber struct {
	Ch chan AlertEntry
	ID string
}

// AlertQueue 阻断/告警消息队列
// BLOCK/ALERT/BLACKLIST_DEVICE 结果投递到此
// 后续对接设备拉黑 + gRPC Alert 通知
type AlertQueue struct {
	mu          sync.Mutex
	entries     []AlertEntry
	subscribers map[string]*AlertSubscriber
}

func NewAlertQueue() *AlertQueue {
	return &AlertQueue{
		entries:     make([]AlertEntry, 0),
		subscribers: make(map[string]*AlertSubscriber),
	}
}

func (q *AlertQueue) Put(entry AlertEntry) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.entries = append(q.entries, entry)
	q.notifySubscribers(entry)
}

func (q *AlertQueue) Drain() []AlertEntry {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := q.entries
	q.entries = make([]AlertEntry, 0)
	return out
}

func (q *AlertQueue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.entries)
}

// Subscribe 注册告警订阅者
func (q *AlertQueue) Subscribe(id string) <-chan AlertEntry {
	q.mu.Lock()
	defer q.mu.Unlock()
	ch := make(chan AlertEntry, 100)
	q.subscribers[id] = &AlertSubscriber{Ch: ch, ID: id}
	return ch
}

// Unsubscribe 取消告警订阅
// 只从 map 中移除，不关闭 channel（避免读取已关闭 channel 返回零值）
func (q *AlertQueue) Unsubscribe(id string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	delete(q.subscribers, id)
}

func (q *AlertQueue) notifySubscribers(entry AlertEntry) {
	for _, sub := range q.subscribers {
		select {
		case sub.Ch <- entry:
		default:
		}
	}
}

func (q *AlertQueue) PutSimple(deviceUUID string, reason string) {
	entry := AlertEntry{
		Request: &types.ParsedRequest{
			Method: "CONNECT",
			Path:   deviceUUID, // 用 Path 字段暂存设备标识，方便排查
		},
		Decision: &types.Decision{
			Action: types.BLOCK,
			Reason: reason,
			RuleID: "MODE3_FP",
		},
	}
	q.Put(entry)
}
