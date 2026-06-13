package output

import (
	"sync"

	"Threshold/pkg/types"
)

// Message 通过校验后暂存的消息单元
// 下游通过 PullApproved 接口拉取
type Message struct {
	Request  *types.ParsedRequest
	Decision *types.Decision
}

const defaultMaxSize = 10000

// OutputBuffer 通过校验的消息暂存队列
// L0 直接入队，L1-L3 Worker 处理后投递
// 下游通过 PullApproved 拉取
type OutputBuffer struct {
	mu          sync.Mutex
	messages    []Message
	maxSize     int
	subscribers []chan struct{}
}

func NewOutputBuffer() *OutputBuffer {
	return &OutputBuffer{
		messages: make([]Message, 0),
		maxSize:  defaultMaxSize,
	}
}

func NewOutputBufferWithMaxSize(maxSize int) *OutputBuffer {
	return &OutputBuffer{
		messages: make([]Message, 0),
		maxSize:  maxSize,
	}
}

func (b *OutputBuffer) Put(msg Message) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.messages) >= b.maxSize {
		b.messages = b.messages[1:]
	}
	b.messages = append(b.messages, msg)
	b.notifySubscribers()
}

func (b *OutputBuffer) Pull() []Message {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := b.messages
	b.messages = make([]Message, 0)
	return out
}

func (b *OutputBuffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.messages)
}

// Subscribe 注册一个订阅者 channel，当有新消息时收到通知
func (b *OutputBuffer) Subscribe() <-chan struct{} {
	ch := make(chan struct{}, 1)
	b.mu.Lock()
	b.subscribers = append(b.subscribers, ch)
	b.mu.Unlock()
	return ch
}

// Unsubscribe 取消订阅
func (b *OutputBuffer) Unsubscribe(ch <-chan struct{}) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for i, sub := range b.subscribers {
		if sub == ch {
			b.subscribers = append(b.subscribers[:i], b.subscribers[i+1:]...)
			close(sub)
			break
		}
	}
}

func (b *OutputBuffer) notifySubscribers() {
	for _, ch := range b.subscribers {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}
