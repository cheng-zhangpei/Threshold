package waiter

import (
	"Threshold/pkg/proto/pb"
	"sync"
	"time"
)

// Waiter 异步等待队列
type Waiter struct {
	mu      sync.RWMutex
	pending map[string]chan *ResponseData
	timeout time.Duration
}
type ResponseData struct {
	Status pb.Status
	Reason string
	Body   []byte
	Error  error
}

func NewWaiter(timeout time.Duration) *Waiter {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &Waiter{
		pending: make(map[string]chan *ResponseData),
		timeout: timeout,
	}
}

func (w *Waiter) Register(reqID string) <-chan *ResponseData {
	ch := make(chan *ResponseData, 1)
	w.mu.Lock()
	w.pending[reqID] = ch
	w.mu.Unlock()
	return ch
}

func (w *Waiter) Complete(reqID string, resp *ResponseData) {
	w.mu.RLock()
	ch, ok := w.pending[reqID]
	w.mu.RUnlock()
	if !ok {
		return
	}
	select {
	case ch <- resp:
	default:
	}
}

func (w *Waiter) Unregister(reqID string) {
	w.mu.Lock()
	ch, ok := w.pending[reqID]
	if ok {
		delete(w.pending, reqID)
		close(ch)
	}
	w.mu.Unlock()
}
func (w *Waiter) Timeout() time.Duration {
	return w.timeout
}
