package output

import (
	"Threshold/pkg/types"
	"Threshold/pkg/waiter"
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"Threshold/pkg/proto/pb"
)

// ============================================================
// Message
// ============================================================

type Message struct {
	Request   *types.ParsedRequest
	Decision  *types.Decision
	RequestID string
}

// ============================================================
// OutputBuffer (多级队列 + 内部消费者)
// ============================================================

const (
	defaultMaxSize   = 10000
	defaultQueueSize = 1024
	defaultWorkers   = 4
)

type OutputBuffer struct {
	// Pull 队列（供 OpenStack 拉取）
	pullMu    sync.Mutex
	pullQueue []Message
	maxSize   int

	// Sender 内部队列（多级队列，每个 Worker 独占一个 channel）
	senderQueues []chan Message
	queueLen     []int32
	workerCount  int
	queueCap     int

	stopCh chan struct{}
	wg     sync.WaitGroup

	httpClient    *http.Client
	senderEnabled bool
	waiter        *waiter.Waiter
}

func NewOutputBuffer() *OutputBuffer {
	return NewOutputBufferWithConfig(defaultMaxSize, defaultWorkers, defaultQueueSize, true, nil)
}

func NewOutputBufferWithConfig(maxSize, workerCount, queueCap int, enableSender bool, w *waiter.Waiter) *OutputBuffer {
	if workerCount <= 0 {
		workerCount = defaultWorkers
	}
	if queueCap <= 0 {
		queueCap = defaultQueueSize
	}
	b := &OutputBuffer{
		pullQueue:     make([]Message, 0, maxSize),
		maxSize:       maxSize,
		senderQueues:  make([]chan Message, workerCount),
		queueLen:      make([]int32, workerCount),
		workerCount:   workerCount,
		queueCap:      queueCap,
		stopCh:        make(chan struct{}),
		senderEnabled: enableSender,
		waiter:        w,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
	for i := 0; i < workerCount; i++ {
		b.senderQueues[i] = make(chan Message, queueCap)
	}
	if enableSender {
		b.startWorkers()
	}
	return b
}

func (b *OutputBuffer) startWorkers() {
	for i := 0; i < b.workerCount; i++ {
		b.wg.Add(1)
		go b.worker(i)
	}
	log.Printf("[OutputBuffer] started %d sender workers", b.workerCount)
}

func (b *OutputBuffer) worker(id int) {
	defer b.wg.Done()
	for {
		select {
		case msg := <-b.senderQueues[id]:
			atomic.AddInt32(&b.queueLen[id], -1)
			b.process(msg)
		case <-b.stopCh:
			return
		}
	}
}
func (b *OutputBuffer) process(msg Message) {
	target := msg.Request.TargetAddr
	if target == "" {
		log.Printf("[OutputBuffer] no target address for %s, skip", msg.Request.OpKey)
		// 返回错误响应，避免 ProxyStream 超时
		if b.waiter != nil && msg.RequestID != "" {
			b.waiter.Complete(msg.RequestID, &waiter.ResponseData{
				Status: pb.Status_BLOCKED,
				Reason: "no target address",
				Error:  fmt.Errorf("no target address"),
			})
		}
		return
	}

	var respData *waiter.ResponseData
	if msg.Request.Method != "TCP" && msg.Request.Method != "" {
		respData = b.sendHTTP(msg, target)
	} else {
		respData = b.sendTCP(msg, target)
	}

	// 通过 Waiter 返回响应
	if b.waiter != nil && msg.RequestID != "" {
		b.waiter.Complete(msg.RequestID, respData)
	}
}
func (b *OutputBuffer) sendHTTP(msg Message, target string) *waiter.ResponseData {
	url := "http://" + target + msg.Request.Path
	req, err := http.NewRequest(msg.Request.Method, url, bytes.NewReader(msg.Request.Body))
	if err != nil {
		return &waiter.ResponseData{
			Status: pb.Status_BLOCKED,
			Reason: err.Error(),
			Error:  err,
		}
	}
	for k, v := range msg.Request.Headers {
		if k == "Connection" || k == "Keep-Alive" || k == "Proxy-Connection" {
			continue
		}
		req.Header.Set(k, v)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req = req.WithContext(ctx)

	resp, err := b.httpClient.Do(req)
	if err != nil {
		return &waiter.ResponseData{
			Status: pb.Status_BLOCKED,
			Reason: err.Error(),
			Error:  err,
		}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return &waiter.ResponseData{
			Status: pb.Status_BLOCKED,
			Reason: err.Error(),
			Error:  err,
		}
	}
	log.Printf("[OutputBuffer] HTTP sent to %s, status: %s, body len: %d", target, resp.Status, len(body))
	return &waiter.ResponseData{
		Status: pb.Status_OK,
		Reason: "OK",
		Body:   body,
	}
}

func (b *OutputBuffer) sendTCP(msg Message, target string) *waiter.ResponseData {
	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return &waiter.ResponseData{
			Status: pb.Status_BLOCKED,
			Reason: err.Error(),
			Error:  err,
		}
	}
	defer conn.Close()

	if len(msg.Request.Body) > 0 {
		_, err = conn.Write(msg.Request.Body)
		if err != nil {
			return &waiter.ResponseData{
				Status: pb.Status_BLOCKED,
				Reason: err.Error(),
				Error:  err,
			}
		}
	}

	// 读取 TCP 响应（简单读取一次，后续可改进为持续读取）
	buf := make([]byte, 65536)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		return &waiter.ResponseData{
			Status: pb.Status_BLOCKED,
			Reason: err.Error(),
			Error:  err,
		}
	}
	log.Printf("[OutputBuffer] TCP sent to %s, sent=%d, recv=%d", target, len(msg.Request.Body), n)
	return &waiter.ResponseData{
		Status: pb.Status_OK,
		Reason: "OK",
		Body:   buf[:n],
	}
}

// ============================================================
// 对外接口
// ============================================================

func (b *OutputBuffer) Put(msg Message) {
	b.pullMu.Lock()
	if len(b.pullQueue) >= b.maxSize {
		b.pullQueue = b.pullQueue[1:]
	}
	b.pullQueue = append(b.pullQueue, msg)
	b.pullMu.Unlock()

	if b.senderEnabled {
		minIdx := 0
		minLen := int32(1<<31 - 1)
		for i := 0; i < b.workerCount; i++ {
			l := atomic.LoadInt32(&b.queueLen[i])
			if l < minLen {
				minLen = l
				minIdx = i
			}
		}
		atomic.AddInt32(&b.queueLen[minIdx], 1)
		b.senderQueues[minIdx] <- msg
	}
}

func (b *OutputBuffer) Pull() []Message {
	b.pullMu.Lock()
	defer b.pullMu.Unlock()
	out := b.pullQueue
	b.pullQueue = make([]Message, 0, b.maxSize)
	return out
}

func (b *OutputBuffer) Len() int {
	b.pullMu.Lock()
	defer b.pullMu.Unlock()
	return len(b.pullQueue)
}

func (b *OutputBuffer) SenderLen() int {
	var total int32
	for i := 0; i < b.workerCount; i++ {
		total += atomic.LoadInt32(&b.queueLen[i])
	}
	return int(total)
}

func (b *OutputBuffer) Stop() {
	if b.senderEnabled {
		close(b.stopCh)
		b.wg.Wait()
		log.Printf("[OutputBuffer] all sender workers stopped")
	}
}
