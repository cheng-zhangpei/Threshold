package dispatch

import (
	"Threshold/server/alert"
	"Threshold/server/output"
	"log"
	"sync/atomic"
	"time"

	"Threshold/pkg/types"
)

// Worker 无状态处理单元
// 从 DispatchManager 的队列竞争消费任务
// 执行: 构建上下文 -> 决策引擎 -> 返回结果
// 通过 atomic flag 实现优雅退休，不依赖锁
type Worker struct {
	id         int64
	dm         *DispatchManager
	retired    atomic.Bool
	lastActive time.Time
}

func NewWorker(id int64, dm *DispatchManager) *Worker {
	log.Print("Worker:  started", id)
	return &Worker{
		id:         id,
		dm:         dm,
		lastActive: time.Now(),
	}
}

// Run 主循环，持续从队列消费任务
func (w *Worker) Run() {
	for {
		if w.retired.Load() {
			return
		}

		select {
		case task, ok := <-w.dm.queue:
			if !ok {
				return
			}
			w.lastActive = time.Now()
			w.process(task)
			w.dm.processed.Add(1)

		case <-w.dm.done:
			return
		}
	}
}
func (w *Worker) process(task DispatchTask) {
	// 构建 ConnectionContext（用于决策引擎）
	connCtx := &types.ConnectionContext{
		ConnectionID: task.Parsed.ConnectionID,
		UserID:       task.Parsed.UserID,
		DeviceUUID:   task.Parsed.DeviceUUID,
		ConnectedAt:  task.Parsed.Timestamp,
	}
	connCtx.RecordEvent(task.Parsed.OpKey)

	// 调用决策函数
	history := make([]*types.ConnectionSummary, 0)
	decision := w.dm.decisionFn(connCtx, history, task.Risk)

	// ----- 阻断：只进 AlertQueue，不经过 OutputBuffer -----
	if decision.Action == types.BLOCK ||
		decision.Action == types.BLOCK_DEVICE ||
		decision.Action == types.BLACKLIST_DEVICE {
		w.dm.AlertQueue.Put(alert.AlertEntry{
			Request:  task.Parsed,
			Decision: decision,
		})
		task.ResultCh <- decision
		return
	}

	// ----- 告警但放行：同时进 AlertQueue 和 OutputBuffer -----
	if decision.Action == types.ALERT || decision.Action == types.QUARANTINE_AND_ALERT {
		w.dm.AlertQueue.Put(alert.AlertEntry{
			Request:  task.Parsed,
			Decision: decision,
		})
		// 继续放行到 OutputBuffer（不 return）
	}

	// ----- 放行：放入 OutputBuffer（包含 ALERT 的 fallthrough） -----
	w.dm.OutputBuf.Put(output.Message{
		Request:   task.Parsed,
		Decision:  decision,
		RequestID: task.RequestID, // 必须传递 RequestID，否则 Sender 无法回传响应
	})

	// 将决策结果返回给调用者（ProxyStream）
	task.ResultCh <- decision
}

// TryRetire 标记 Worker 为退休状态
func (w *Worker) TryRetire() bool {
	return w.retired.CompareAndSwap(false, true)
}

func (w *Worker) LastActive() time.Time {
	return w.lastActive
}
