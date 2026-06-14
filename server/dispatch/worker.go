package dispatch

import (
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

// process 单条任务处理流水线
func (w *Worker) process(task DispatchTask) {
	connCtx := &types.ConnectionContext{
		ConnectionID: task.Parsed.ConnectionID,
		UserID:       task.Parsed.UserID,
		DeviceUUID:   task.Parsed.DeviceUUID,
		ConnectedAt:  task.Parsed.Timestamp,
	}
	connCtx.RecordEvent(task.Parsed.OpKey)

	history := make([]*types.ConnectionSummary, 0)
	decision := w.dm.decisionFn(connCtx, history, task.Risk)

	task.ResultCh <- decision
}

// TryRetire 标记 Worker 为退休状态
func (w *Worker) TryRetire() bool {
	return w.retired.CompareAndSwap(false, true)
}

func (w *Worker) LastActive() time.Time {
	return w.lastActive
}
