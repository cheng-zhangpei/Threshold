package router_v1

import (
	"fmt"
	"log"
	"sync"

	"Threshold/pkg/types"
	"Threshold/server/output"
)

// Dispatcher 调度接口
// Router 将 L1+ 的请求委托给 Dispatcher 入队处理
type Dispatcher interface {
	Enqueue(parsed *types.ParsedRequest, riskLevel types.RiskLevel) *types.Decision
}

// routeRequest 提交给 Router 消费者处理的请求单元
type routeRequest struct {
	parsed   *types.ParsedRequest
	resultCh chan *types.Decision
}

// Router 事件消费型核心路由组件
// Handler 将请求非阻塞提交到缓冲队列，多个消费者 goroutine 并发消费
// L0 直接穿透到 OutputBuffer，L1+ 委托给 Dispatcher 入队
// Go channel 原生保证每条消息只会被一个消费者处理，无需额外加锁
type Router struct {
	riskTable *OperationRiskTable
	output    *output.OutputBuffer
	dispatch  Dispatcher

	inputCh chan routeRequest
	done    chan struct{}
	wg      sync.WaitGroup
}

func NewRouter(riskTable *OperationRiskTable, out *output.OutputBuffer, dispatch Dispatcher, consumers int, queueSize int) *Router {
	if consumers <= 0 {
		consumers = 3
	}
	if queueSize <= 0 {
		queueSize = 4096
	}
	r := &Router{
		riskTable: riskTable,
		output:    out,
		dispatch:  dispatch,
		inputCh:   make(chan routeRequest, queueSize),
		done:      make(chan struct{}),
	}
	for i := 0; i < consumers; i++ {
		r.wg.Add(1)
		go r.run()
	}
	return r
}

// Classify 根据请求的操作标识判定静态风险等级
func (r *Router) Classify(parsed *types.ParsedRequest) types.RiskLevel {
	return r.riskTable.Lookup(parsed.Method, parsed.Path)
}

// RouteAsync 非阻塞提交请求到缓冲队列
// 返回 decisionCh，调用者阻塞等待即可拿到决策结果
// 队列满时返回错误（背压），调用方可据此返回 THROTTLE
func (r *Router) RouteAsync(parsed *types.ParsedRequest) (*types.Decision, error) {
	resultCh := make(chan *types.Decision, 1)
	req := routeRequest{parsed: parsed, resultCh: resultCh}

	select {
	case r.inputCh <- req:
	case <-r.done:
		return nil, fmt.Errorf("router is shutting down")
	default:
		return nil, fmt.Errorf("router input queue full, throttle")
	}

	select {
	case decision := <-resultCh:
		return decision, nil
	case <-r.done:
		return nil, fmt.Errorf("router is shutting down")
	}
}

// run 消费者 goroutine，从 inputCh 并发消费请求
// Go channel 保证每条消息只被一个 goroutine 读到
func (r *Router) run() {
	defer r.wg.Done()
	for {
		select {
		case req, ok := <-r.inputCh:
			if !ok {
				log.Printf("router input channel closed")
				return
			}
			decision := r.process(req.parsed)
			req.resultCh <- decision
		case <-r.done:
			return
		}
	}
}

// process 核心处理逻辑：Classify + 分发
func (r *Router) process(parsed *types.ParsedRequest) *types.Decision {
	riskLevel := r.Classify(parsed)

	if riskLevel == types.L0 {
		decision := &types.Decision{
			Action: types.ALLOW,
			Reason: "L0 direct pass",
			RuleID: "L0",
		}
		r.output.Put(output.Message{
			Request:  parsed,
			Decision: decision,
		})
		return decision
	}
	if r.dispatch == nil {
		// 降级模式：dispatch 不可用时，直接放行到 OutputBuffer
		log.Printf("[Router] dispatch unavailable, fallback to direct pass for %s", parsed.OpKey)
		decision := &types.Decision{
			Action: types.ALLOW,
			Reason: "dispatch disabled, fallback to direct pass",
			RuleID: "DISPATCH_FALLBACK",
		}
		r.output.Put(output.Message{
			Request:  parsed,
			Decision: decision,
		})
		return decision
	}
	return r.dispatch.Enqueue(parsed, riskLevel)
}

// RouteL0 L0 操作直接穿透到 OutputBuffer
func (r *Router) RouteL0(parsed *types.ParsedRequest, decision *types.Decision) {
	r.output.Put(output.Message{
		Request:  parsed,
		Decision: decision,
	})
}

// QueueLen 当前缓冲队列深度
func (r *Router) QueueLen() int {
	return len(r.inputCh)
}

// Shutdown 优雅关闭：通知所有消费者退出，等待处理完剩余请求
func (r *Router) Shutdown() {
	close(r.done)
	r.wg.Wait()
}
