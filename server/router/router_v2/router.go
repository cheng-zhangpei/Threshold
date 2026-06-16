package router_v2

import (
	"fmt"
	"log"
	"sync"

	"Threshold/pkg/types"
	"Threshold/server/output"
)

// Dispatcher 调度接口（与 V1 保持一致）
type Dispatcher interface {
	Enqueue(parsed *types.ParsedRequest, riskLevel types.RiskLevel) *types.Decision
}

// routeRequest 提交给 Router 消费者处理的请求单元
type routeRequest struct {
	parsed   *types.ParsedRequest
	resultCh chan *types.Decision
}

// Router V2 配置驱动路由组件
type Router struct {
	engine    *RuleEngine
	output    *output.OutputBuffer
	dispatch  Dispatcher
	inputCh   chan routeRequest
	done      chan struct{}
	wg        sync.WaitGroup
	queueSize int
	consumers int
}

// NewRouter 创建 Router 实例
func NewRouter(cfg *Config, out *output.OutputBuffer, dispatch Dispatcher, consumers, queueSize int) (*Router, error) {
	if consumers <= 0 {
		consumers = 3
	}
	if queueSize <= 0 {
		queueSize = 4096
	}

	engine := NewRuleEngine(cfg)

	r := &Router{
		engine:    engine,
		output:    out,
		dispatch:  dispatch,
		inputCh:   make(chan routeRequest, queueSize),
		done:      make(chan struct{}),
		queueSize: queueSize,
		consumers: consumers,
	}

	for i := 0; i < consumers; i++ {
		r.wg.Add(1)
		go r.run()
	}

	log.Printf("[RouterV2] started with %d consumers, queue size %d", consumers, queueSize)
	return r, nil
}

// NewRouterFromFile 从配置文件创建 Router
func NewRouterFromFile(configPath string, out *output.OutputBuffer, dispatch Dispatcher, consumers, queueSize int) (*Router, error) {
	cfg, err := LoadConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("load router config: %w", err)
	}
	return NewRouter(cfg, out, dispatch, consumers, queueSize)
}

// Classify 静态分级（同步，用于 L0 快速判断）
func (r *Router) Classify(parsed *types.ParsedRequest) RiskLevel {
	return r.engine.Match(parsed)
}

// RouteAsync 非阻塞提交请求到缓冲队列
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

// run 消费者 goroutine
func (r *Router) run() {
	defer r.wg.Done()
	for {
		select {
		case req, ok := <-r.inputCh:
			if !ok {
				log.Printf("[RouterV2] input channel closed")
				return
			}
			decision := r.process(req.parsed)
			req.resultCh <- decision
		case <-r.done:
			return
		}
	}
}

// process 核心处理：分级 + 分发
func (r *Router) process(parsed *types.ParsedRequest) *types.Decision {
	riskLevel := r.engine.Match(parsed)

	if riskLevel == L0 {
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

// RouteL0 L0 直接穿透（兼容 V1 接口）
func (r *Router) RouteL0(parsed *types.ParsedRequest, decision *types.Decision) {
	r.output.Put(output.Message{
		Request:  parsed,
		Decision: decision,
	})
}

// QueueLen 当前队列深度
func (r *Router) QueueLen() int {
	return len(r.inputCh)
}

// Shutdown 优雅关闭
func (r *Router) Shutdown() {
	close(r.done)
	r.wg.Wait()
	log.Printf("[RouterV2] shutdown complete")
}
