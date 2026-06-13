package grpc

import (
	"context"
	"fmt"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"Threshold/pkg/types"
	"Threshold/server/alert"
	"Threshold/server/decision"
	"Threshold/server/fingerprint"
	"Threshold/server/output"
	"Threshold/server/router"

	pb "Threshold/pkg/proto/pb"
)

type Handler struct {
	pb.UnimplementedSecurityProxyServer

	mu          sync.RWMutex
	connections map[string]*types.ConnectionContext

	fpTree     *fingerprint.Tree
	engine     *decision.Engine
	router     *router.Router
	outputBuf  *output.OutputBuffer
	alertQueue *alert.AlertQueue

	notifySubs sync.Map
}

func NewHandler(
	fpTree *fingerprint.Tree,
	engine *decision.Engine,
	router *router.Router,
	outputBuf *output.OutputBuffer,
	alertQueue *alert.AlertQueue,
) *Handler {
	return &Handler{
		connections: make(map[string]*types.ConnectionContext),
		fpTree:      fpTree,
		engine:      engine,
		router:      router,
		outputBuf:   outputBuf,
		alertQueue:  alertQueue,
	}
}

// ============================================================
// EstablishConnection 连接初始化
// ============================================================

func (h *Handler) EstablishConnection(ctx context.Context, req *pb.ConnectionInit) (*pb.ConnectionAck, error) {
	if req.UserId == "" || req.DeviceUuid == "" {
		return &pb.ConnectionAck{Accepted: false, Reason: "missing user_id or device_uuid"}, nil
	}

	connIP := req.Ip
	fp := types.DeviceFingerprint{OS: &req.OsType, IP: &connIP, UUID: &req.DeviceUuid}
	if !h.fpTree.Match(fp) {
		return &pb.ConnectionAck{Accepted: false, Reason: "device not registered"}, nil
	}

	connID := fmt.Sprintf("conn-%s-%d", req.DeviceUuid[:8], time.Now().UnixMilli())
	connCtx := &types.ConnectionContext{
		ConnectionID: connID, UserID: req.UserId, DeviceUUID: req.DeviceUuid,
		ConnectedAt: time.UnixMilli(req.Timestamp), IP: req.Ip,
	}

	h.mu.Lock()
	h.connections[connID] = connCtx
	h.mu.Unlock()

	return &pb.ConnectionAck{ConnectionId: connID, Accepted: true}, nil
}

// ============================================================
// ProxyStream 请求代理流
// 流水线: Parse -> Fingerprint -> Router(Classify) -> Decision -> Response
// ============================================================

func (h *Handler) ProxyStream(stream pb.SecurityProxy_ProxyStreamServer) error {
	for {
		req, err := stream.Recv()
		if err != nil {
			return err
		}

		parsed, err := types.ParseProxyRequest(req.ConnectionId, req.DeviceUuid, req.UserId, req.Timestamp, req.RawHttpRequest)
		if err != nil {
			return status.Errorf(codes.InvalidArgument, "parse request: %v", err)
		}

		// Step 1: 指纹校验
		if !h.fpTree.Match(parsed.Fingerprint) {
			stream.Send(&pb.ProxyResponse{ConnectionId: parsed.ConnectionID, Status: pb.Status_BLOCKED, Reason: "fingerprint mismatch"})
			continue
		}

		// Step 2: 记录事件到 ConnectionContext
		h.mu.RLock()
		connCtx := h.connections[parsed.ConnectionID]
		h.mu.RUnlock()
		if connCtx != nil {
			connCtx.RecordEvent(parsed.OpKey)
		}

		// Step 3: Router 分级路由
		// L0 直接穿透到 OutputBuffer，L1+ 由 DispatchManager 处理
		// 当前 DispatchManager 尚未实现，L1+ 暂时直接走决策引擎
		riskLevel := h.router.Classify(parsed)

		var decisionResult *types.Decision
		if riskLevel == types.L0 {
			decisionResult = &types.Decision{
				Action: types.ALLOW,
				Reason: "L0 direct pass",
				RuleID: "L0",
			}
			h.outputBuf.Put(output.Message{Request: parsed, Decision: decisionResult})
		} else {
			history := make([]*types.ConnectionSummary, 0)
			decisionResult = h.engine.Evaluate(connCtx, history, riskLevel)

			// 根据决策结果分发到 OutputBuffer 或 AlertQueue
			switch decisionResult.Action {
			case types.BLOCK, types.BLOCK_DEVICE, types.BLACKLIST_DEVICE, types.ALERT, types.QUARANTINE_AND_ALERT:
				h.alertQueue.Put(alert.AlertEntry{Request: parsed, Decision: decisionResult})
			default:
				h.outputBuf.Put(output.Message{Request: parsed, Decision: decisionResult})
			}
		}

		// Step 4: 映射决策到 gRPC 响应状态 TODO 更多的响应决策
		respStatus := pb.Status_OK
		reason := decisionResult.Reason
		switch decisionResult.Action {
		case types.BLOCK, types.BLOCK_DEVICE, types.BLACKLIST_DEVICE:
			respStatus = pb.Status_BLOCKED
		case types.REQUIRE_2FA, types.BLOCK_LOGIN:
			respStatus = pb.Status_RATE_LIMITED
		}

		stream.Send(&pb.ProxyResponse{ConnectionId: parsed.ConnectionID, Status: respStatus, Reason: reason})
	}
}

// ============================================================
// CloseConnection 连接关闭
// ============================================================

func (h *Handler) CloseConnection(ctx context.Context, req *pb.ConnectionClose) (*pb.CloseAck, error) {
	h.mu.Lock()
	_, exists := h.connections[req.ConnectionId]
	if exists {
		delete(h.connections, req.ConnectionId)
	}
	h.mu.Unlock()

	if !exists {
		return &pb.CloseAck{Success: false}, nil
	}
	return &pb.CloseAck{Success: true}, nil
}

// ============================================================
// PullApproved 下游拉取已通过校验的消息
// 双向流: 客户端发送 PullRequest 指定 batch_size
// 服务端从 OutputBuffer 批量拉取并返回 ApprovedMessage
// ============================================================

func (h *Handler) PullApproved(stream pb.SecurityProxy_PullApprovedServer) error {
	for {
		req, err := stream.Recv()
		if err != nil {
			return err
		}

		batchSize := int(req.BatchSize)
		if batchSize <= 0 {
			batchSize = 100
		}

		// 从 OutputBuffer 拉取全部消息，取前 batchSize 条
		allMsgs := h.outputBuf.Pull()
		count := batchSize
		if count > len(allMsgs) {
			count = len(allMsgs)
		}

		for i := 0; i < count; i++ {
			msg := allMsgs[i]
			approved := &pb.ApprovedMessage{
				MessageId:      fmt.Sprintf("%s-%d", msg.Request.ConnectionID, i),
				ConnectionId:   msg.Request.ConnectionID,
				RawHttpRequest: msg.Request.Body,
				DecisionAction: msg.Decision.Action.String(),
				DecisionReason: msg.Decision.Reason,
				Timestamp:      time.Now().UnixMilli(),
			}
			if err := stream.Send(approved); err != nil {
				return err
			}
		}

		// 如果有剩余消息，放回 OutputBuffer
		if count < len(allMsgs) {
			for i := count; i < len(allMsgs); i++ {
				h.outputBuf.Put(allMsgs[i])
			}
		}
	}
}

// ============================================================
// SubscribeNotify 下游订阅告警通知
// 服务端单向流: 订阅 AlertQueue，实时推送 NotifyEvent
// ============================================================

func (h *Handler) SubscribeNotify(req *pb.NotifyRequest, stream pb.SecurityProxy_SubscribeNotifyServer) error {
	if req.SubscriberId == "" {
		return status.Errorf(codes.InvalidArgument, "missing subscriber_id")
	}

	// 注册到 AlertQueue 订阅者
	ch := h.alertQueue.Subscribe(req.SubscriberId)
	defer h.alertQueue.Unsubscribe(req.SubscriberId)

	for {
		select {
		case entry, ok := <-ch:
			if !ok {
				return nil
			}
			event := &pb.NotifyEvent{
				EventId:      fmt.Sprintf("alert-%d", time.Now().UnixNano()),
				EventType:    pb.EventType_ALERT_TRIGGERED,
				UserId:       entry.Request.UserID,
				ConnectionId: entry.Request.ConnectionID,
				DeviceUuid:   entry.Request.DeviceUUID,
				Message:      entry.Decision.Reason,
				Timestamp:    time.Now().UnixMilli(),
			}
			if err := stream.Send(event); err != nil {
				return err
			}

		case <-stream.Context().Done():
			return stream.Context().Err()
		}
	}
}

// ============================================================
// BroadcastNotify 向所有订阅者广播通知事件
// ============================================================

func (h *Handler) BroadcastNotify(event *pb.NotifyEvent) {
	h.notifySubs.Range(func(key, value interface{}) bool {
		ch := value.(chan *pb.NotifyEvent)
		select {
		case ch <- event:
		default:
		}
		return true
	})
}
