package grpc

import (
	"Threshold/pkg/waiter"
	router_v1 "Threshold/server/router/router_v1"
	"Threshold/server/router/router_v2"
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"Threshold/pkg/types"
	"Threshold/server/alert"
	"Threshold/server/decision"
	"Threshold/server/fingerprint"
	"Threshold/server/output"
	"Threshold/server/portrait"

	pb "Threshold/pkg/proto/pb"
)

type Handler struct {
	pb.UnimplementedSecurityProxyServer

	mu          sync.RWMutex
	connections map[string]*types.ConnectionContext

	fpTree     *fingerprint.Tree
	engine     *decision.Engine
	r          *router_v1.Router
	r2         *router_v2.Router
	outputBuf  *output.OutputBuffer
	alertQueue *alert.AlertQueue
	portrait   *portrait.Store
	waiter     *waiter.Waiter
	notifySubs sync.Map
}

func NewHandler(
	fpTree *fingerprint.Tree,
	engine *decision.Engine,
	r *router_v1.Router,
	r2 *router_v2.Router,
	outputBuf *output.OutputBuffer,
	alertQueue *alert.AlertQueue,
	portraitStore *portrait.Store,
	w *waiter.Waiter,
) *Handler {
	//NewWaiter()
	return &Handler{
		connections: make(map[string]*types.ConnectionContext),
		fpTree:      fpTree,
		engine:      engine,
		r:           r,
		r2:          r2,
		outputBuf:   outputBuf,
		alertQueue:  alertQueue,
		portrait:    portraitStore,
		waiter:      w,
	}
}

// ============================================================
// EstablishConnection
// ============================================================
func (h *Handler) EstablishConnection(ctx context.Context, req *pb.ConnectionInit) (*pb.ConnectionAck, error) {
	//log.Printf("EstablishConnection called")
	if req.UserId == "" || req.DeviceUuid == "" {
		return &pb.ConnectionAck{Accepted: false, Reason: "missing user_id or device_uuid"}, nil
	}
	protocol := req.Protocol
	if protocol == "" {
		protocol = "http"
	}
	connIP := req.Ip
	fp := types.DeviceFingerprint{OS: &req.OsType, IP: &connIP, UUID: &req.DeviceUuid}
	if !h.fpTree.Match(fp) {
		log.Println("[Blocked] device not registered!")
		return &pb.ConnectionAck{Accepted: false, Reason: "device not registered"}, nil
	}

	connID := fmt.Sprintf("conn-%s-%d", req.DeviceUuid[:8], time.Now().UnixMilli())
	connCtx := &types.ConnectionContext{
		ConnectionID: connID, UserID: req.UserId, DeviceUUID: req.DeviceUuid,
		ConnectedAt: time.UnixMilli(req.Timestamp), IP: req.Ip, Protocol: protocol, TargetAddr: req.TargetAddr,
	}
	log.Printf("[ESTABLISH] targetAddr:%s", req.TargetAddr)
	h.mu.Lock()
	h.connections[connID] = connCtx
	h.mu.Unlock()

	return &pb.ConnectionAck{ConnectionId: connID, Accepted: true}, nil
}

// ============================================================
// ProxyStream
// ============================================================
func (h *Handler) ProxyStream(stream pb.SecurityProxy_ProxyStreamServer) error {
	for {
		req, err := stream.Recv()
		if err != nil {
			return err
		}

		// 获取连接上下文
		h.mu.RLock()
		connCtx, exists := h.connections[req.ConnectionId]
		h.mu.RUnlock()
		if !exists {
			stream.Send(&pb.ProxyResponse{
				ConnectionId: req.ConnectionId,
				Status:       pb.Status_BLOCKED,
				Reason:       "unknown connection",
			})
			continue
		}

		// ----- 1. 解析请求 -----
		var parsed *types.ParsedRequest
		if connCtx.Protocol == "http" {
			parsed, err = types.ParseProxyRequest(req.ConnectionId, req.DeviceUuid, req.UserId, req.Timestamp, req.RawHttpRequest)
			if err != nil {
				log.Printf("parse HTTP request: %v", err)
				stream.Send(&pb.ProxyResponse{
					ConnectionId: req.ConnectionId,
					Status:       pb.Status_BLOCKED,
					Reason:       "parse error",
				})
				continue
			}
		} else {
			parsed = &types.ParsedRequest{
				ConnectionID: req.ConnectionId,
				DeviceUUID:   req.DeviceUuid,
				UserID:       req.UserId,
				Timestamp:    time.UnixMilli(req.Timestamp),
				Method:       "TCP",
				Path:         connCtx.TargetAddr,
				OpKey:        "TCP " + connCtx.TargetAddr,
				Body:         req.RawHttpRequest,
				Headers:      make(map[string]string),
				TargetAddr:   connCtx.TargetAddr,
			}
		}

		// 记录事件
		if connCtx != nil {
			connCtx.RecordEvent(parsed.OpKey)
		}

		// ----- 2. 路由 -----
		var riskLevel types.RiskLevel
		if connCtx.Protocol == "http" {
			if h.r == nil {
				log.Println("[Server] router_v1 not enabled")
				continue
			}
			riskLevel = h.r.Classify(parsed)
		} else {
			if h.r2 == nil {
				log.Println("[Server] router_v2 not enabled")
				continue
			}
			riskLevel = h.r2.Classify(parsed)
		}

		// ----- 3. 决策 -----
		var decisionResult *types.Decision
		if riskLevel == types.L0 {
			decisionResult = &types.Decision{
				Action: types.ALLOW,
				Reason: "L0 direct pass",
				RuleID: "L0",
			}
		} else {
			var history []*types.ConnectionSummary
			if h.portrait != nil {
				history = h.portrait.GetHistory(parsed.UserID, 20)
			}
			if h.engine != nil {
				decisionResult = h.engine.Evaluate(connCtx, history, riskLevel)
			} else {
				// 降级：如果 engine 未启用，直接放行
				decisionResult = &types.Decision{
					Action: types.ALLOW,
					Reason: "engine disabled, fallback",
					RuleID: "FALLBACK",
				}
			}
		}

		// ----- 4. 阻断处理 -----
		if decisionResult.Action == types.BLOCK ||
			decisionResult.Action == types.BLOCK_DEVICE ||
			decisionResult.Action == types.BLACKLIST_DEVICE {
			h.alertQueue.Put(alert.AlertEntry{Request: parsed, Decision: decisionResult})
			stream.Send(&pb.ProxyResponse{
				ConnectionId: parsed.ConnectionID,
				Status:       pb.Status_BLOCKED,
				Reason:       decisionResult.Reason,
			})
			continue
		}

		// 对于 ALERT/THROTTLE 等，仍然放行，但记录告警
		if decisionResult.Action == types.ALERT || decisionResult.Action == types.THROTTLE {
			h.alertQueue.Put(alert.AlertEntry{Request: parsed, Decision: decisionResult})
		}

		// ----- 5. 放行：放入 OutputBuffer，等待后端响应 -----
		reqID := fmt.Sprintf("%s-%d", req.ConnectionId, time.Now().UnixNano())
		respCh := h.waiter.Register(reqID)
		defer h.waiter.Unregister(reqID)

		msg := output.Message{
			Request:   parsed,
			Decision:  decisionResult,
			RequestID: reqID,
		}
		h.outputBuf.Put(msg)

		// 等待响应
		select {
		case respData := <-respCh:
			if respData.Error != nil {
				stream.Send(&pb.ProxyResponse{
					ConnectionId: parsed.ConnectionID,
					Status:       pb.Status_BLOCKED,
					Reason:       respData.Error.Error(),
				})
			} else {
				stream.Send(&pb.ProxyResponse{
					ConnectionId:    parsed.ConnectionID,
					Status:          respData.Status,
					Reason:          respData.Reason,
					RawHttpResponse: respData.Body,
				})
			}
		case <-time.After(h.waiter.Timeout()):
			// 超时，移除等待
			h.waiter.Unregister(reqID)
			stream.Send(&pb.ProxyResponse{
				ConnectionId: parsed.ConnectionID,
				Status:       pb.Status_RATE_LIMITED,
				Reason:       "backend response timeout",
			})
		}
	}
}

// ============================================================
// CloseConnection
// ============================================================
func (h *Handler) CloseConnection(ctx context.Context, req *pb.ConnectionClose) (*pb.CloseAck, error) {
	h.mu.Lock()
	connCtx, exists := h.connections[req.ConnectionId]
	if exists {
		delete(h.connections, req.ConnectionId)
	}
	h.mu.Unlock()

	if !exists {
		return &pb.CloseAck{Success: false}, nil
	}

	// Update portrait: extract summary + aggregate profile
	if err := h.portrait.OnConnectionClose(connCtx); err != nil {
		log.Printf("[PORTRAIT] failed to update on close: %v", err)
	}

	return &pb.CloseAck{Success: true}, nil
}

// ============================================================
// PullApproved
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

		if count < len(allMsgs) {
			for i := count; i < len(allMsgs); i++ {
				h.outputBuf.Put(allMsgs[i])
			}
		}
	}
}

// ============================================================
// SubscribeNotify
// ============================================================
func (h *Handler) SubscribeNotify(req *pb.NotifyRequest, stream pb.SecurityProxy_SubscribeNotifyServer) error {
	if req.SubscriberId == "" {
		return status.Errorf(codes.InvalidArgument, "missing subscriber_id")
	}

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
// BroadcastNotify
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

// ============================================================
// Admin: Device management
// TODO 后面这些接口全部都要改，改为管理员接口，这个必须在server启动的时候就动态注入进去的
// ============================================================

func (h *Handler) RegisterDevice(ctx context.Context, req *pb.RegisterDeviceRequest) (*pb.RegisterDeviceResponse, error) {
	osType := req.OsType
	ip := req.Ip
	fp := types.DeviceFingerprint{UUID: &req.DeviceUuid, OS: &osType, IP: &ip}
	if err := h.fpTree.Register("admin", fp); err != nil {
		return &pb.RegisterDeviceResponse{Success: false, Reason: err.Error()}, nil
	}
	log.Printf("[ADMIN] device registered: uuid=%s os=%s ip=%s", req.DeviceUuid, req.OsType, req.Ip)
	return &pb.RegisterDeviceResponse{Success: true}, nil
}

func (h *Handler) UnregisterDevice(ctx context.Context, req *pb.UnregisterDeviceRequest) (*pb.UnregisterDeviceResponse, error) {
	fp := types.DeviceFingerprint{UUID: &req.DeviceUuid}
	if err := h.fpTree.Unregister("admin", fp); err != nil {
		return &pb.UnregisterDeviceResponse{Success: false, Reason: err.Error()}, nil
	}
	log.Printf("[ADMIN] device unregistered: uuid=%s", req.DeviceUuid)
	return &pb.UnregisterDeviceResponse{Success: true}, nil
}

func (h *Handler) ListDevices(ctx context.Context, req *pb.ListDevicesRequest) (*pb.ListDevicesResponse, error) {
	// TODO: iterate fingerprint tree to list all registered devices
	// For now return empty list
	return &pb.ListDevicesResponse{Devices: []*pb.DeviceInfo{}}, nil
}
