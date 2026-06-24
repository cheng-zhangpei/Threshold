package grpc

import (
	"Threshold/pkg/waiter"
	"Threshold/server/admin"
	"Threshold/server/dispatch"
	router_v1 "Threshold/server/router/router_v1"
	"Threshold/server/router/router_v2"
	"Threshold/server/token"
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
	dm         *dispatch.DispatchManager

	AdminStore *admin.Store
	TokenStore *token.Store
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
	dm *dispatch.DispatchManager,
	AdminStore *admin.Store,
	TokenStore *token.Store,
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
		dm:          dm,
		AdminStore:  AdminStore,
		TokenStore:  TokenStore,
	}
}

// ============================================================
// EstablishConnection
// ============================================================
func (h *Handler) EstablishConnection(ctx context.Context, req *pb.ConnectionInit) (*pb.ConnectionAck, error) {
	log.Printf("EstablishConnection called")
	if req.UserId == "" || req.DeviceUuid == "" {
		return &pb.ConnectionAck{Accepted: false, Reason: "missing user_id or device_uuid"}, nil
	}
	protocol := req.Protocol
	if protocol == "" {
		protocol = "http"
	}
	connIP := req.Ip
	fp := types.DeviceFingerprint{OS: &req.OsType, IP: &connIP, UUID: &req.DeviceUuid}
	log.Println(fp)
	if !h.fpTree.Match(fp) {
		log.Println("[Blocked] device not registered!")
		return &pb.ConnectionAck{Accepted: false, Reason: "device not registered"}, nil
	}
	log.Printf("[UnBlocked] device registered: %s", connIP)
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

		// ----- 3. 生成请求 ID 并注册 Waiter -----
		reqID := fmt.Sprintf("%s-%d", req.ConnectionId, time.Now().UnixNano())
		respCh := h.waiter.Register(reqID)
		defer h.waiter.Unregister(reqID)

		var decisionResult *types.Decision

		// ----- 4. 决策与分发 -----
		if riskLevel == types.L0 {
			// L0 直传，不入队
			decisionResult = &types.Decision{
				Action: types.ALLOW,
				Reason: "L0 direct pass",
				RuleID: "L0",
			}
			// L0 直接放入 OutputBuffer，携带 RequestID 以便 Sender 通过 Waiter 回传响应
			h.outputBuf.Put(output.Message{
				Request:   parsed,
				Decision:  decisionResult,
				RequestID: reqID,
			})
		} else {
			// L1-L3 交给 DispatchManager 异步处理（内部决策 + 放入 OutputBuffer/AlertQueue）
			// 注意：Enqueue 会阻塞等待 Worker 决策完成并返回 decisionResult
			// Worker 会将消息（含 RequestID）放入 OutputBuffer，最终由 Sender 通过 Waiter 回传响应
			decisionResult = h.dm.Enqueue(parsed, riskLevel, reqID)
			if decisionResult == nil {
				stream.Send(&pb.ProxyResponse{
					ConnectionId: parsed.ConnectionID,
					Status:       pb.Status_RATE_LIMITED,
					Reason:       "dispatch failed",
				})
				continue
			}
			// Worker 已经将消息放入 OutputBuffer/AlertQueue，这里不需要再放
		}

		// ----- 5. 阻断处理（不需要等待后端响应） -----
		if decisionResult.Action == types.BLOCK ||
			decisionResult.Action == types.BLOCK_DEVICE ||
			decisionResult.Action == types.BLACKLIST_DEVICE {
			stream.Send(&pb.ProxyResponse{
				ConnectionId: parsed.ConnectionID,
				Status:       pb.Status_BLOCKED,
				Reason:       decisionResult.Reason,
			})
			continue
		}

		// ----- 6. 放行：等待后端响应（通过 Waiter） -----
		select {
		case respData := <-respCh:
			// 正常收到后端响应
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
					RawHttpResponse: respData.Body, // 真实的业务响应数据
				})
			}
		case <-time.After(h.waiter.Timeout()):
			// 超时：移除等待，返回限流响应
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
// Admin: 初始化管理员（仅首次可用）
// TODO(cheng) 为了安全起见我们暂时只设置一个管理员，并且只能被调用一次，
// ============================================================
func (h *Handler) InitAdmin(ctx context.Context, req *pb.InitAdminRequest) (*pb.InitAdminResponse, error) {
	if h.AdminStore == nil {
		return &pb.InitAdminResponse{Success: false, Reason: "admin store not initialized"}, nil
	}

	if h.AdminStore.HasAdmin() {
		return &pb.InitAdminResponse{Success: false, Reason: "admin already initialized"}, nil
	}

	if req.Username == "" || req.Password == "" {
		return &pb.InitAdminResponse{Success: false, Reason: "username and password are required"}, nil
	}

	// 验证一次性口令
	if err := admin.ValidatePasscode("./data", req.Passcode); err != nil {
		log.Printf("[ADMIN] init failed: invalid passcode")
		return &pb.InitAdminResponse{Success: false, Reason: "invalid passcode"}, nil
	}

	if err := h.AdminStore.InitAdmin(req.Username, req.Password); err != nil {
		return &pb.InitAdminResponse{Success: false, Reason: err.Error()}, nil
	}

	log.Printf("[ADMIN] admin initialized: user=%s", req.Username)
	return &pb.InitAdminResponse{Success: true}, nil
}

// ============================================================
// Admin: 登录获取 Token
// ============================================================

func (h *Handler) LoginAdmin(ctx context.Context, req *pb.LoginAdminRequest) (*pb.LoginAdminResponse, error) {
	if h.AdminStore == nil || h.TokenStore == nil {
		return &pb.LoginAdminResponse{Success: false, Reason: "admin/token store not initialized"}, nil
	}

	// 验证密码
	if err := h.AdminStore.Verify(req.Username, req.Password); err != nil {
		log.Printf("[ADMIN] login failed: user=%s err=%v", req.Username, err)
		return &pb.LoginAdminResponse{Success: false, Reason: "invalid credentials"}, nil
	}

	// TTL: 客户端请求 vs 服务端上限
	maxTTL := 7 * 24 * time.Hour // 7 天上限
	requestedTTL := time.Duration(req.TtlSeconds) * time.Second
	if requestedTTL <= 0 || requestedTTL > maxTTL {
		requestedTTL = 24 * time.Hour
	}

	tokenStr, expiresAt, err := h.TokenStore.Generate(req.Username, requestedTTL)
	if err != nil {
		return &pb.LoginAdminResponse{Success: false, Reason: fmt.Sprintf("token generation failed: %v", err)}, nil
	}

	log.Printf("[ADMIN] login success: user=%s ttl=%v", req.Username, requestedTTL)
	return &pb.LoginAdminResponse{
		Success:   true,
		Token:     tokenStr,
		ExpiresAt: expiresAt,
	}, nil
}

func (h *Handler) validateAdminToken(tokenStr string) error {
	if h.TokenStore == nil {
		return fmt.Errorf("token store not initialized")
	}
	if tokenStr == "" {
		return fmt.Errorf("token is required")
	}
	_, err := h.TokenStore.Validate(tokenStr)
	if err != nil {
		return fmt.Errorf("token validation failed: %w", err)
	}
	return nil
}

// ============================================================
// Admin: Device management
// ============================================================

func (h *Handler) RegisterDevice(ctx context.Context, req *pb.RegisterDeviceRequest) (*pb.RegisterDeviceResponse, error) {
	// Token 校验
	if err := h.validateAdminToken(req.Token); err != nil {
		return &pb.RegisterDeviceResponse{Success: false, Reason: err.Error()}, nil
	}

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
	// Token 校验
	if err := h.validateAdminToken(req.Token); err != nil {
		return &pb.UnregisterDeviceResponse{Success: false, Reason: err.Error()}, nil
	}

	osType := req.OsType
	ip := req.Ip
	fp := types.DeviceFingerprint{UUID: &req.DeviceUuid, OS: &osType, IP: &ip}
	if err := h.fpTree.Unregister("admin", fp); err != nil {
		return &pb.UnregisterDeviceResponse{Success: false, Reason: err.Error()}, nil
	}
	log.Printf("[ADMIN] device unregistered: uuid=%s", req.DeviceUuid)
	return &pb.UnregisterDeviceResponse{Success: true}, nil
}

func (h *Handler) ListDevices(ctx context.Context, req *pb.ListDevicesRequest) (*pb.ListDevicesResponse, error) {
	// Token 校验
	if err := h.validateAdminToken(req.Token); err != nil {
		return nil, fmt.Errorf("auth failed: %w", err)
	}
	// 遍历指纹树获取已注册设备
	devices := h.fpTree.ListDevices(int(req.GetLimit()))
	log.Printf("[ADMIN] list devices: count=%d limit=%d", len(devices), req.GetLimit())
	return &pb.ListDevicesResponse{Devices: devices}, nil
}
