package grpc

import (
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
	"Threshold/server/router"

	pb "Threshold/pkg/proto/pb"
)

type Handler struct {
	pb.UnimplementedSecurityProxyServer

	mu          sync.RWMutex
	connections map[string]*types.ConnectionContext

	fpTree     *fingerprint.Tree
	engine     *decision.Engine
	r          *router.Router
	outputBuf  *output.OutputBuffer
	alertQueue *alert.AlertQueue
	portrait   *portrait.Store

	notifySubs sync.Map
}

func NewHandler(
	fpTree *fingerprint.Tree,
	engine *decision.Engine,
	r *router.Router,
	outputBuf *output.OutputBuffer,
	alertQueue *alert.AlertQueue,
	portraitStore *portrait.Store,
) *Handler {
	return &Handler{
		connections: make(map[string]*types.ConnectionContext),
		fpTree:      fpTree,
		engine:      engine,
		r:           r,
		outputBuf:   outputBuf,
		alertQueue:  alertQueue,
		portrait:    portraitStore,
	}
}

// ============================================================
// EstablishConnection
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
// ProxyStream
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

		// Step 1: fingerprint check
		if !h.fpTree.Match(parsed.Fingerprint) {
			stream.Send(&pb.ProxyResponse{ConnectionId: parsed.ConnectionID, Status: pb.Status_BLOCKED, Reason: "fingerprint mismatch"})
			continue
		}

		// Step 2: record event
		h.mu.RLock()
		connCtx := h.connections[parsed.ConnectionID]
		h.mu.RUnlock()
		if connCtx != nil {
			connCtx.RecordEvent(parsed.OpKey)
		}

		// Step 3: route
		riskLevel := h.r.Classify(parsed)

		var decisionResult *types.Decision
		if riskLevel == types.L0 {
			decisionResult = &types.Decision{Action: types.ALLOW, Reason: "L0 direct pass", RuleID: "L0"}
			h.outputBuf.Put(output.Message{Request: parsed, Decision: decisionResult})
		} else {
			// Fetch history from portrait store for decision engine
			history := h.portrait.GetHistory(parsed.UserID, 20)
			decisionResult = h.engine.Evaluate(connCtx, history, riskLevel)

			switch decisionResult.Action {
				case types.BLOCK, types.BLOCK_DEVICE, types.BLACKLIST_DEVICE, types.ALERT, types.QUARANTINE_AND_ALERT:
					h.alertQueue.Put(alert.AlertEntry{Request: parsed, Decision: decisionResult})
				default:
					h.outputBuf.Put(output.Message{Request: parsed, Decision: decisionResult})
			}
		}

		// Step 4: map to gRPC response
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