package grpc

import (
	"context"

	"fmt"

	"sync"

	"time"

	"google.golang.org/grpc/codes"

	"google.golang.org/grpc/status"

	"Threshold/pkg/types"

	"Threshold/server/decision"

	"Threshold/server/fingerprint"

	pb "Threshold/pkg/proto/pb"
)

type Handler struct {
	pb.UnimplementedSecurityProxyServer

	mu sync.RWMutex

	connections map[string]*types.ConnectionContext

	fpTree *fingerprint.Tree

	engine *decision.Engine

	notifySubs sync.Map
}

func NewHandler(fpTree *fingerprint.Tree, engine *decision.Engine) *Handler {

	return &Handler{

		connections: make(map[string]*types.ConnectionContext),

		fpTree: fpTree, engine: engine,
	}
}

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

		// Step 2: risk classification + decision engine

		riskLevel := types.L0 // TODO:接入 Router

		h.mu.RLock()

		connCtx := h.connections[parsed.ConnectionID]

		h.mu.RUnlock()

		history := make([]*types.ConnectionSummary, 0)

		if connCtx != nil {

			connCtx.RecordEvent(parsed.OpKey)

		}

		decisionResult := h.engine.Evaluate(connCtx, history, riskLevel)

		// Step 3: map decision to response status

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

func (h *Handler) PullApproved(stream pb.SecurityProxy_PullApprovedServer) error {

	req, err := stream.Recv()

	if err != nil {
		return err
	}

	_ = req

	return nil
}

func (h *Handler) SubscribeNotify(req *pb.NotifyRequest, stream pb.SecurityProxy_SubscribeNotifyServer) error {

	if req.SubscriberId == "" {
		return status.Errorf(codes.InvalidArgument, "missing subscriber_id")
	}

	ch := make(chan *pb.NotifyEvent, 100)

	h.notifySubs.Store(req.SubscriberId, ch)

	defer h.notifySubs.Delete(req.SubscriberId)

	for {

		select {

		case event := <-ch:

			if err := stream.Send(event); err != nil {
				return err
			}

		case <-stream.Context().Done():

			return stream.Context().Err()

		}

	}
}

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
