package proxy

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "Threshold/pkg/proto/pb"
	"Threshold/client/collector"
)

// LocalProxy is a gRPC server for IDV clients and a gRPC client to Threshold server.
type LocalProxy struct {
	pb.UnimplementedSecurityProxyServer
	listenAddr  string
	grpcServer  *grpc.Server
	serverAddr  string
	serverConn  *grpc.ClientConn
	serverClient pb.SecurityProxyClient
	deviceUUID  string
	userID      string
	mu          sync.RWMutex
	connections map[string]*connState
}

type connState struct {
	connID    string
	deviceUUID string
	userID    string
	collector *collector.Collector
}

type Config struct {
	ListenAddr string
	ServerAddr string
	DeviceUUID string
	UserID     string
}

func New(cfg Config) *LocalProxy {
	return &LocalProxy{
		listenAddr:  cfg.ListenAddr,
		serverAddr:  cfg.ServerAddr,
		deviceUUID:  cfg.DeviceUUID,
		userID:      cfg.UserID,
		connections: make(map[string]*connState),
	}
}

func (p *LocalProxy) Start() error {
	var err error
	p.serverConn, err = grpc.NewClient(p.serverAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("dial server: %w", err)
	}
	p.serverClient = pb.NewSecurityProxyClient(p.serverConn)
	log.Printf("[CLIENT] connected to server %s", p.serverAddr)

	lis, err := net.Listen("tcp", p.listenAddr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	p.listenAddr = lis.Addr().String()
	p.grpcServer = grpc.NewServer()
	pb.RegisterSecurityProxyServer(p.grpcServer, p)
	log.Printf("[CLIENT] proxy listening on %s", p.listenAddr)
	return p.grpcServer.Serve(lis)
}

func (p *LocalProxy) Stop() {
	if p.grpcServer != nil { p.grpcServer.GracefulStop() }
	if p.serverConn != nil { p.serverConn.Close() }
	log.Printf("[CLIENT] stopped")
}

func (p *LocalProxy) EstablishConnection(ctx context.Context, req *pb.ConnectionInit) (*pb.ConnectionAck, error) {
	log.Printf("[CLIENT] EstablishConnection user=%s device=%s", req.UserId, req.DeviceUuid)
	resp, err := p.serverClient.EstablishConnection(ctx, req)
	if err != nil {
		return nil, err
	}
	if resp.Accepted {
		p.mu.Lock()
		p.connections[resp.ConnectionId] = &connState{connID: resp.ConnectionId, deviceUUID: req.DeviceUuid, userID: req.UserId, collector: collector.NewCollector()}
		p.mu.Unlock()
	}
	return resp, nil
}

func (p *LocalProxy) ProxyStream(stream pb.SecurityProxy_ProxyStreamServer) error {
	for {
		req, err := stream.Recv()
		if err != nil { return err }
		p.mu.RLock()
		cs := p.connections[req.ConnectionId]
		p.mu.RUnlock()
		if cs != nil { cs.collector.Record("proxy", req.ConnectionId) }

		serverStream, err := p.serverClient.ProxyStream(context.Background())
		if err != nil {
			stream.Send(&pb.ProxyResponse{ConnectionId: req.ConnectionId, Status: pb.Status_RATE_LIMITED, Reason: fmt.Sprintf("server error: %v", err)})
			continue
		}
		serverStream.Send(req)
		serverStream.CloseSend()
		resp, err := serverStream.Recv()
		if err != nil {
			log.Printf("[CLIENT] recv error: %v", err)
			continue
		}
		stream.Send(resp)
	}
}

func (p *LocalProxy) CloseConnection(ctx context.Context, req *pb.ConnectionClose) (*pb.CloseAck, error) {
	p.mu.Lock()
	delete(p.connections, req.ConnectionId)
	p.mu.Unlock()
	return p.serverClient.CloseConnection(ctx, req)
}

func (p *LocalProxy) PullApproved(stream pb.SecurityProxy_PullApprovedServer) error {
	return fmt.Errorf("not implemented on client")
}

func (p *LocalProxy) SubscribeNotify(req *pb.NotifyRequest, stream pb.SecurityProxy_SubscribeNotifyServer) error {
	return fmt.Errorf("not implemented on client")
}

func (p *LocalProxy) ListenAddr() string {
	return p.listenAddr
}

func (p *LocalProxy) RegisterDevice(ctx context.Context, req *pb.RegisterDeviceRequest) (*pb.RegisterDeviceResponse, error) {
	return p.serverClient.RegisterDevice(ctx, req)
}

func (p *LocalProxy) UnregisterDevice(ctx context.Context, req *pb.UnregisterDeviceRequest) (*pb.UnregisterDeviceResponse, error) {
	return p.serverClient.UnregisterDevice(ctx, req)
}

func (p *LocalProxy) ListDevices(ctx context.Context, req *pb.ListDevicesRequest) (*pb.ListDevicesResponse, error) {
	return p.serverClient.ListDevices(ctx, req)
}