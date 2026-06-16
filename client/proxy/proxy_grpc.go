package proxy

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"Threshold/client/collector"
	pb "Threshold/pkg/proto/pb"
)

// LocalProxy is a gRPC server for IDV clients and a gRPC client to Threshold server.
type LocalProxy struct {
	pb.UnimplementedSecurityProxyServer
	listenAddr   string
	grpcServer   *grpc.Server
	serverAddr   string
	serverConn   *grpc.ClientConn
	serverClient pb.SecurityProxyClient
	deviceUUID   string
	userID       string
	osType       string
	mu           sync.RWMutex
	connections  map[string]*connState
}

type connState struct {
	connID     string
	deviceUUID string
	userID     string
	osType     string
	ip         string // ← 客户端在 ConnectionInit 中声明的 IP
	collector  *collector.Collector
}

type Config struct {
	ListenAddr string
	ServerAddr string
	DeviceUUID string
	UserID     string
	OSType     string
}

func New(cfg Config) *LocalProxy {
	return &LocalProxy{
		listenAddr:  cfg.ListenAddr,
		serverAddr:  cfg.ServerAddr,
		deviceUUID:  cfg.DeviceUUID,
		userID:      cfg.UserID,
		osType:      cfg.OSType,
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
	if p.grpcServer != nil {
		p.grpcServer.GracefulStop()
	}
	if p.serverConn != nil {
		p.serverConn.Close()
	}
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
		p.connections[resp.ConnectionId] = &connState{
			connID:     resp.ConnectionId,
			deviceUUID: req.DeviceUuid,
			userID:     req.UserId,
			osType:     req.OsType,
			ip:         req.Ip, // ← 保存客户端声明的 IP
			collector:  collector.NewCollector(),
		}
		p.mu.Unlock()
	}
	return resp, nil
}

func (p *LocalProxy) ProxyStream(stream pb.SecurityProxy_ProxyStreamServer) error {
	for {
		req, err := stream.Recv()
		if err != nil {
			return err
		}

		p.mu.RLock()
		cs := p.connections[req.ConnectionId]
		p.mu.RUnlock()
		if cs != nil {
			cs.collector.Record("proxy", req.ConnectionId)
		}

		// ──── 注入 X-Proxy-* 指纹头 ────
		deviceUUID := p.deviceUUID
		osType := p.osType
		clientIP := "" // fallback
		if cs != nil {
			deviceUUID = cs.deviceUUID
			osType = cs.osType
			clientIP = cs.ip // ← 用 ConnectionInit 时保存的 IP
		}

		injected, err := injectProxyHeaders(req.RawHttpRequest, deviceUUID, osType, clientIP)
		if err != nil {
			log.Printf("[CLIENT] injectProxyHeaders error: %v", err)
			stream.Send(&pb.ProxyResponse{
				ConnectionId: req.ConnectionId,
				Status:       pb.Status_BLOCKED,
				Reason:       fmt.Sprintf("header injection failed: %v", err),
			})
			continue
		}
		req.RawHttpRequest = injected
		// ──────────────────────────────────

		serverStream, err := p.serverClient.ProxyStream(context.Background())
		if err != nil {
			stream.Send(&pb.ProxyResponse{
				ConnectionId: req.ConnectionId,
				Status:       pb.Status_RATE_LIMITED,
				Reason:       fmt.Sprintf("server error: %v", err),
			})
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

// TODO 这里有些接口是需要管理才可以操作的，比如说将用户注册到白名单，这里后续一定要加上鉴权的操作

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

// injectProxyHeaders 在 HTTP 请求的 header 区域末尾注入 X-Proxy-* 指纹头。
// 只注入请求中尚不存在的字段，避免重复。
func injectProxyHeaders(raw []byte, deviceUUID, osType, clientIP string) ([]byte, error) {
	s := string(raw)

	headers := []struct {
		key   string
		value string
	}{
		{"X-Proxy-UUID", deviceUUID},
		{"X-Proxy-OS", osType},
		{"X-Proxy-IP", clientIP},
	}

	// 检查哪些头已经存在
	needInject := false
	for _, h := range headers {
		if h.value != "" && !strings.Contains(s, h.key+":") {
			needInject = true
			break
		}
	}
	if !needInject {
		return raw, nil
	}

	// 构造要注入的头部行
	var injectLines string
	for _, h := range headers {
		if h.value != "" && !strings.Contains(s, h.key+":") {
			injectLines += h.key + ": " + h.value + "\r\n"
		}
	}

	// 在 \r\n\r\n（header 结束标记）前插入
	idx := strings.Index(s, "\r\n\r\n")
	if idx >= 0 {
		// 在空行前注入
		result := s[:idx] + "\r\n" + injectLines + s[idx:]
		return []byte(result), nil
	}

	// 没有 body，追加到末尾
	return []byte(strings.TrimRight(s, "\r\n") + "\r\n" + injectLines + "\r\n"), nil
}
