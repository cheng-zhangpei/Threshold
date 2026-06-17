package proxy

import (
	"context"
	"encoding/binary"
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

// EstablishConnection
func (p *LocalProxy) EstablishConnection(ctx context.Context, req *pb.ConnectionInit) (*pb.ConnectionAck, error) {
	log.Printf("[CLIENT] EstablishConnection user=%s device=%s", req.UserId, req.DeviceUuid)
	// 设置默认协议：如果未指定，视为 HTTP（IDV Client 场景）
	if req.Protocol == "" {
		req.Protocol = "http"
	}
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
			ip:         req.Ip,
			collector:  collector.NewCollector(),
		}
		p.mu.Unlock()
	}
	return resp, nil
}

// ProxyStream
func (p *LocalProxy) ProxyStream(stream pb.SecurityProxy_ProxyStreamServer) error {
	for {
		req, err := stream.Recv()
		if err != nil {
			return err
		}

		// 获取连接状态
		p.mu.RLock()
		cs := p.connections[req.ConnectionId]
		p.mu.RUnlock()
		if cs != nil {
			cs.collector.Record("proxy", req.ConnectionId)
		}

		// ---- 注入指纹（HTTP 才注入 Header） ----
		deviceUUID := p.deviceUUID
		osType := p.osType
		clientIP := ""
		if cs != nil {
			deviceUUID = cs.deviceUUID
			osType = cs.osType
			clientIP = cs.ip
		}
		processedData, _ := detectAndInject(req.RawHttpRequest, deviceUUID, osType, clientIP)
		req.RawHttpRequest = processedData
		// ------------------------------------

		// 创建到服务端的 gRPC 流（每个请求独立流）
		serverStream, err := p.serverClient.ProxyStream(context.Background())
		if err != nil {
			log.Printf("[CLIENT] create server stream error: %v", err)
			stream.Send(&pb.ProxyResponse{
				ConnectionId: req.ConnectionId,
				Status:       pb.Status_RATE_LIMITED,
				Reason:       fmt.Sprintf("server error: %v", err),
			})
			continue
		}

		// 发送请求
		if err := serverStream.Send(req); err != nil {
			log.Printf("[CLIENT] send to server error: %v", err)
			stream.Send(&pb.ProxyResponse{
				ConnectionId: req.ConnectionId,
				Status:       pb.Status_RATE_LIMITED,
				Reason:       fmt.Sprintf("send error: %v", err),
			})
			continue
		}
		serverStream.CloseSend()

		// 等待服务端响应
		resp, err := serverStream.Recv()
		if err != nil {
			log.Printf("[CLIENT] recv from server error: %v", err)
			stream.Send(&pb.ProxyResponse{
				ConnectionId: req.ConnectionId,
				Status:       pb.Status_RATE_LIMITED,
				Reason:       fmt.Sprintf("recv error: %v", err),
			})
			continue
		}
		// 将响应转发给 IDV Client
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

// injectTCPFingerprint 在 TCP 字节流前添加指纹头（原型）
func injectTCPFingerprint(raw []byte, deviceUUID string) ([]byte, bool) {
	if len(raw) == 0 || deviceUUID == "" {
		return raw, false
	}
	// 构造 payload: [4字节长度][UUID字节]
	uuidBytes := []byte(deviceUUID)
	length := uint32(len(uuidBytes))
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, length)
	injected := append(header, uuidBytes...)
	injected = append(injected, raw...)
	return injected, true
}

// detectAndInject 智能探测并注入指纹
// 返回值: (新数据, 是否修改)
func detectAndInject(raw []byte, deviceUUID, osType, clientIP string) ([]byte, bool) {
	if len(raw) == 0 {
		return raw, false
	}
	switch detectProtocol(raw) {
	case protocolHTTP:
		injected, err := injectProxyHeaders(raw, deviceUUID, osType, clientIP)
		if err != nil {
			log.Printf("[CLIENT] inject HTTP headers error: %v", err)
			return raw, false
		}
		return injected, true
	case protocolTCP:
		// TODO(CHENG) 我认为这里其实没必要注入指纹,指纹在grpc建立连接的时候就已经确立了
		//injected, _ := injectTCPFingerprint(raw, deviceUUID)
		return raw, true
	default:
		// 未知协议，原样返回（安全策略）
		return raw, false
	}
}

const (
	protocolUnknown = iota
	protocolHTTP
	protocolTCP
	// 未来可添加: protocolTLS, protocolSSH, protocolMySQL, ...
)

// detectProtocol 简单探测
func detectProtocol(raw []byte) int {
	// HTTP 方法列表
	methods := [][]byte{
		[]byte("GET "), []byte("POST "), []byte("PUT "),
		[]byte("DELETE "), []byte("PATCH "), []byte("HEAD "),
		[]byte("CONNECT "), []byte("OPTIONS "), []byte("TRACE "),
	}
	for _, m := range methods {
		if len(raw) >= len(m) && string(raw[:len(m)]) == string(m) {
			return protocolHTTP
		}
	}
	// 其他协议探测可在此扩展，例如：
	// if len(raw) >= 3 && raw[0] == 0x16 && raw[1] == 0x03 { return protocolTLS }
	// if len(raw) >= 4 && string(raw[:4]) == "SSH-" { return protocolSSH }
	// 默认非 HTTP 视为普通 TCP
	return protocolTCP
}
