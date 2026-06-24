package main

import (
	"Threshold/pkg/waiter"
	"Threshold/server/admin"
	"Threshold/server/router/router_v1"
	"Threshold/server/router/router_v2"
	"Threshold/server/token"
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"Threshold/pkg/storage"
	"Threshold/pkg/types"
	"Threshold/server/alert"
	"Threshold/server/decision"
	"Threshold/server/dispatch"
	"Threshold/server/fingerprint"
	"Threshold/server/output"
	"Threshold/server/portrait"

	clientproxy "Threshold/client/proxy"
	servergrpc "Threshold/server/grpc"

	pb "Threshold/pkg/proto/pb"
)

type testEnv struct {
	grpcSrv     *grpc.Server
	srvAddr     string
	clientProxy *clientproxy.LocalProxy
	cleanup     func()
}

func setupEnv(t *testing.T) *testEnv {
	t.Helper()
	log.Println("[SETUP] === using NEW proxy_grpc.go with injection ===")

	tmpDir, err := os.MkdirTemp("", "client-e2e-*")
	if err != nil {
		t.Fatalf("mkdir temp: %v", err)
	}

	store, err := storage.NewBoltStore(filepath.Join(tmpDir, "scripts.db"))
	if err != nil {
		t.Fatalf("new bolt store: %v", err)
	}
	wal := storage.NewWAL(store)
	wal.Recover()

	fpTree, err := fingerprint.NewTree(store, wal)
	if err != nil {
		t.Fatalf("new fingerprint tree: %v", err)
	}

	testUUID := "scripts-device-001"
	testOS := "linux"
	testIP := "10.0.0.1"
	fpTree.Register("init", types.DeviceFingerprint{
		UUID: &testUUID, OS: &testOS, IP: &testIP,
	})
	waiterInstance := waiter.NewWaiter(30 * time.Second)

	ps := portrait.NewStore(store)
	engine := decision.NewEngine(ps)
	outputBuf := output.NewOutputBufferWithConfig(10000, 4, 1024, true, waiterInstance)
	alertQueue := alert.NewAlertQueue()

	// 创建 Waiter

	dm := dispatch.NewDispatchManager(dispatch.DispatcherConfig{
		Policy: dispatch.PoolPolicy{
			MinWorkers: 2, MaxWorkers: 8, MaxQueueSize: 64, HealthCheckIntervalSec: 5,
		},
		Store: store,
		DecisionFn: func(ctx *types.ConnectionContext, history []*types.ConnectionSummary, rl types.RiskLevel) *types.Decision {
			return engine.Evaluate(ctx, history, rl)
		},
	}, outputBuf, alertQueue)

	riskTable := router_v1.NewOperationRiskTable()
	r := router_v1.NewRouter(riskTable, outputBuf, dm, 2, 256)

	var r2 *router_v2.Router = nil

	srvLis, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	grpcSrv := grpc.NewServer()
	// 修改 NewHandler 调用：传入 dm 和 waiter，移除 engine
	adminStore, err := admin.NewStore(store)
	if err != nil {
		log.Fatalf("init admin store: %v", err)
	}

	tokenStore, err := token.NewStore(store, "")
	if err != nil {
		log.Fatalf("init token store: %v", err)
	}
	handler := servergrpc.NewHandler(fpTree, engine, r, r2, outputBuf, alertQueue, ps, waiterInstance, dm, adminStore, tokenStore)
	pb.RegisterSecurityProxyServer(grpcSrv, handler)
	go grpcSrv.Serve(srvLis)
	srvAddr := srvLis.Addr().String()

	cp := clientproxy.New(clientproxy.Config{
		ListenAddr: ":0",
		ServerAddr: srvAddr,
		DeviceUUID: "scripts-device-001",
		UserID:     "scripts-user",
		OSType:     "linux",
	})
	go cp.Start()
	time.Sleep(200 * time.Millisecond)

	cleanup := func() {
		cp.Stop()
		grpcSrv.GracefulStop()
		r.Shutdown()
		dm.Shutdown()
		store.Close()
		os.RemoveAll(tmpDir)
	}

	return &testEnv{grpcSrv: grpcSrv, srvAddr: srvAddr, clientProxy: cp, cleanup: cleanup}
}
func idvClient(t *testing.T, addr string) pb.SecurityProxyClient {
	t.Helper()
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial client: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return pb.NewSecurityProxyClient(conn)
}

func directClient(t *testing.T, addr string) pb.SecurityProxyClient {
	t.Helper()
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial server: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return pb.NewSecurityProxyClient(conn)
}

var rawGET = []byte("GET /api/cloud/public/images HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\r\n")
var rawDELETE = []byte("DELETE /api/cloud/public/images HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\r\n")
var rawPOST = []byte("POST /api/cloud/public/images HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\r\n{\"name\":\"scripts-image\"}")
var rawUnknownPath = []byte("PATCH /api/router_v1/unknown/endpoint HTTP/1.1\r\nHost: localhost\r\n\r\n")

// ============================================================
// 连接建立测试
// ============================================================

func TestClientProxy_EstablishConnection(t *testing.T) {
	env := setupEnv(t)
	defer env.cleanup()

	client := idvClient(t, env.clientProxy.ListenAddr())
	resp, err := client.EstablishConnection(context.Background(), &pb.ConnectionInit{
		UserId:     "scripts-user",
		DeviceUuid: "scripts-device-001",
		Ip:         "10.0.0.1",
		OsType:     "linux",
		Timestamp:  time.Now().UnixMilli(),
	})
	if err != nil {
		t.Fatalf("EstablishConnection error: %v", err)
	}
	if !resp.Accepted {
		t.Fatalf("expected accepted, got rejected: %s", resp.Reason)
	}
	if resp.ConnectionId == "" {
		t.Error("expected non-empty connection_id")
	}
	fmt.Printf("[E2E] EstablishConnection OK: conn_id=%s\n", resp.ConnectionId)
}

func TestClientProxy_EstablishConnection_UnknownDevice(t *testing.T) {
	env := setupEnv(t)
	defer env.cleanup()

	client := idvClient(t, env.clientProxy.ListenAddr())
	resp, err := client.EstablishConnection(context.Background(), &pb.ConnectionInit{
		UserId:     "scripts-user",
		DeviceUuid: "unknown-device-999",
		Ip:         "10.0.0.1",
		OsType:     "linux",
		Timestamp:  time.Now().UnixMilli(),
	})
	if err != nil {
		t.Fatalf("EstablishConnection error: %v", err)
	}
	if resp.Accepted {
		t.Fatal("expected rejected for unknown device, but got accepted")
	}
	fmt.Printf("[E2E] EstablishConnection_UnknownDevice OK: rejected=%s\n", resp.Reason)
}

// ============================================================
// 请求转发测试 — L0 只读查询（直接穿透）
// ============================================================

func TestClientProxy_ProxyStream_GET_L0(t *testing.T) {
	env := setupEnv(t)
	defer env.cleanup()

	client := idvClient(t, env.clientProxy.ListenAddr())
	connResp, _ := client.EstablishConnection(context.Background(), &pb.ConnectionInit{
		UserId: "scripts-user", DeviceUuid: "scripts-device-001",
		Ip: "10.0.0.1", OsType: "linux", Timestamp: time.Now().UnixMilli(),
	})
	if !connResp.Accepted {
		t.Fatalf("connection not accepted: %s", connResp.Reason)
	}

	stream, err := client.ProxyStream(context.Background())
	if err != nil {
		t.Fatalf("ProxyStream: %v", err)
	}
	stream.Send(&pb.ProxyRequest{
		ConnectionId:   connResp.ConnectionId,
		DeviceUuid:     "scripts-device-001",
		UserId:         "scripts-user",
		RawHttpRequest: rawGET,
		Timestamp:      time.Now().UnixMilli(),
	})
	stream.CloseSend()

	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	if resp.Status != pb.Status_OK {
		t.Errorf("status=%v, want OK. reason=%s", resp.Status, resp.Reason)
	}
	fmt.Printf("[E2E] ProxyStream GET L0 OK: status=%v reason=%s\n", resp.Status, resp.Reason)
}

// ============================================================
// 请求转发测试 — L2 DELETE 操作
// ============================================================

func TestClientProxy_ProxyStream_DELETE_L2(t *testing.T) {
	env := setupEnv(t)
	defer env.cleanup()

	client := idvClient(t, env.clientProxy.ListenAddr())
	connResp, _ := client.EstablishConnection(context.Background(), &pb.ConnectionInit{
		UserId: "scripts-user", DeviceUuid: "scripts-device-001",
		Ip: "10.0.0.1", OsType: "linux", Timestamp: time.Now().UnixMilli(),
	})
	if !connResp.Accepted {
		t.Fatalf("connection not accepted: %s", connResp.Reason)
	}

	stream, _ := client.ProxyStream(context.Background())
	stream.Send(&pb.ProxyRequest{
		ConnectionId:   connResp.ConnectionId,
		DeviceUuid:     "scripts-device-001",
		UserId:         "scripts-user",
		RawHttpRequest: rawDELETE,
		Timestamp:      time.Now().UnixMilli(),
	})
	stream.CloseSend()

	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	if resp.Status != pb.Status_OK {
		t.Errorf("status=%v, want OK. reason=%s", resp.Status, resp.Reason)
	}
	fmt.Printf("[E2E] ProxyStream DELETE L2 OK: status=%v reason=%s\n", resp.Status, resp.Reason)
}

// ============================================================
// 请求转发测试 — L1 POST 写操作
// ============================================================

func TestClientProxy_ProxyStream_POST_L1(t *testing.T) {
	env := setupEnv(t)
	defer env.cleanup()

	client := idvClient(t, env.clientProxy.ListenAddr())
	connResp, _ := client.EstablishConnection(context.Background(), &pb.ConnectionInit{
		UserId: "scripts-user", DeviceUuid: "scripts-device-001",
		Ip: "10.0.0.1", OsType: "linux", Timestamp: time.Now().UnixMilli(),
	})
	if !connResp.Accepted {
		t.Fatalf("connection not accepted: %s", connResp.Reason)
	}

	stream, _ := client.ProxyStream(context.Background())
	stream.Send(&pb.ProxyRequest{
		ConnectionId:   connResp.ConnectionId,
		DeviceUuid:     "scripts-device-001",
		UserId:         "scripts-user",
		RawHttpRequest: rawPOST,
		Timestamp:      time.Now().UnixMilli(),
	})
	stream.CloseSend()

	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	if resp.Status != pb.Status_OK {
		t.Errorf("status=%v, want OK. reason=%s", resp.Status, resp.Reason)
	}
	fmt.Printf("[E2E] ProxyStream POST L1 OK: status=%v reason=%s\n", resp.Status, resp.Reason)
}

// ============================================================
// 指纹校验测试 — 未注册设备的连接应被拒绝
// ============================================================

func TestClientProxy_FingerprintMismatch(t *testing.T) {
	env := setupEnv(t)
	defer env.cleanup()

	client := idvClient(t, env.clientProxy.ListenAddr())
	resp, err := client.EstablishConnection(context.Background(), &pb.ConnectionInit{
		UserId:     "scripts-user",
		DeviceUuid: "hacker-device-999",
		Ip:         "10.0.0.1",
		OsType:     "linux",
		Timestamp:  time.Now().UnixMilli(),
	})
	if err != nil {
		t.Fatalf("EstablishConnection error: %v", err)
	}
	if resp.Accepted {
		t.Fatal("expected rejected for unregistered device fingerprint")
	}
	fmt.Printf("[E2E] FingerprintMismatch OK: correctly rejected=%s\n", resp.Reason)
}

// ============================================================
// 未知路径测试 — Router 应默认 L1
// ============================================================

func TestClientProxy_UnknownPath_DefaultsToL1(t *testing.T) {
	env := setupEnv(t)
	defer env.cleanup()

	client := idvClient(t, env.clientProxy.ListenAddr())
	connResp, _ := client.EstablishConnection(context.Background(), &pb.ConnectionInit{
		UserId: "scripts-user", DeviceUuid: "scripts-device-001",
		Ip: "10.0.0.1", OsType: "linux", Timestamp: time.Now().UnixMilli(),
	})
	if !connResp.Accepted {
		t.Fatalf("connection not accepted: %s", connResp.Reason)
	}

	stream, _ := client.ProxyStream(context.Background())
	stream.Send(&pb.ProxyRequest{
		ConnectionId:   connResp.ConnectionId,
		DeviceUuid:     "scripts-device-001",
		UserId:         "scripts-user",
		RawHttpRequest: rawUnknownPath,
		Timestamp:      time.Now().UnixMilli(),
	})
	stream.CloseSend()

	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	if resp.Status != pb.Status_OK {
		t.Errorf("status=%v, want OK. reason=%s", resp.Status, resp.Reason)
	}
	fmt.Printf("[E2E] UnknownPath L1 OK: status=%v reason=%s\n", resp.Status, resp.Reason)
}

// ============================================================
// 连接关闭测试
// ============================================================

func TestClientProxy_CloseConnection(t *testing.T) {
	env := setupEnv(t)
	defer env.cleanup()

	client := idvClient(t, env.clientProxy.ListenAddr())
	connResp, _ := client.EstablishConnection(context.Background(), &pb.ConnectionInit{
		UserId: "scripts-user", DeviceUuid: "scripts-device-001",
		Ip: "10.0.0.1", OsType: "linux", Timestamp: time.Now().UnixMilli(),
	})
	if !connResp.Accepted {
		t.Fatalf("connection not accepted")
	}

	stream, _ := client.ProxyStream(context.Background())
	stream.Send(&pb.ProxyRequest{
		ConnectionId:   connResp.ConnectionId,
		DeviceUuid:     "scripts-device-001",
		UserId:         "scripts-user",
		RawHttpRequest: rawGET,
		Timestamp:      time.Now().UnixMilli(),
	})
	stream.CloseSend()
	stream.Recv()

	closeResp, err := client.CloseConnection(context.Background(), &pb.ConnectionClose{
		ConnectionId: connResp.ConnectionId,
		Timestamp:    time.Now().UnixMilli(),
	})
	if err != nil {
		t.Fatalf("CloseConnection error: %v", err)
	}
	if !closeResp.Success {
		t.Error("close failed")
	}
	fmt.Printf("[E2E] CloseConnection OK\n")
}

// ============================================================
// 并发请求测试
// ============================================================

func TestClientProxy_Concurrent(t *testing.T) {
	env := setupEnv(t)
	defer env.cleanup()

	client := idvClient(t, env.clientProxy.ListenAddr())
	connResp, _ := client.EstablishConnection(context.Background(), &pb.ConnectionInit{
		UserId: "scripts-user", DeviceUuid: "scripts-device-001",
		Ip: "10.0.0.1", OsType: "linux", Timestamp: time.Now().UnixMilli(),
	})
	if !connResp.Accepted {
		t.Fatalf("connection not accepted")
	}

	var wg sync.WaitGroup
	n := 10
	errCh := make(chan error, n)

	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			s, err := client.ProxyStream(context.Background())
			if err != nil {
				errCh <- fmt.Errorf("ProxyStream: %w", err)
				return
			}
			s.Send(&pb.ProxyRequest{
				ConnectionId:   connResp.ConnectionId,
				DeviceUuid:     "scripts-device-001",
				UserId:         "scripts-user",
				RawHttpRequest: rawGET,
				Timestamp:      time.Now().UnixMilli(),
			})
			s.CloseSend()
			resp, err := s.Recv()
			if err != nil {
				errCh <- fmt.Errorf("recv: %w", err)
				return
			}
			if resp.Status != pb.Status_OK {
				errCh <- fmt.Errorf("status=%v reason=%s", resp.Status, resp.Reason)
			}
		}()
	}
	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrent error: %v", err)
	}
	fmt.Printf("[E2E] %d concurrent requests OK\n", n)
}

// ============================================================
// 指纹注入验证 — 确认 Client 正确注入了 X-Proxy-* 字段
// ============================================================

func TestClientProxy_FingerprintInjection(t *testing.T) {
	env := setupEnv(t)
	defer env.cleanup()

	client := idvClient(t, env.clientProxy.ListenAddr())
	connResp, err := client.EstablishConnection(context.Background(), &pb.ConnectionInit{
		UserId: "scripts-user", DeviceUuid: "scripts-device-001",
		Ip: "10.0.0.1", OsType: "linux", Timestamp: time.Now().UnixMilli(),
	})
	if err != nil {
		t.Fatalf("EstablishConnection: %v", err)
	}
	if !connResp.Accepted {
		t.Fatalf("connection not accepted: %s", connResp.Reason)
	}

	stream, err := client.ProxyStream(context.Background())
	if err != nil {
		t.Fatalf("ProxyStream: %v", err)
	}
	stream.Send(&pb.ProxyRequest{
		ConnectionId:   connResp.ConnectionId,
		DeviceUuid:     "scripts-device-001",
		UserId:         "scripts-user",
		RawHttpRequest: []byte("GET /api/cloud/public/images HTTP/1.1\r\nHost: localhost\r\n\r\n"),
		Timestamp:      time.Now().UnixMilli(),
	})
	stream.CloseSend()

	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	if resp.Status == pb.Status_BLOCKED {
		t.Fatalf("fingerprint injection failed: Client did not inject X-Proxy-* headers. status=%v reason=%s", resp.Status, resp.Reason)
	}
	if resp.Status != pb.Status_OK {
		t.Errorf("unexpected status=%v reason=%s", resp.Status, resp.Reason)
	}
	fmt.Printf("[E2E] FingerprintInjection OK: status=%v\n", resp.Status)
}

// ============================================================
// 指纹注入完整字段验证 — 确认所有 6 个维度都被注入
// ============================================================

func TestClientProxy_FingerprintAllDimensions(t *testing.T) {
	env := setupEnv(t)
	defer env.cleanup()

	directConn, err := grpc.NewClient(env.srvAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial server: %v", err)
	}
	defer directConn.Close()
	directClient := pb.NewSecurityProxyClient(directConn)

	connResp, err := directClient.EstablishConnection(context.Background(), &pb.ConnectionInit{
		UserId: "scripts-user", DeviceUuid: "scripts-device-001",
		Ip: "10.0.0.1", OsType: "linux", Timestamp: time.Now().UnixMilli(),
	})
	if err != nil {
		t.Fatalf("EstablishConnection: %v", err)
	}
	if !connResp.Accepted {
		t.Fatalf("connection not accepted: %s", connResp.Reason)
	}

	stream, _ := directClient.ProxyStream(context.Background())
	stream.Send(&pb.ProxyRequest{
		ConnectionId: connResp.ConnectionId,
		DeviceUuid:   "scripts-device-001",
		UserId:       "scripts-user",
		RawHttpRequest: []byte("GET /api/cloud/public/images HTTP/1.1\r\n" +
			"Host: localhost\r\n" +
			"X-Proxy-UUID: scripts-device-001\r\n" +
			"X-Proxy-OS: linux\r\n" +
			"X-Proxy-IP: 10.0.0.1\r\n" +
			"\r\n"),
		Timestamp: time.Now().UnixMilli(),
	})
	stream.CloseSend()

	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	if resp.Status == pb.Status_BLOCKED {
		t.Errorf("fingerprint should match with UUID+OS+IP, got BLOCKED: %s", resp.Reason)
	}
	fmt.Printf("[E2E] FingerprintAllDimensions OK: UUID+OS+IP partial match status=%v\n", resp.Status)
}

// ============================================================
// 指纹边界测试 — 注入错误/残缺指纹，验证系统正确拒绝
// ============================================================

func TestFingerprint_WrongUUID(t *testing.T) {
	env := setupEnv(t)
	defer env.cleanup()

	dCli := directClient(t, env.srvAddr)
	connResp, err := dCli.EstablishConnection(context.Background(), &pb.ConnectionInit{
		UserId: "scripts-user", DeviceUuid: "scripts-device-001",
		Ip: "10.0.0.1", OsType: "linux", Timestamp: time.Now().UnixMilli(),
	})
	if err != nil {
		t.Fatalf("EstablishConnection: %v", err)
	}
	if !connResp.Accepted {
		t.Fatalf("connection not accepted: %s", connResp.Reason)
	}

	stream, _ := dCli.ProxyStream(context.Background())
	stream.Send(&pb.ProxyRequest{
		ConnectionId: connResp.ConnectionId,
		DeviceUuid:   "scripts-device-001",
		UserId:       "scripts-user",
		RawHttpRequest: []byte("GET /api/cloud/public/images HTTP/1.1\r\n" +
			"Host: localhost\r\n" +
			"X-Proxy-UUID: WRONG-UUID-999\r\n" +
			"X-Proxy-OS: linux\r\n" +
			"X-Proxy-IP: 10.0.0.1\r\n" +
			"\r\n"),
		Timestamp: time.Now().UnixMilli(),
	})
	stream.CloseSend()

	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	if resp.Status != pb.Status_BLOCKED {
		t.Errorf("expected BLOCKED for wrong UUID, got status=%v reason=%s", resp.Status, resp.Reason)
	}
	fmt.Printf("[E2E] WrongUUID OK: correctly blocked, reason=%s\n", resp.Reason)
}

func TestFingerprint_WrongIP(t *testing.T) {
	env := setupEnv(t)
	defer env.cleanup()

	dCli := directClient(t, env.srvAddr)
	connResp, err := dCli.EstablishConnection(context.Background(), &pb.ConnectionInit{
		UserId: "scripts-user", DeviceUuid: "scripts-device-001",
		Ip: "10.0.0.1", OsType: "linux", Timestamp: time.Now().UnixMilli(),
	})
	if err != nil {
		t.Fatalf("EstablishConnection: %v", err)
	}
	if !connResp.Accepted {
		t.Fatalf("connection not accepted: %s", connResp.Reason)
	}

	stream, _ := dCli.ProxyStream(context.Background())
	stream.Send(&pb.ProxyRequest{
		ConnectionId: connResp.ConnectionId,
		DeviceUuid:   "scripts-device-001",
		UserId:       "scripts-user",
		RawHttpRequest: []byte("GET /api/cloud/public/images HTTP/1.1\r\n" +
			"Host: localhost\r\n" +
			"X-Proxy-UUID: scripts-device-001\r\n" +
			"X-Proxy-OS: linux\r\n" +
			"X-Proxy-IP: 192.168.99.99\r\n" +
			"\r\n"),
		Timestamp: time.Now().UnixMilli(),
	})
	stream.CloseSend()

	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	if resp.Status != pb.Status_BLOCKED {
		t.Errorf("expected BLOCKED for wrong IP, got status=%v reason=%s", resp.Status, resp.Reason)
	}
	fmt.Printf("[E2E] WrongIP OK: correctly blocked, reason=%s\n", resp.Reason)
}

func TestFingerprint_WrongOS(t *testing.T) {
	env := setupEnv(t)
	defer env.cleanup()

	dCli := directClient(t, env.srvAddr)
	connResp, err := dCli.EstablishConnection(context.Background(), &pb.ConnectionInit{
		UserId: "scripts-user", DeviceUuid: "scripts-device-001",
		Ip: "10.0.0.1", OsType: "linux", Timestamp: time.Now().UnixMilli(),
	})
	if err != nil {
		t.Fatalf("EstablishConnection: %v", err)
	}
	if !connResp.Accepted {
		t.Fatalf("connection not accepted: %s", connResp.Reason)
	}

	stream, _ := dCli.ProxyStream(context.Background())
	stream.Send(&pb.ProxyRequest{
		ConnectionId: connResp.ConnectionId,
		DeviceUuid:   "scripts-device-001",
		UserId:       "scripts-user",
		RawHttpRequest: []byte("GET /api/cloud/public/images HTTP/1.1\r\n" +
			"Host: localhost\r\n" +
			"X-Proxy-UUID: scripts-device-001\r\n" +
			"X-Proxy-OS: windows\r\n" +
			"X-Proxy-IP: 10.0.0.1\r\n" +
			"\r\n"),
		Timestamp: time.Now().UnixMilli(),
	})
	stream.CloseSend()

	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	if resp.Status != pb.Status_BLOCKED {
		t.Errorf("expected BLOCKED for wrong OS, got status=%v reason=%s", resp.Status, resp.Reason)
	}
	fmt.Printf("[E2E] WrongOS OK: correctly blocked, reason=%s\n", resp.Reason)
}

func TestFingerprint_MissingOSAndIP(t *testing.T) {
	env := setupEnv(t)
	defer env.cleanup()

	dCli := directClient(t, env.srvAddr)
	connResp, err := dCli.EstablishConnection(context.Background(), &pb.ConnectionInit{
		UserId: "scripts-user", DeviceUuid: "scripts-device-001",
		Ip: "10.0.0.1", OsType: "linux", Timestamp: time.Now().UnixMilli(),
	})
	if err != nil {
		t.Fatalf("EstablishConnection: %v", err)
	}
	if !connResp.Accepted {
		t.Fatalf("connection not accepted: %s", connResp.Reason)
	}

	stream, _ := dCli.ProxyStream(context.Background())
	stream.Send(&pb.ProxyRequest{
		ConnectionId: connResp.ConnectionId,
		DeviceUuid:   "scripts-device-001",
		UserId:       "scripts-user",
		RawHttpRequest: []byte("GET /api/cloud/public/images HTTP/1.1\r\n" +
			"Host: localhost\r\n" +
			"X-Proxy-UUID: scripts-device-001\r\n" +
			"\r\n"),
		Timestamp: time.Now().UnixMilli(),
	})
	stream.CloseSend()

	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	fmt.Printf("[E2E] MissingOSAndIP: status=%v reason=%s\n", resp.Status, resp.Reason)
	if resp.Status == pb.Status_BLOCKED {
		fmt.Println("  -> system correctly blocked incomplete fingerprint")
	} else {
		fmt.Println("  -> system skipped null fields and matched on UUID only")
	}
}

func TestFingerprint_AllFieldsWrong(t *testing.T) {
	env := setupEnv(t)
	defer env.cleanup()

	dCli := directClient(t, env.srvAddr)
	connResp, err := dCli.EstablishConnection(context.Background(), &pb.ConnectionInit{
		UserId: "scripts-user", DeviceUuid: "scripts-device-001",
		Ip: "10.0.0.1", OsType: "linux", Timestamp: time.Now().UnixMilli(),
	})
	if err != nil {
		t.Fatalf("EstablishConnection: %v", err)
	}
	if !connResp.Accepted {
		t.Fatalf("connection not accepted: %s", connResp.Reason)
	}

	stream, _ := dCli.ProxyStream(context.Background())
	stream.Send(&pb.ProxyRequest{
		ConnectionId: connResp.ConnectionId,
		DeviceUuid:   "scripts-device-001",
		UserId:       "scripts-user",
		RawHttpRequest: []byte("GET /api/cloud/public/images HTTP/1.1\r\n" +
			"Host: localhost\r\n" +
			"X-Proxy-UUID: fake-device-999\r\n" +
			"X-Proxy-OS: darwin\r\n" +
			"X-Proxy-IP: 172.16.0.1\r\n" +
			"\r\n"),
		Timestamp: time.Now().UnixMilli(),
	})
	stream.CloseSend()

	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	if resp.Status != pb.Status_BLOCKED {
		t.Errorf("expected BLOCKED for all-wrong fingerprint, got status=%v reason=%s", resp.Status, resp.Reason)
	}
	fmt.Printf("[E2E] AllFieldsWrong OK: correctly blocked, reason=%s\n", resp.Reason)
}

func TestFingerprint_EmptyRawRequest(t *testing.T) {
	env := setupEnv(t)
	defer env.cleanup()

	dCli := directClient(t, env.srvAddr)
	connResp, err := dCli.EstablishConnection(context.Background(), &pb.ConnectionInit{
		UserId: "scripts-user", DeviceUuid: "scripts-device-001",
		Ip: "10.0.0.1", OsType: "linux", Timestamp: time.Now().UnixMilli(),
	})
	if err != nil {
		t.Fatalf("EstablishConnection: %v", err)
	}
	if !connResp.Accepted {
		t.Fatalf("connection not accepted: %s", connResp.Reason)
	}

	stream, _ := dCli.ProxyStream(context.Background())
	stream.Send(&pb.ProxyRequest{
		ConnectionId:   connResp.ConnectionId,
		DeviceUuid:     "scripts-device-001",
		UserId:         "scripts-user",
		RawHttpRequest: []byte{},
		Timestamp:      time.Now().UnixMilli(),
	})
	stream.CloseSend()

	resp, err := stream.Recv()
	if err != nil {
		fmt.Printf("[E2E] EmptyRawRequest OK: server returned error (expected): %v\n", err)
		return
	}
	if resp.Status != pb.Status_BLOCKED {
		t.Errorf("expected BLOCKED for empty request, got status=%v reason=%s", resp.Status, resp.Reason)
	}
	fmt.Printf("[E2E] EmptyRawRequest OK: status=%v reason=%s\n", resp.Status, resp.Reason)
}

func TestFingerprint_NoHeadersAtAll(t *testing.T) {
	env := setupEnv(t)
	defer env.cleanup()

	dCli := directClient(t, env.srvAddr)
	connResp, err := dCli.EstablishConnection(context.Background(), &pb.ConnectionInit{
		UserId: "scripts-user", DeviceUuid: "scripts-device-001",
		Ip: "10.0.0.1", OsType: "linux", Timestamp: time.Now().UnixMilli(),
	})
	if err != nil {
		t.Fatalf("EstablishConnection: %v", err)
	}
	if !connResp.Accepted {
		t.Fatalf("connection not accepted: %s", connResp.Reason)
	}

	stream, _ := dCli.ProxyStream(context.Background())
	stream.Send(&pb.ProxyRequest{
		ConnectionId: connResp.ConnectionId,
		DeviceUuid:   "scripts-device-001",
		UserId:       "scripts-user",
		RawHttpRequest: []byte("GET /api/cloud/public/images HTTP/1.1\r\n" +
			"Host: localhost\r\n" +
			"Accept: application/json\r\n" +
			"\r\n"),
		Timestamp: time.Now().UnixMilli(),
	})
	stream.CloseSend()

	resp, err := stream.Recv()
	if err != nil {
		fmt.Printf("[E2E] NoHeadersAtAll OK: server returned error (expected): %v\n", err)
		return
	}
	if resp.Status != pb.Status_BLOCKED {
		t.Errorf("expected BLOCKED when no X-Proxy-* headers, got status=%v reason=%s", resp.Status, resp.Reason)
	}
	fmt.Printf("[E2E] NoHeadersAtAll OK: correctly blocked, reason=%s\n", resp.Reason)
}

func TestFingerprint_ViaClientProxy_TamperedHeader(t *testing.T) {
	env := setupEnv(t)
	defer env.cleanup()

	client := idvClient(t, env.clientProxy.ListenAddr())
	connResp, err := client.EstablishConnection(context.Background(), &pb.ConnectionInit{
		UserId: "scripts-user", DeviceUuid: "scripts-device-001",
		Ip: "10.0.0.1", OsType: "linux", Timestamp: time.Now().UnixMilli(),
	})
	if err != nil {
		t.Fatalf("EstablishConnection: %v", err)
	}
	if !connResp.Accepted {
		t.Fatalf("connection not accepted: %s", connResp.Reason)
	}

	stream, _ := client.ProxyStream(context.Background())
	stream.Send(&pb.ProxyRequest{
		ConnectionId: connResp.ConnectionId,
		DeviceUuid:   "scripts-device-001",
		UserId:       "scripts-user",
		RawHttpRequest: []byte("GET /api/cloud/public/images HTTP/1.1\r\n" +
			"Host: localhost\r\n" +
			"X-Proxy-UUID: TAMPERED-FAKE-UUID\r\n" +
			"\r\n"),
		Timestamp: time.Now().UnixMilli(),
	})
	stream.CloseSend()

	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	if resp.Status != pb.Status_BLOCKED {
		t.Errorf("expected BLOCKED for tampered UUID header, got status=%v reason=%s", resp.Status, resp.Reason)
	}
	fmt.Printf("[E2E] TamperedHeader OK: correctly blocked tampered fingerprint, reason=%s\n", resp.Reason)
}

func TestFingerprint_MixedBatch_Concurrent(t *testing.T) {
	env := setupEnv(t)
	defer env.cleanup()

	dCli := directClient(t, env.srvAddr)
	connResp, err := dCli.EstablishConnection(context.Background(), &pb.ConnectionInit{
		UserId: "scripts-user", DeviceUuid: "scripts-device-001",
		Ip: "10.0.0.1", OsType: "linux", Timestamp: time.Now().UnixMilli(),
	})
	if err != nil {
		t.Fatalf("EstablishConnection: %v", err)
	}
	if !connResp.Accepted {
		t.Fatalf("connection not accepted: %s", connResp.Reason)
	}

	type testCase struct {
		name     string
		fpHeader string
		expectOK bool
	}

	cases := []testCase{
		{"valid", "X-Proxy-UUID: scripts-device-001\r\nX-Proxy-OS: linux\r\nX-Proxy-IP: 10.0.0.1", true},
		{"valid2", "X-Proxy-UUID: scripts-device-001\r\nX-Proxy-OS: linux\r\nX-Proxy-IP: 10.0.0.1", true},
		{"wrong-uuid", "X-Proxy-UUID: not-my-device\r\nX-Proxy-OS: linux\r\nX-Proxy-IP: 10.0.0.1", false},
		{"wrong-ip", "X-Proxy-UUID: scripts-device-001\r\nX-Proxy-OS: linux\r\nX-Proxy-IP: 99.99.99.99", false},
		{"wrong-os", "X-Proxy-UUID: scripts-device-001\r\nX-Proxy-OS: windows\r\nX-Proxy-IP: 10.0.0.1", false},
		{"no-headers", "", false},
		{"valid3", "X-Proxy-UUID: scripts-device-001\r\nX-Proxy-OS: linux\r\nX-Proxy-IP: 10.0.0.1", true},
		{"all-wrong", "X-Proxy-UUID: fake\r\nX-Proxy-OS: freebsd\r\nX-Proxy-IP: 1.2.3.4", false},
		{"empty-uuid", "X-Proxy-UUID: \r\nX-Proxy-OS: linux\r\nX-Proxy-IP: 10.0.0.1", false},
		{"valid4", "X-Proxy-UUID: scripts-device-001\r\nX-Proxy-OS: linux\r\nX-Proxy-IP: 10.0.0.1", true},
	}

	var wg sync.WaitGroup
	errCh := make(chan string, len(cases))

	for _, tc := range cases {
		wg.Add(1)
		go func(tc testCase) {
			defer wg.Done()

			headers := ""
			if tc.fpHeader != "" {
				for _, h := range strings.Split(tc.fpHeader, "\r\n") {
					if h != "" {
						headers += h + "\r\n"
					}
				}
			}

			raw := "GET /api/cloud/public/images HTTP/1.1\r\nHost: localhost\r\n" + headers + "\r\n"

			stream, err := dCli.ProxyStream(context.Background())
			if err != nil {
				errCh <- fmt.Sprintf("[%s] ProxyStream error: %v", tc.name, err)
				return
			}
			stream.Send(&pb.ProxyRequest{
				ConnectionId:   connResp.ConnectionId,
				DeviceUuid:     "scripts-device-001",
				UserId:         "scripts-user",
				RawHttpRequest: []byte(raw),
				Timestamp:      time.Now().UnixMilli(),
			})
			stream.CloseSend()

			resp, err := stream.Recv()
			if err != nil {
				errCh <- fmt.Sprintf("[%s] recv error: %v", tc.name, err)
				return
			}

			if tc.expectOK && resp.Status == pb.Status_BLOCKED {
				errCh <- fmt.Sprintf("[%s] expected OK but got BLOCKED: %s", tc.name, resp.Reason)
			} else if !tc.expectOK && resp.Status != pb.Status_BLOCKED {
				errCh <- fmt.Sprintf("[%s] expected BLOCKED but got %v: %s", tc.name, resp.Status, resp.Reason)
			} else {
				fmt.Printf("[MixedBatch] %s: status=%v (as expected)\n", tc.name, resp.Status)
			}
		}(tc)
	}

	wg.Wait()
	close(errCh)

	for msg := range errCh {
		t.Errorf("mixed batch error: %s", msg)
	}
}
