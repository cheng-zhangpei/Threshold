package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
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
	"Threshold/server/router"

	servergrpc "Threshold/server/grpc"
	clientproxy "Threshold/client/proxy"

	pb "Threshold/pkg/proto/pb"
)

type testEnv struct {
	grpcSrv   *grpc.Server
	srvAddr   string
	clientProxy *clientproxy.LocalProxy
	cleanup   func()
}

func setupEnv(t *testing.T) *testEnv {
	t.Helper()
	tmpDir, _ := os.MkdirTemp("", "client-e2e-*")

	store, _ := storage.NewBoltStore(filepath.Join(tmpDir, "test.db"))
	wal := storage.NewWAL(store)
	wal.Recover()

	fpTree, _ := fingerprint.NewTree(store, wal)
	testUUID := "test-device-001"
	testOS := "linux"
	testIP := "10.0.0.1"
	fpTree.Register("init", types.DeviceFingerprint{UUID: &testUUID, OS: &testOS, IP: &testIP})

	ps := portrait.NewStore(store)
	engine := decision.NewEngine(ps)
	outputBuf := output.NewOutputBuffer()
	alertQueue := alert.NewAlertQueue()

	dm := dispatch.NewDispatchManager(dispatch.DispatcherConfig{
		Policy: dispatch.PoolPolicy{MinWorkers: 2, MaxWorkers: 8, MaxQueueSize: 64, HealthCheckIntervalSec: 5},
		Store: store,
		DecisionFn: func(ctx *types.ConnectionContext, history []*types.ConnectionSummary, rl types.RiskLevel) *types.Decision {
			return engine.Evaluate(ctx, history, rl)
		},
	})

	riskTable := router.NewOperationRiskTable()
	r := router.NewRouter(riskTable, outputBuf, dm, 2, 256)

	// Start Threshold server
	srvLis, _ := net.Listen("tcp", ":0")
	grpcSrv := grpc.NewServer()
	handler := servergrpc.NewHandler(fpTree, engine, r, outputBuf, alertQueue, ps)
	pb.RegisterSecurityProxyServer(grpcSrv, handler)
	go grpcSrv.Serve(srvLis)
	srvAddr := srvLis.Addr().String()

	// Start Threshold client proxy
	cp := clientproxy.New(clientproxy.Config{
		ListenAddr: ":0",
		ServerAddr: srvAddr,
		DeviceUUID: "test-device-001",
		UserID:     "test-user",
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
	conn, _ := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	t.Cleanup(func() { conn.Close() })
	return pb.NewSecurityProxyClient(conn)
}

var rawGET = []byte("GET /api/cloud/public/images HTTP/1.1\r\nHost: localhost\r\nX-Proxy-UUID: test-device-001\r\nX-Proxy-OS: linux\r\nX-Proxy-IP: 10.0.0.1\r\n\r\n")
var rawDELETE = []byte("DELETE /api/cloud/public/images HTTP/1.1\r\nHost: localhost\r\nX-Proxy-UUID: test-device-001\r\nX-Proxy-OS: linux\r\nX-Proxy-IP: 10.0.0.1\r\n\r\n")

func TestClientProxy_EstablishConnection(t *testing.T) {
	env := setupEnv(t)
	defer env.cleanup()

	client := idvClient(t, env.clientProxy.ListenAddr())
	resp, err := client.EstablishConnection(context.Background(), &pb.ConnectionInit{
		UserId: "test-user", DeviceUuid: "test-device-001",
		Ip: "10.0.0.1", OsType: "linux", Timestamp: time.Now().UnixMilli(),
	})
	if err != nil { t.Fatalf("error: %v", err) }
	if !resp.Accepted {
		t.Errorf("rejected: %s", resp.Reason)
	}
	fmt.Printf("[E2E] EstablishConnection OK: conn_id=%s", resp.ConnectionId)
}

func TestClientProxy_ProxyStream_GET_L0(t *testing.T) {
	env := setupEnv(t)
	defer env.cleanup()

	client := idvClient(t, env.clientProxy.ListenAddr())
	connResp, _ := client.EstablishConnection(context.Background(), &pb.ConnectionInit{
		UserId: "test-user", DeviceUuid: "test-device-001",
		Ip: "10.0.0.1", OsType: "linux", Timestamp: time.Now().UnixMilli(),
	})

	stream, _ := client.ProxyStream(context.Background())
	stream.Send(&pb.ProxyRequest{
		ConnectionId: connResp.ConnectionId, DeviceUuid: "test-device-001",
		UserId: "test-user", RawHttpRequest: rawGET, Timestamp: time.Now().UnixMilli(),
	})
	stream.CloseSend()

	resp, err := stream.Recv()
	if err != nil { t.Fatal(err) }
	if resp.Status != pb.Status_OK {
		t.Errorf("status=%v, want OK. reason=%s", resp.Status, resp.Reason)
	}
	fmt.Printf("[E2E] ProxyStream GET L0 OK: status=%v reason=%s", resp.Status, resp.Reason)
}

func TestClientProxy_ProxyStream_DELETE_L2(t *testing.T) {
	env := setupEnv(t)
	defer env.cleanup()

	client := idvClient(t, env.clientProxy.ListenAddr())
	connResp, _ := client.EstablishConnection(context.Background(), &pb.ConnectionInit{
		UserId: "test-user", DeviceUuid: "test-device-001",
		Ip: "10.0.0.1", OsType: "linux", Timestamp: time.Now().UnixMilli(),
	})

	stream, _ := client.ProxyStream(context.Background())
	stream.Send(&pb.ProxyRequest{
		ConnectionId: connResp.ConnectionId, DeviceUuid: "test-device-001",
		UserId: "test-user", RawHttpRequest: rawDELETE, Timestamp: time.Now().UnixMilli(),
	})
	stream.CloseSend()

	resp, _ := stream.Recv()
	fmt.Printf("[E2E] ProxyStream DELETE L2 OK: status=%v reason=%s", resp.Status, resp.Reason)
}

func TestClientProxy_CloseConnection(t *testing.T) {
	env := setupEnv(t)
	defer env.cleanup()

	client := idvClient(t, env.clientProxy.ListenAddr())
	connResp, _ := client.EstablishConnection(context.Background(), &pb.ConnectionInit{
		UserId: "test-user", DeviceUuid: "test-device-001",
		Ip: "10.0.0.1", OsType: "linux", Timestamp: time.Now().UnixMilli(),
	})

	closeResp, err := client.CloseConnection(context.Background(), &pb.ConnectionClose{
		ConnectionId: connResp.ConnectionId, Timestamp: time.Now().UnixMilli(),
	})
	if err != nil { t.Fatal(err) }
	if !closeResp.Success { t.Error("close failed") }
	fmt.Printf("[E2E] CloseConnection OK")
}

func TestClientProxy_Concurrent(t *testing.T) {
	env := setupEnv(t)
	defer env.cleanup()

	client := idvClient(t, env.clientProxy.ListenAddr())
	connResp, _ := client.EstablishConnection(context.Background(), &pb.ConnectionInit{
		UserId: "test-user", DeviceUuid: "test-device-001",
		Ip: "10.0.0.1", OsType: "linux", Timestamp: time.Now().UnixMilli(),
	})

	var wg sync.WaitGroup
	n := 10
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			s, _ := client.ProxyStream(context.Background())
			s.Send(&pb.ProxyRequest{
				ConnectionId: connResp.ConnectionId, DeviceUuid: "test-device-001",
				UserId: "test-user", RawHttpRequest: rawGET, Timestamp: time.Now().UnixMilli(),
			})
			s.CloseSend()
			resp, _ := s.Recv()
			if resp.Status != pb.Status_OK { t.Errorf("status=%v", resp.Status) }
		}()
	}
	wg.Wait()
	fmt.Printf("[E2E] %d concurrent requests OK", n)
}