package main

import (
	"Threshold/server/router/router_v1"
	"Threshold/server/router/router_v2"
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

	pb "Threshold/pkg/proto/pb"
	servergrpc "Threshold/server/grpc"
)

// ============================================================
// 集成测试：完整 server 启动 + gRPC client 端到端联调
// ============================================================

type testEnv struct {
	client  pb.SecurityProxyClient
	grpcSrv *grpc.Server
	conn    *grpc.ClientConn
	store   storage.Store
	output  *output.OutputBuffer
	alert   *alert.AlertQueue
}

func setupTestEnv(t *testing.T) *testEnv {
	t.Helper()

	tmpDir, _ := os.MkdirTemp("", "server-integration-*")
	t.Cleanup(func() { os.RemoveAll(tmpDir) })

	store, err := storage.NewBoltStore(filepath.Join(tmpDir, "scripts.db"))
	if err != nil {
		t.Fatal(err)
	}
	wal := storage.NewWAL(store)
	wal.Recover()

	fpTree, err := fingerprint.NewTree(store, wal)
	if err != nil {
		t.Fatal(err)
	}

	testUUID := "scripts-device-uuid-001"
	testOS := "linux"
	testIP := "10.0.0.1"
	fp := types.DeviceFingerprint{UUID: &testUUID, OS: &testOS, IP: &testIP}
	if err := fpTree.Register("init-conn", fp); err != nil {
		t.Fatalf("register fingerprint: %v", err)
	}

	ps := portrait.NewStore(store)
	engine := decision.NewEngine(ps)
	outputBuf := output.NewOutputBuffer()
	alertQueue := alert.NewAlertQueue()

	dm := dispatch.NewDispatchManager(dispatch.DispatcherConfig{
		Policy: dispatch.PoolPolicy{
			MinWorkers:             2,
			MaxWorkers:             8,
			MaxQueueSize:           64,
			HealthCheckIntervalSec: 5,
		},
		Store: store,
		DecisionFn: func(ctx *types.ConnectionContext, history []*types.ConnectionSummary, riskLevel types.RiskLevel) *types.Decision {
			return engine.Evaluate(ctx, history, riskLevel)
		},
	})

	riskTable := router_v1.NewOperationRiskTable()
	r := router_v1.NewRouter(riskTable, outputBuf, dm, 2, 256)
	var r2 *router_v2.Router = nil
	grpcSrv := grpc.NewServer()
	handler := servergrpc.NewHandler(fpTree, engine, r, r2, outputBuf, alertQueue, ps)
	pb.RegisterSecurityProxyServer(grpcSrv, handler)

	lis, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	go grpcSrv.Serve(lis)
	t.Cleanup(func() {
		grpcSrv.GracefulStop()
		r.Shutdown()
		dm.Shutdown()
		store.Close()
	})

	conn, err := grpc.NewClient(
		lis.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })

	client := pb.NewSecurityProxyClient(conn)
	return &testEnv{client: client, grpcSrv: grpcSrv, conn: conn, store: store, output: outputBuf, alert: alertQueue}
}

func testFingerprintHeaders() []byte {
	return []byte("GET /api/cloud/public/images HTTP/1.1\r\nHost: localhost\r\nX-Proxy-UUID: scripts-device-uuid-001\r\nX-Proxy-OS: linux\r\nX-Proxy-IP: 10.0.0.1\r\n\r\n")
}

func testConnInit() *pb.ConnectionInit {
	return &pb.ConnectionInit{
		UserId:     "scripts-user",
		DeviceUuid: "scripts-device-uuid-001",
		Ip:         "10.0.0.1",
		OsType:     "linux",
		Timestamp:  time.Now().UnixMilli(),
	}
}

func TestIntegration_EstablishConnection(t *testing.T) {
	e := setupTestEnv(t)
	resp, err := e.client.EstablishConnection(context.Background(), testConnInit())
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if !resp.Accepted {
		t.Errorf("rejected: %s", resp.Reason)
	}
	fmt.Printf("EstablishConnection OK: conn_id=%s\n", resp.ConnectionId)
}

func TestIntegration_EstablishConnection_Rejected(t *testing.T) {
	e := setupTestEnv(t)
	resp, _ := e.client.EstablishConnection(context.Background(), &pb.ConnectionInit{
		UserId: "user-002", DeviceUuid: "unknown-device-uuid",
		Ip: "10.0.0.99", OsType: "windows", Timestamp: time.Now().UnixMilli(),
	})
	if resp.Accepted {
		t.Error("unknown device should be rejected")
	}
}

func TestIntegration_ProxyStream_GET_L0(t *testing.T) {
	e := setupTestEnv(t)
	connResp, _ := e.client.EstablishConnection(context.Background(), testConnInit())

	stream, _ := e.client.ProxyStream(context.Background())
	stream.Send(&pb.ProxyRequest{
		ConnectionId: connResp.ConnectionId, DeviceUuid: "scripts-device-uuid-001",
		UserId: "scripts-user", RawHttpRequest: testFingerprintHeaders(), Timestamp: time.Now().UnixMilli(),
	})

	resp, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != pb.Status_OK {
		t.Errorf("status = %v, want OK", resp.Status)
	}
	fmt.Printf("GET L0 OK: status=%v reason=%s\n", resp.Status, resp.Reason)
}

func TestIntegration_ProxyStream_DELETE_L2(t *testing.T) {
	e := setupTestEnv(t)
	connResp, _ := e.client.EstablishConnection(context.Background(), testConnInit())

	stream, _ := e.client.ProxyStream(context.Background())
	rawHTTP := []byte("DELETE /api/cloud/public/images HTTP/1.1\r\nHost: localhost\r\nX-Proxy-UUID: scripts-device-uuid-001\r\nX-Proxy-OS: linux\r\nX-Proxy-IP: 10.0.0.1\r\n\r\n")
	stream.Send(&pb.ProxyRequest{
		ConnectionId: connResp.ConnectionId, DeviceUuid: "scripts-device-uuid-001",
		UserId: "scripts-user", RawHttpRequest: rawHTTP, Timestamp: time.Now().UnixMilli(),
	})

	resp, _ := stream.Recv()
	fmt.Printf("DELETE L2 OK: status=%v reason=%s\n", resp.Status, resp.Reason)
}

func TestIntegration_ProxyStream_FingerprintMismatch(t *testing.T) {
	e := setupTestEnv(t)
	connResp, _ := e.client.EstablishConnection(context.Background(), testConnInit())

	stream, _ := e.client.ProxyStream(context.Background())
	rawHTTP := []byte("GET /api/cloud/public/images HTTP/1.1\r\nHost: localhost\r\nX-Proxy-UUID: wrong-device-uuid\r\nX-Proxy-OS: linux\r\nX-Proxy-IP: 10.0.0.1\r\n\r\n")
	stream.Send(&pb.ProxyRequest{
		ConnectionId: connResp.ConnectionId, DeviceUuid: "scripts-device-uuid-001",
		UserId: "scripts-user", RawHttpRequest: rawHTTP, Timestamp: time.Now().UnixMilli(),
	})

	resp, _ := stream.Recv()
	if resp.Status != pb.Status_BLOCKED {
		t.Errorf("status = %v, want BLOCKED", resp.Status)
	}
	fmt.Printf("Fingerprint Mismatch OK: status=%v\n", resp.Status)
}

func TestIntegration_PullApproved(t *testing.T) {
	e := setupTestEnv(t)
	connResp, _ := e.client.EstablishConnection(context.Background(), testConnInit())

	// 发送 GET 请求 -> L0 -> OutputBuffer
	stream, _ := e.client.ProxyStream(context.Background())
	for i := 0; i < 3; i++ {
		stream.Send(&pb.ProxyRequest{
			ConnectionId: connResp.ConnectionId, DeviceUuid: "scripts-device-uuid-001",
			UserId: "scripts-user", RawHttpRequest: testFingerprintHeaders(), Timestamp: time.Now().UnixMilli(),
		})
		stream.Recv()
	}
	stream.CloseSend()

	time.Sleep(200 * time.Millisecond)

	// PullApproved: 发送请求后 CloseSend，服务端收到 EOF 退出循环
	pullStream, err := e.client.PullApproved(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	pullStream.Send(&pb.PullRequest{SubscriberId: "scripts-sub", BatchSize: 10, Timestamp: time.Now().UnixMilli()})
	pullStream.CloseSend()

	count := 0
	for {
		msg, err := pullStream.Recv()
		if err != nil {
			break
		}
		count++
		fmt.Printf("PullApproved msg[%d]: action=%s reason=%s\n", count, msg.DecisionAction, msg.DecisionReason)
	}
	if count == 0 {
		t.Error("PullApproved got 0 messages")
	}
	fmt.Printf("PullApproved total: %d messages\n", count)
}

func TestIntegration_CloseConnection(t *testing.T) {
	e := setupTestEnv(t)
	connResp, _ := e.client.EstablishConnection(context.Background(), testConnInit())

	closeResp, err := e.client.CloseConnection(context.Background(), &pb.ConnectionClose{
		ConnectionId: connResp.ConnectionId, Timestamp: time.Now().UnixMilli(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !closeResp.Success {
		t.Error("CloseConnection failed")
	}
	fmt.Printf("CloseConnection OK\n")
}

func TestIntegration_ConcurrentProxyStream(t *testing.T) {
	e := setupTestEnv(t)
	connResp, _ := e.client.EstablishConnection(context.Background(), testConnInit())

	var wg sync.WaitGroup
	n := 20
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			stream, err := e.client.ProxyStream(context.Background())
			if err != nil {
				t.Errorf("error: %v", err)
				return
			}
			stream.Send(&pb.ProxyRequest{
				ConnectionId: connResp.ConnectionId, DeviceUuid: "scripts-device-uuid-001",
				UserId: "scripts-user", RawHttpRequest: testFingerprintHeaders(), Timestamp: time.Now().UnixMilli(),
			})
			resp, _ := stream.Recv()
			if resp.Status != pb.Status_OK {
				t.Errorf("status = %v, want OK", resp.Status)
			}
		}()
	}
	wg.Wait()
	fmt.Printf("ConcurrentProxyStream: %d requests OK\n", n)
}
