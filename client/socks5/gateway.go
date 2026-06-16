// client/socks5/gateway.go
package socks5

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	pb "Threshold/pkg/proto/pb"
)

type Gateway struct {
	listenAddr string
	userID     string
	deviceUUID string
	osType     string
	localIP    string
	client     pb.SecurityProxyClient
	ctx        context.Context
}

func NewGateway(listenAddr, userID, deviceUUID, osType, localIP string, client pb.SecurityProxyClient) *Gateway {
	return &Gateway{
		listenAddr: listenAddr,
		userID:     userID,
		deviceUUID: deviceUUID,
		osType:     osType,
		localIP:    localIP,
		client:     client,
	}
}

// Start 启动 SOCKS5 监听
func (g *Gateway) Start() error {
	lis, err := net.Listen("tcp", g.listenAddr)
	if err != nil {
		return err
	}
	log.Printf("[SOCKS5] listening on %s", g.listenAddr)

	for {
		conn, err := lis.Accept()
		log.Println("[SOCKS5] accepting connection")
		if err != nil {
			log.Printf("[SOCKS5] accept error: %v", err)
			continue
		}
		go g.handleConn(conn)
	}
}

func (g *Gateway) handleConn(conn net.Conn) {
	defer conn.Close()

	// 1. SOCKS5 握手
	if err := Handshake(conn, conn); err != nil {
		log.Printf("[SOCKS5] handshake error: %v", err)
		return
	}

	// 2. 解析 CONNECT 请求（拿到目标地址，暂存备用）
	targetAddr, err := ParseRequest(conn)
	if err != nil {
		log.Printf("[SOCKS5] parse request error: %v", err)
		return
	}
	log.Printf("[SOCKS5] target: %s", targetAddr)

	// 3. 建立 gRPC 连接（调用 EstablishConnection）
	connID, err := g.establishGRPCConnection()
	if err != nil {
		log.Printf("[SOCKS5] establish grpc error: %v", err)
		return
	}
	log.Printf("[SOCKS5] grpc connection established: %s", connID)
	defer g.closeGRPCConnection(connID)

	// 4. 创建 ProxyStream 双向流
	stream, err := g.client.ProxyStream(context.Background())
	if err != nil {
		log.Printf("[SOCKS5] create stream error: %v", err)
		return
	}

	// 5. 回复 SOCKS5 连接成功
	if err := SendSuccessResponse(conn); err != nil {
		log.Printf("[SOCKS5] send success response error: %v", err)
		return
	}

	// 6. 双向转发
	errChan := make(chan error, 2)

	// 6a. conn -> gRPC stream
	go func() {
		buf := make([]byte, 32*1024) // 32KB buffer
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				req := &pb.ProxyRequest{
					ConnectionId:   connID,
					RawHttpRequest: buf[:n],
					// 其他字段可省略，服务端从 ConnectionInit 已获取
				}
				log.Printf("[SOCKS5] proxy request: %v, sending to the grpc proxy", req)
				if sendErr := stream.Send(req); sendErr != nil {
					errChan <- sendErr
					return
				}
			}
			if err != nil {
				errChan <- err
				return
			}
		}
	}()

	// 6b. gRPC stream -> conn
	go func() {
		for {
			resp, err := stream.Recv()
			if err != nil {
				errChan <- err
				return
			}
			if resp.GetRawHttpResponse() != nil {
				if _, writeErr := conn.Write(resp.GetRawHttpResponse()); writeErr != nil {
					errChan <- writeErr
					return
				}
			}
		}
	}()

	// 等待任一端关闭
	<-errChan
	log.Printf("[SOCKS5] connection %s closed", connID)
}

func (g *Gateway) establishGRPCConnection() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := &pb.ConnectionInit{
		UserId:     g.userID,
		DeviceUuid: g.deviceUUID,
		OsType:     g.osType,
		Ip:         g.localIP,
		Timestamp:  time.Now().UnixMilli(),
		Protocol:   "tcp",
	}
	resp, err := g.client.EstablishConnection(ctx, req)
	if err != nil {
		return "", err
	}
	if !resp.Accepted {
		return "", fmt.Errorf("connection rejected: %s", resp.Reason)
	}
	return resp.ConnectionId, nil
}

func (g *Gateway) closeGRPCConnection(connID string) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	req := &pb.ConnectionClose{
		ConnectionId: connID,
		Timestamp:    time.Now().UnixMilli(),
	}
	if _, err := g.client.CloseConnection(ctx, req); err != nil {
		log.Printf("[SOCKS5] close connection error: %v", err)
	}
}
