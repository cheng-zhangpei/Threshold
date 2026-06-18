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
	log.Printf("[SOCKS5] handleConn called") // 新增

	// 1. SOCKS5 握手
	if err := Handshake(conn, conn); err != nil {
		log.Printf("[SOCKS5] handshake error: %v", err)
		return
	}

	// 2. 解析 CONNECT 请求
	targetAddr, err := ParseRequest(conn)
	if err != nil {
		log.Printf("[SOCKS5] parse request error: %v", err)
		return
	}
	log.Printf("[SOCKS5] target: %s", targetAddr)

	// 3. 建立 gRPC 连接
	connID, err := g.establishGRPCConnection(targetAddr)
	if err != nil {
		log.Printf("[SOCKS5] establish grpc error: %v", err)
		// 返回 SOCKS5 通用错误
		sendSOCKS5Error(conn, repFailure)
		return
	}
	defer g.closeGRPCConnection(connID)

	// 4. 创建 ProxyStream
	stream, err := g.client.ProxyStream(context.Background())
	if err != nil {
		log.Printf("[SOCKS5] create stream error: %v", err)
		sendSOCKS5Error(conn, repFailure)
		return
	}

	// 5. 回复 SOCKS5 连接成功（先告诉客户端连接已建立，但业务结果看后面的响应）
	if err := SendSuccessResponse(conn); err != nil {
		log.Printf("[SOCKS5] send success response error: %v", err)
		return
	}

	// 6. 双向转发
	errChan := make(chan error, 2)

	// 6a. conn -> gRPC stream
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				req := &pb.ProxyRequest{
					ConnectionId:   connID,
					RawHttpRequest: buf[:n],
				}
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

	// 6b. gRPC stream -> conn（根据 Status 处理）
	go func() {
		for {
			resp, err := stream.Recv()
			if err != nil {
				errChan <- err
				return
			}

			// 根据响应状态处理
			switch resp.Status {
			case pb.Status_OK:
				// 正常响应，写回数据
				if resp.RawHttpResponse != nil && len(resp.RawHttpResponse) > 0 {
					if _, writeErr := conn.Write(resp.RawHttpResponse); writeErr != nil {
						errChan <- writeErr
						return
					}
				}
				// 如果响应为空（如 HEAD 请求），继续等待下一个请求
				log.Printf("[SOCKS5] connection %s: OK response sent", connID)

			case pb.Status_BLOCKED, pb.Status_BLACKLISTED:
				// 阻断：发送 SOCKS5 错误并关闭连接
				log.Printf("[SOCKS5] connection %s: %s, reason: %s", connID, resp.Status, resp.Reason)
				sendSOCKS5Error(conn, repFailure)
				errChan <- fmt.Errorf("blocked: %s", resp.Reason)
				return

			case pb.Status_RATE_LIMITED:
				// 限流：可返回 SOCKS5 错误，也可尝试重试（简单处理：直接关闭）
				log.Printf("[SOCKS5] connection %s: rate limited, reason: %s", connID, resp.Reason)
				sendSOCKS5Error(conn, repFailure)
				errChan <- fmt.Errorf("rate limited: %s", resp.Reason)
				return

			default:
				log.Printf("[SOCKS5] connection %s: unknown status %v, closing", connID, resp.Status)
				sendSOCKS5Error(conn, repFailure)
				errChan <- fmt.Errorf("unknown status: %v", resp.Status)
				return
			}
		}
	}()

	// 等待任一端关闭
	<-errChan
	log.Printf("[SOCKS5] connection %s closed", connID)
}

// sendSOCKS5Error 发送 SOCKS5 错误响应
func sendSOCKS5Error(conn net.Conn, rep byte) {
	// VER=5, REP=rep, RSV=0, ATYP=1 (IPv4), BND.ADDR=0.0.0.0, BND.PORT=0
	resp := []byte{
		0x05, rep, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,
	}
	conn.Write(resp)
}
func (g *Gateway) establishGRPCConnection(targetAddr string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := &pb.ConnectionInit{
		UserId:     g.userID,
		DeviceUuid: g.deviceUUID,
		OsType:     g.osType,
		Ip:         g.localIP,
		Timestamp:  time.Now().UnixMilli(),
		Protocol:   "tcp",
		TargetAddr: targetAddr,
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
