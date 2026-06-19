package tcplistener

import (
	"Threshold/pkg/types"
	"Threshold/server/dispatch"
	"Threshold/server/portrait"
	"Threshold/server/router/router_v2"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"time"
)

// ============================================================
// 配置与接口
// ============================================================

// Config 直连模式配置
type Config struct {
	Enabled    bool
	ListenAddr string
	CertFile   string
	KeyFile    string
}

// FingerMatcher 指纹匹配接口（与 fingerprint.Tree.Match 签名一致）
type FingerMatcher interface {
	Match(fp types.DeviceFingerprint) bool
}

// AlertSender 告警接口
type AlertSender interface {
	PutSimple(deviceUUID string, reason string)
}

// ============================================================
// Deps 外部依赖（全部可 nil）
// ============================================================

// Deps Mode 3 直连模式所需的外部组件
type Deps struct {
	Router   *router_v2.Router
	DM       *dispatch.DispatchManager
	Portrait *portrait.Store
}

// ============================================================
// Listener
// ============================================================

// Listener Mode 3 TCP+TLS 直连监听器
type Listener struct {
	cfg   Config
	fp    FingerMatcher
	alert AlertSender
	deps  Deps
}

// New 创建 Listener
func New(cfg Config, fp FingerMatcher, alert AlertSender, deps Deps) *Listener {
	return &Listener{cfg: cfg, fp: fp, alert: alert, deps: deps}
}

// Start 启动 TLS 监听，阻塞运行
func (l *Listener) Start() error {
	cert, err := tls.LoadX509KeyPair(l.cfg.CertFile, l.cfg.KeyFile)
	if err != nil {
		return fmt.Errorf("load TLS certs: %w", err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	ln, err := tls.Listen("tcp", l.cfg.ListenAddr, tlsCfg)
	if err != nil {
		return fmt.Errorf("tls listen on %s: %w", l.cfg.ListenAddr, err)
	}
	defer ln.Close()

	log.Printf("[tcplistener] listening on %s (TLS)", l.cfg.ListenAddr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("[tcplistener] accept error: %v", err)
			continue
		}
		go l.handle(conn.(*tls.Conn))
	}
}

// ============================================================
// handle 单连接处理（完整安全决策链路）
//
// 流程:
//
//	① TLS 握手
//	② 读取并解析握手包 → 设备 UUID + 真实目标地址
//	③ 指纹校验
//	④ 握手响应
//	⑤ 请求循环:
//	   读帧 → 解析为 ParsedRequest → Router 分级
//	   → L0 直通 OutputBuffer / L1-L3 交 DispatchManager
//	   → 阻断则返回 BLOCKED
//	   → 放行则通过 Waiter 等待后端响应 → 回传给客户端
//	⑥ 连接关闭 → 画像更新
func (l *Listener) handle(conn *tls.Conn) {
	defer conn.Close()

	// ① TLS 握手
	if err := conn.Handshake(); err != nil {
		log.Printf("[tcplistener] TLS handshake failed: %v", err)
		return
	}
	remote := conn.RemoteAddr().String()
	log.Printf("[tcplistener] TLS ok, remote=%s", remote)

	// ② 读取握手包
	raw, err := readFrame(conn)
	if err != nil {
		log.Printf("[tcplistener] read handshake: %v", err)
		return
	}
	hs, err := parseHandshake(raw)
	if err != nil {
		log.Printf("[tcplistener] parse handshake: %v", err)
		writeRespFrame(conn, StatusBlocked, nil)
		return
	}
	log.Printf("[tcplistener] handshake: uuid=%s target=%s", hs.UUID, hs.Target)

	// ③ 指纹校验
	if l.fp != nil {
		host, _, _ := net.SplitHostPort(remote)
		fp := types.DeviceFingerprint{
			UUID:     strPtr(hs.UUID),
			OS:       strPtr("linux"),
			IP:       strPtr(host),
			Port:     nil,
			Protocol: nil,
			Reserved: nil,
		}
		if !l.fp.Match(fp) {
			log.Printf("[tcplistener] FINGERPRINT REJECTED uuid=%s ip=%s", hs.UUID, host)
			writeRespFrame(conn, StatusBlocked, nil)
			if l.alert != nil {
				l.alert.PutSimple(hs.UUID, "mode3 fingerprint mismatch")
			}
			return
		}
	}

	// ④ 握手响应 OK
	if err := writeRespFrame(conn, StatusOK, nil); err != nil {
		log.Printf("[tcplistener] send handshake ok: %v", err)
		return
	}

	connID := fmt.Sprintf("mode3-%s-%d", hs.UUID, time.Now().UnixNano())
	log.Printf("[tcplistener] session: connID=%s uuid=%s → %s", connID, hs.UUID, hs.Target)

	// ⑤ 请求循环
	for {
		reqData, err := readFrame(conn)
		if err != nil {
			log.Printf("[tcplistener] session end: connID=%s err=%v", connID, err)
			return
		}

		log.Printf("[tcplistener] request: %d bytes → %s", len(reqData), hs.Target)
		// 走安全决策 + 直接转发
		l.secureRoute(conn, connID, hs.UUID, hs.Target, remote, reqData)
	}
}

// closePortrait 连接关闭时更新用户画像（如果 portrait 可用）
func (l *Listener) closePortrait(connID, deviceUUID, remote string) {
	if l.deps.Portrait == nil {
		return
	}
	// portrait 更新由 PortraitStore 的 on_connection_close 逻辑处理
	// Mode 3 的连接上下文通过 DispatchManager 传入的 ConnectionContext 维护
	// 连接关闭时 PortraitStore 会自动从该上下文生成 ConnectionSummary
	log.Printf("[tcplistener] portrait update: connID=%s uuid=%s", connID, deviceUUID)
}

func strPtr(s string) *string {
	return &s
}

// ============================================================
// secureRoute 完整模式：安全决策 + 直接转发
// ============================================================
func (l *Listener) secureRoute(conn *tls.Conn, connID, deviceUUID, target, remote string, reqData []byte) {
	// ---- 解析请求 ----
	parsed, parseErr := types.ParseProxyRequest(
		connID, deviceUUID, "", time.Now().UnixMilli(), reqData,
	)
	if parseErr != nil {
		parsed = &types.ParsedRequest{
			ConnectionID: connID,
			DeviceUUID:   deviceUUID,
			UserID:       "",
			Timestamp:    time.Now(),
			Method:       "TCP",
			Path:         target,
			OpKey:        "TCP " + target,
			Body:         reqData,
			Headers:      make(map[string]string),
			TargetAddr:   target,
		}
	}

	// ---- Router 分级 ----
	riskLevel := types.L0
	if l.deps.Router != nil {
		riskLevel = l.deps.Router.Classify(parsed)
	}
	log.Printf("[tcplistener] classify: %s → risk=%v", parsed.OpKey, riskLevel)

	// ---- 非 L0: 通过 DM 入队做完整决策 ----
	if riskLevel != types.L0 && l.deps.DM != nil {
		reqID := fmt.Sprintf("%s-%d", connID, time.Now().UnixNano())
		decision := l.deps.DM.Enqueue(parsed, riskLevel, reqID)
		if decision != nil && (decision.Action == types.BLOCK ||
			decision.Action == types.BLOCK_DEVICE ||
			decision.Action == types.BLACKLIST_DEVICE) {
			writeRespFrame(conn, StatusBlocked, nil)
			if l.alert != nil {
				l.alert.PutSimple(deviceUUID, decision.Reason)
			}
			log.Printf("[tcplistener] BLOCKED: rule=%s reason=%s", decision.RuleID, decision.Reason)
			return
		}
		// 决策通过，但不需要 Waiter 等 Sender 响应
		// 因为我们直接转发，不走 OutputBuffer
		log.Printf("[tcplistener] allowed: rule=%s action=%v", decision.RuleID, decision.Action)
	}

	// ---- 安全检查通过，直接转发到目标 ----
	l.forwardAndRespond(conn, target, reqData)
}

// forwardAndRespond 直接转发到目标，回传响应
func (l *Listener) forwardAndRespond(conn *tls.Conn, target string, reqData []byte) {
	resp, err := l.forward(target, reqData)
	if err != nil {
		log.Printf("[tcplistener] forward error: %v", err)
		writeRespFrame(conn, StatusBlocked, nil)
		return
	}
	log.Printf("[tcplistener] forward response: %d bytes", len(resp))
	if err := writeRespFrame(conn, StatusOK, resp); err != nil {
		log.Printf("[tcplistener] send response: %v", err)
	}
}

// forward 连接真实目标，发送原始请求，读取原始响应
func (l *Listener) forward(target string, payload []byte) ([]byte, error) {
	targetConn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", target, err)
	}
	defer targetConn.Close()

	targetConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := targetConn.Write(payload); err != nil {
		return nil, fmt.Errorf("write to %s: %w", target, err)
	}

	if tc, ok := targetConn.(*net.TCPConn); ok {
		tc.CloseWrite()
	}

	targetConn.SetReadDeadline(time.Now().Add(15 * time.Second))
	resp, err := io.ReadAll(targetConn)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() && len(resp) > 0 {
			return resp, nil
		}
		if err != io.EOF && len(resp) == 0 {
			return nil, fmt.Errorf("read from %s: %w", target, err)
		}
	}

	return resp, nil
}
