package tcplistener

import (
	"Threshold/pkg/types"
	"Threshold/server/portrait"
	"Threshold/server/router/router_v2"
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

// ============================================================
// 配置与接口
// ============================================================

type Config struct {
	Enabled    bool
	ListenAddr string
	CertFile   string
	KeyFile    string
}

type FingerMatcher interface {
	Match(fp types.DeviceFingerprint) bool
}

type AlertSender interface {
	PutSimple(deviceUUID string, reason string)
}

type DecisionEvaluator interface {
	Evaluate(ctx *types.ConnectionContext, history []*types.ConnectionSummary, riskLevel types.RiskLevel) *types.Decision
}

// ============================================================
// Deps
// ============================================================

type Deps struct {
	Router   *router_v2.Router
	Engine   DecisionEvaluator
	Portrait *portrait.Store
}

// ============================================================
// ConnPool 连接池：复用到目标服务器的 TCP 连接
// ============================================================

type ConnPool struct {
	mu         sync.Mutex
	conns      map[string][]*poolConn
	maxPerHost int
}

type poolConn struct {
	conn    net.Conn
	created time.Time
}

func NewConnPool() *ConnPool {
	return &ConnPool{
		conns:      make(map[string][]*poolConn),
		maxPerHost: 20,
	}
}

func (p *ConnPool) Get(target string) (net.Conn, error) {
	p.mu.Lock()
	conns := p.conns[target]
	if len(conns) > 0 {
		pc := conns[len(conns)-1]
		p.conns[target] = conns[:len(conns)-1]
		p.mu.Unlock()

		// 检查连接是否过期（60 秒）
		if time.Since(pc.created) > 60*time.Second {
			pc.conn.Close()
			return p.dial(target)
		}
		return pc.conn, nil
	}
	p.mu.Unlock()

	return p.dial(target)
}

func (p *ConnPool) Put(target string, conn net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()

	conns := p.conns[target]
	if len(conns) >= p.maxPerHost {
		conn.Close()
		return
	}
	p.conns[target] = append(conns, &poolConn{conn: conn, created: time.Now()})
}

func (p *ConnPool) dial(target string) (net.Conn, error) {
	return net.DialTimeout("tcp", target, 5*time.Second)
}

// ============================================================
// Listener
// ============================================================

type Listener struct {
	cfg   Config
	fp    FingerMatcher
	alert AlertSender
	deps  Deps
	pool  *ConnPool
}

func New(cfg Config, fp FingerMatcher, alert AlertSender, deps Deps) *Listener {
	return &Listener{cfg: cfg, fp: fp, alert: alert, deps: deps, pool: NewConnPool()}
}

func (l *Listener) Start() error {
	cert, err := tls.LoadX509KeyPair(l.cfg.CertFile, l.cfg.KeyFile)
	if err != nil {
		return fmt.Errorf("load TLS cert: %w", err)
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
// handle
// ============================================================

func (l *Listener) handle(conn *tls.Conn) {
	defer conn.Close()

	// ① TLS 握手
	if err := conn.Handshake(); err != nil {
		log.Printf("[tcplistener] TLS handshake failed: %v", err)
		return
	}
	remote := conn.RemoteAddr().String()

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
		l.secureRoute(conn, connID, hs.UUID, hs.Target, remote, reqData)
	}
}

// ============================================================
// secureRoute 安全决策 + 连接池转发
// ============================================================

func (l *Listener) secureRoute(conn *tls.Conn, connID, deviceUUID, target, remote string, reqData []byte) {
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

	// Router 分级
	riskLevel := types.L0
	if l.deps.Router != nil {
		riskLevel = l.deps.Router.Classify(parsed)
	}

	// 非 L0: 决策引擎评估
	if riskLevel != types.L0 && l.deps.Engine != nil {
		ctx := &types.ConnectionContext{
			ConnectionID: connID,
			DeviceUUID:   deviceUUID,
		}
		decision := l.deps.Engine.Evaluate(ctx, nil, riskLevel)
		if decision != nil && (decision.Action == types.BLOCK ||
			decision.Action == types.BLOCK_DEVICE ||
			decision.Action == types.BLACKLIST_DEVICE) {
			writeRespFrame(conn, StatusBlocked, nil)
			if l.alert != nil {
				l.alert.PutSimple(deviceUUID, decision.Reason)
			}
			return
		}
	}

	// 连接池转发
	l.forwardWithPool(conn, target, reqData)
}

// ============================================================
// forwardWithPool 用连接池转发请求
// ============================================================

func (l *Listener) forwardWithPool(conn *tls.Conn, target string, reqData []byte) {
	// 从连接池获取连接
	targetConn, err := l.pool.Get(target)
	if err != nil {
		log.Printf("[tcplistener] pool get error: %v", err)
		writeRespFrame(conn, StatusBlocked, nil)
		return
	}

	// 发送请求
	targetConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := targetConn.Write(reqData); err != nil {
		targetConn.Close()
		// 重试一次
		targetConn, err = l.pool.Get(target)
		if err != nil {
			writeRespFrame(conn, StatusBlocked, nil)
			return
		}
		if _, err := targetConn.Write(reqData); err != nil {
			targetConn.Close()
			writeRespFrame(conn, StatusBlocked, nil)
			return
		}
	}

	// 用 http.ReadResponse 正确解析 HTTP 响应
	targetConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(targetConn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		targetConn.Close()
		writeRespFrame(conn, StatusBlocked, nil)
		return
	}

	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		targetConn.Close()
		writeRespFrame(conn, StatusBlocked, nil)
		return
	}

	// 重建完整 HTTP 响应字节
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "%s %s\r\n", resp.Proto, resp.Status)
	resp.Header.Write(&buf)
	buf.WriteString("\r\n")
	buf.Write(body)
	respBytes := buf.Bytes()

	writeRespFrame(conn, StatusOK, respBytes)

	// 连接放回池里复用
	l.pool.Put(target, targetConn)
}

func strPtr(s string) *string {
	return &s
}
