package tcplistener

import (
	"Threshold/pkg/types"
	"Threshold/server/fingerprint"
	"Threshold/server/portrait"
	"Threshold/server/router/router_v2"
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// ============================================================
// 配置与接口
// ============================================================
const maxLifetime = 30 * time.Minute

// 默认值常量，仅用于 ApplyDefaults 兜底
const (
	defaultMaxConns            = 1000
	defaultMaxPerHost          = 20
	defaultMaxLifetime         = 30 * time.Minute
	defaultMaxIdle             = 5 * time.Minute
	defaultJanitorInterval     = 30 * time.Second
	defaultDialTimeout         = 5 * time.Second
	defaultTLSHandshakeTimeout = 10 * time.Second
	defaultRequestReadTimeout  = 60 * time.Second
	defaultWriteTimeout        = 10 * time.Second
	defaultReadTimeout         = 10 * time.Second
	defaultMaxPayloadSize      = 1 << 20  // 1MB
	defaultMaxResponseSize     = 10 << 20 // 10MB
)

type Config struct {
	Enabled    bool   `yaml:"enabled"`
	ListenAddr string `yaml:"listen_addr"`
	CertFile   string `yaml:"cert_file"`
	KeyFile    string `yaml:"key_file"`
	CACertFile string `yaml:"ca_cert_file"`

	// 连接池
	MaxConns    int           `yaml:"max_conns"`
	MaxPerHost  int           `yaml:"max_per_host"`
	MaxLifetime time.Duration `yaml:"max_lifetime"`
	MaxIdle     time.Duration `yaml:"max_idle"`

	// Janitor
	JanitorInterval time.Duration `yaml:"janitor_interval"`

	// 超时
	DialTimeout         time.Duration `yaml:"dial_timeout"`
	TLSHandshakeTimeout time.Duration `yaml:"tls_handshake_timeout"`
	RequestReadTimeout  time.Duration `yaml:"request_read_timeout"`
	WriteTimeout        time.Duration `yaml:"write_timeout"`
	ReadTimeout         time.Duration `yaml:"read_timeout"`

	// 帧限制
	MaxPayloadSize  int `yaml:"max_payload_size"`
	MaxResponseSize int `yaml:"max_response_size"`
}

// ApplyDefaults 将零值字段填充为默认值
func (c *Config) ApplyDefaults() {
	if c.MaxConns == 0 {
		c.MaxConns = defaultMaxConns
	}
	if c.MaxPerHost == 0 {
		c.MaxPerHost = defaultMaxPerHost
	}
	if c.MaxLifetime == 0 {
		c.MaxLifetime = defaultMaxLifetime
	}
	if c.MaxIdle == 0 {
		c.MaxIdle = defaultMaxIdle
	}
	if c.JanitorInterval == 0 {
		c.JanitorInterval = defaultJanitorInterval
	}
	if c.DialTimeout == 0 {
		c.DialTimeout = defaultDialTimeout
	}
	if c.TLSHandshakeTimeout == 0 {
		c.TLSHandshakeTimeout = defaultTLSHandshakeTimeout
	}
	if c.RequestReadTimeout == 0 {
		c.RequestReadTimeout = defaultRequestReadTimeout
	}
	if c.WriteTimeout == 0 {
		c.WriteTimeout = defaultWriteTimeout
	}
	if c.ReadTimeout == 0 {
		c.ReadTimeout = defaultReadTimeout
	}
	if c.MaxPayloadSize == 0 {
		c.MaxPayloadSize = defaultMaxPayloadSize
	}
	if c.MaxResponseSize == 0 {
		c.MaxResponseSize = defaultMaxResponseSize
	}
}

type FingerMatcher interface {
	Match(fp types.DeviceFingerprint) fingerprint.MatchResult
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
	Engine   DecisionEvaluator // 所以这个位置没有做dispatch的负载均衡了，这里的优化干脆单独做算了
	Portrait *portrait.Store
}

// ============================================================
// ConnPool 连接池：复用到目标服务器的 TCP 连接
// ============================================================

type pooledConn struct {
	conn     net.Conn
	br       *bufio.Reader // 与 conn 绑定，避免预读数据丢失
	created  time.Time
	lastUsed time.Time
}

type hostPool struct {
	mu    sync.Mutex
	conns []*pooledConn
}
type ConnPool struct {
	mu         sync.RWMutex
	hosts      map[string]*hostPool
	cfg        *Config // ← 改为引用 Config
	totalConns int32
	stopOnce   sync.Once
	stopCh     chan struct{}
	closed     int32
}

func NewConnPool(cfg *Config) *ConnPool {
	p := &ConnPool{
		hosts:  make(map[string]*hostPool),
		cfg:    cfg,
		stopCh: make(chan struct{}),
	}
	go p.startJanitor()
	return p
}

func (p *ConnPool) dial(target string) (*pooledConn, error) {
	if atomic.LoadInt32(&p.closed) == 1 {
		return nil, fmt.Errorf("connection pool is closed")
	}
	if atomic.LoadInt32(&p.totalConns) >= int32(p.cfg.MaxConns) {
		return nil, fmt.Errorf("connection pool exhausted (%d/%d)",
			atomic.LoadInt32(&p.totalConns), p.cfg.MaxConns)
	}
	conn, err := net.DialTimeout("tcp", target, p.cfg.DialTimeout) // ← 从 cfg 读
	if err != nil {
		return nil, err
	}
	atomic.AddInt32(&p.totalConns, 1)
	now := time.Now()
	return &pooledConn{
		conn:     conn,
		br:       bufio.NewReader(conn),
		created:  now,
		lastUsed: now,
	}, nil
}

func (p *ConnPool) Put(target string, pc *pooledConn) {
	if atomic.LoadInt32(&p.closed) == 1 {
		p.closeConn(pc)
		return
	}

	hp := p.getHost(target)
	hp.mu.Lock()
	defer hp.mu.Unlock()

	if len(hp.conns) >= p.cfg.MaxPerHost { // ← 从 cfg 读
		p.closeConn(pc)
		return
	}
	pc.lastUsed = time.Now()
	hp.conns = append(hp.conns, pc)
}

func (p *ConnPool) cleanup() {
	p.mu.RLock()
	targets := make([]string, 0, len(p.hosts))
	for t := range p.hosts {
		targets = append(targets, t)
	}
	p.mu.RUnlock()

	for _, target := range targets {
		hp := p.getHost(target)
		hp.mu.Lock()

		alive := hp.conns[:0]
		for _, pc := range hp.conns {
			if time.Since(pc.created) > p.cfg.MaxLifetime || // ← 从 cfg 读
				time.Since(pc.lastUsed) > p.cfg.MaxIdle || // ← 从 cfg 读
				!p.isAlive(pc) {
				p.closeConn(pc)
				continue
			}
			alive = append(alive, pc)
		}
		for i := len(alive); i < len(hp.conns); i++ {
			hp.conns[i] = nil
		}
		hp.conns = alive

		hp.mu.Unlock()
	}
}

func (p *ConnPool) startJanitor() {
	ticker := time.NewTicker(p.cfg.JanitorInterval) // ← 从 cfg 读
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.cleanup()
		case <-p.stopCh:
			return
		}
	}
}

func (p *ConnPool) Get(target string) (*pooledConn, error) {
	if atomic.LoadInt32(&p.closed) == 1 {
		return nil, fmt.Errorf("connection pool is closed")
	}

	hp := p.getHost(target)

	hp.mu.Lock()
	for len(hp.conns) > 0 {
		pc := hp.conns[len(hp.conns)-1]
		hp.conns = hp.conns[:len(hp.conns)-1]
		hp.mu.Unlock()

		if time.Since(pc.created) > p.cfg.MaxLifetime { // ← 从 cfg 读
			p.closeConn(pc)
			hp.mu.Lock()
			continue
		}
		if p.isAlive(pc) {
			if pc.br.Buffered() > 0 {
				p.closeConn(pc)
			} else {
				pc.lastUsed = time.Now()
				return pc, nil
			}
		} else {
			p.closeConn(pc)
		}

		hp.mu.Lock()
	}
	hp.mu.Unlock()

	return p.dial(target)
}

// getHost 获取或创建 per-host 连接栈（带 lazy init）
func (p *ConnPool) getHost(target string) *hostPool {
	// 快速路径：读锁查找
	p.mu.RLock()
	hp, ok := p.hosts[target]
	p.mu.RUnlock()
	if ok {
		return hp
	}

	// 慢速路径：写锁创建（double-check）
	p.mu.Lock()
	defer p.mu.Unlock()
	hp, ok = p.hosts[target]
	if !ok {
		hp = &hostPool{}
		p.hosts[target] = hp
	}
	return hp
}

func (p *ConnPool) isAlive(pc *pooledConn) bool {

	pc.conn.SetReadDeadline(time.Now().Add(1 * time.Millisecond))
	// Peek 不消费字节，只窥探缓冲区和底层连接
	_, err := pc.br.Peek(1)
	pc.conn.SetReadDeadline(time.Time{})

	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return true // 超时 = 连接活着，只是没数据
		}
		return false
	}
	// Peek 到数据 = 有脏数据，连接不可信
	return false
}

// closeConn 统一的连接关闭：关闭 socket + 减少计数
func (p *ConnPool) closeConn(pc *pooledConn) {
	pc.conn.Close()
	atomic.AddInt32(&p.totalConns, -1)
}

func (p *ConnPool) Close() {
	p.stopOnce.Do(func() {
		atomic.StoreInt32(&p.closed, 1) // ← 标记关闭
		close(p.stopCh)
	})

	p.mu.Lock()
	defer p.mu.Unlock()
	for _, hp := range p.hosts {
		hp.mu.Lock()
		for _, pc := range hp.conns {
			p.closeConn(pc)
		}
		hp.conns = nil
		hp.mu.Unlock()
	}
}

// ============================================================
// Listener
// ============================================================

type Listener struct {
	cfg       Config
	fp        FingerMatcher
	alert     AlertSender
	deps      Deps
	pool      *ConnPool
	ln        net.Listener
	closeCh   chan struct{}
	closeOnce sync.Once
	sem       chan struct{}
}

func New(cfg Config, fp FingerMatcher, alert AlertSender, deps Deps) *Listener {
	cfg.ApplyDefaults() // ← 入口兜底

	return &Listener{
		cfg:     cfg,
		fp:      fp,
		alert:   alert,
		deps:    deps,
		pool:    NewConnPool(&cfg),
		closeCh: make(chan struct{}),
		sem:     make(chan struct{}, cfg.MaxConns),
	}
}
func (l *Listener) Close() {
	l.closeOnce.Do(func() {
		close(l.closeCh)
		if l.ln != nil {
			l.ln.Close()
		}
		l.pool.Close()
	})
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

	// 加载 CA 证书，启用 mTLS（验证客户端证书）
	if l.cfg.CACertFile != "" {
		caCert, err := os.ReadFile(l.cfg.CACertFile)
		if err != nil {
			log.Printf("[tcplistener] WARN: failed to load CA cert: %v", err)
		} else {
			pool := x509.NewCertPool()
			if pool.AppendCertsFromPEM(caCert) {
				tlsCfg.ClientCAs = pool
				tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
				log.Printf("[tcplistener] mTLS enabled (CA=%s)", l.cfg.CACertFile)
			}
		}
	}

	if tlsCfg.ClientAuth == tls.NoClientCert {
		log.Printf("[tcplistener] TLS: one-way (no client cert required)")
	}

	ln, err := tls.Listen("tcp", l.cfg.ListenAddr, tlsCfg)
	if err != nil {
		return fmt.Errorf("tls listen on %s: %w", l.cfg.ListenAddr, err)
	}
	l.ln = ln
	defer ln.Close()

	log.Printf("[tcplistener] listening on %s (TLS)", l.cfg.ListenAddr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-l.closeCh:
				log.Printf("[tcplistener] shutting down")
				return nil
			default:
				log.Printf("[tcplistener] accept error: %v", err)
				continue
			}
		}

		// 并发连接数控制
		select {
		case l.sem <- struct{}{}: // 拿到令牌，继续
			go func() {
				defer func() { <-l.sem }() // 处理完归还令牌
				l.handle(conn.(*tls.Conn))
			}()
		default: // 令牌池满，拒绝连接
			conn.Close()
			log.Printf("[tcplistener] connection rejected: at capacity")
		}
	}
}

// ============================================================
// handle：这里就对应这之前so中connect到实际的写过程，其实就是网络通讯和包处理但是不会很难
// ============================================================

func (l *Listener) handle(conn *tls.Conn) {
	defer conn.Close()

	// TLS 握手 + 首帧超时 ← 从 cfg 读
	conn.SetDeadline(time.Now().Add(l.cfg.TLSHandshakeTimeout))

	if err := conn.Handshake(); err != nil {
		log.Printf("[tcplistener] TLS handshake failed: %v", err)
		return
	}
	remote := conn.RemoteAddr().String()

	raw, err := readFrame(conn, l.cfg.MaxPayloadSize)
	if err != nil {
		log.Printf("[tcplistener] read handshake: %v", err)
		return
	}
	conn.SetDeadline(time.Time{})

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
		result := l.fp.Match(fp)

		if !result.Matched {
			log.Printf("[tcplistener] FINGERPRINT REJECTED uuid=%s ip=%s", hs.UUID, host)
			writeRespFrame(conn, StatusBlocked, nil)
			if l.alert != nil {
				l.alert.PutSimple(hs.UUID, "mode3 fingerprint mismatch")
			}
			return
		}
		if len(result.AuditDiffs) > 0 {
			for _, d := range result.AuditDiffs {
				log.Printf("[AUDIT] UUID=%s %s drift: %s → %s (path=%s)",
					string(*fp.UUID), d.Dimension,
					d.Registered, d.Actual, result.MatchPath)
			}
		}
	}

	// ④ 握手响应 OK
	/*
	 * 验证通过，告诉客户端"你可以开始发数据了"
	 *
	 * 此时客户端的 handshake_send 会收到 STATUS_OK
	 * connect() 函数返回 0，应用以为连接成功
	 */
	conn.SetWriteDeadline(time.Now().Add(l.cfg.WriteTimeout)) // ← 从 cfg 读
	if err := writeRespFrame(conn, StatusOK, nil); err != nil {
		return
	}
	conn.SetWriteDeadline(time.Time{})

	connID := fmt.Sprintf("mode3-%s-%d", hs.UUID, time.Now().UnixNano())
	log.Printf("[tcplistener] session: connID=%s uuid=%s → %s", connID, hs.UUID, hs.Target)

	// 请求循环
	for {
		conn.SetReadDeadline(time.Now().Add(l.cfg.RequestReadTimeout)) // ← 从 cfg 读
		reqData, err := readFrame(conn, l.cfg.MaxPayloadSize)
		conn.SetReadDeadline(time.Time{})
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
		// 封装一下路由器所需要的数据，这个到不会很复杂
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
		// TODO(cheng)往后内部就是详细的决策过程，那么这个决策过程其实还需要详细设计，因为对于TCP连接来说，他的威胁和语义可以怎么设计还需要权衡
		// TODO(cheng) 决策引擎后续可以
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
// ============================================================
// forwardWithPool 用连接池转发请求
// ============================================================
func (l *Listener) forwardWithPool(conn *tls.Conn, target string, reqData []byte) {
	pc, err := l.pool.Get(target)
	if err != nil {
		log.Printf("[tcplistener] dial %s: %v", target, err)
		writeRespFrame(conn, StatusBlocked, nil)
		return
	}

	respBytes, err := l.doRoundTrip(pc, reqData)
	if err != nil {
		// 第一次失败：连接可能已死，关闭后重试一次
		l.pool.closeConn(pc) // ← 统一走 closeConn

		pc, retryErr := l.pool.Get(target)
		if retryErr != nil {
			log.Printf("[tcplistener] retry dial %s: %v", target, retryErr)
			writeRespFrame(conn, StatusBlocked, nil)
			return
		}
		respBytes, err = l.doRoundTrip(pc, reqData)
		if err != nil {
			l.pool.closeConn(pc) // ← 统一走 closeConn
			log.Printf("[tcplistener] retry failed %s: %v", target, err)
			writeRespFrame(conn, StatusBlocked, nil)
			return
		}
	}

	writeRespFrame(conn, StatusOK, respBytes)
	l.pool.Put(target, pc)
}

func strPtr(s string) *string {
	return &s
}

const MaxResponseSize = 10 << 20 // 10MB

func (l *Listener) doRoundTrip(pc *pooledConn, reqData []byte) ([]byte, error) {
	pc.conn.SetWriteDeadline(time.Now().Add(l.cfg.WriteTimeout)) // ← 从 cfg 读
	if _, err := pc.conn.Write(reqData); err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}

	pc.conn.SetReadDeadline(time.Now().Add(l.cfg.ReadTimeout)) // ← 从 cfg 读
	resp, err := http.ReadResponse(pc.br, nil)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(l.cfg.MaxResponseSize+1))) // ← 从 cfg 读
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if len(body) > l.cfg.MaxResponseSize { // ← 从 cfg 读
		return nil, fmt.Errorf("response too large: %d bytes (limit %d)", len(body), l.cfg.MaxResponseSize)
	}

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "%s %s\r\n", resp.Proto, resp.Status)
	resp.Header.Write(&buf)
	buf.WriteString("\r\n")
	buf.Write(body)

	return buf.Bytes(), nil
}
