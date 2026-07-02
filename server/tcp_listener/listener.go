package tcplistener

import (
	"Threshold/pkg/types"
	"Threshold/server/fingerprint"
	"Threshold/server/portrait"
	"Threshold/server/router/router_v2"
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// ============================================================
// 配置与接口
// ============================================================

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
	defaultRateLimitPerSec     = 100
	defaultRateLimitBurst      = 200
)

type Config struct {
	Enabled    bool   `yaml:"enabled"`
	ListenAddr string `yaml:"listen_addr"`
	CertFile   string `yaml:"cert_file"`
	KeyFile    string `yaml:"key_file"`
	CACertFile string `yaml:"ca_cert_file"`

	MaxConns    int           `yaml:"max_conns"`
	MaxPerHost  int           `yaml:"max_per_host"`
	MaxLifetime time.Duration `yaml:"max_lifetime"`
	MaxIdle     time.Duration `yaml:"max_idle"`

	JanitorInterval time.Duration `yaml:"janitor_interval"`

	DialTimeout         time.Duration `yaml:"dial_timeout"`
	TLSHandshakeTimeout time.Duration `yaml:"tls_handshake_timeout"`
	RequestReadTimeout  time.Duration `yaml:"request_read_timeout"`
	WriteTimeout        time.Duration `yaml:"write_timeout"`
	ReadTimeout         time.Duration `yaml:"read_timeout"`

	MaxPayloadSize  int `yaml:"max_payload_size"`
	MaxResponseSize int `yaml:"max_response_size"`

	RateLimitPerSec int64 `yaml:"rate_limit_per_sec"`
	RateLimitBurst  int64 `yaml:"rate_limit_burst"`
}

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
	if c.RateLimitPerSec == 0 {
		c.RateLimitPerSec = defaultRateLimitPerSec
	}
	if c.RateLimitBurst == 0 {
		c.RateLimitBurst = defaultRateLimitBurst
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

type Deps struct {
	Router   *router_v2.Router
	Engine   DecisionEvaluator
	Portrait *portrait.Store
}

// ============================================================
// ConnPool 连接池
// ============================================================

type pooledConn struct {
	conn     net.Conn
	br       *bufio.Reader
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
	cfg        *Config
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
	conn, err := net.DialTimeout("tcp", target, p.cfg.DialTimeout)
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

func (p *ConnPool) Get(target string) (*pooledConn, error) {
	if atomic.LoadInt32(&p.closed) == 1 {
		return nil, fmt.Errorf("connection pool is closed")
	}

	hp := p.getHost(target)
	hp.mu.Lock()

	for len(hp.conns) > 0 {
		pc := hp.conns[len(hp.conns)-1]
		hp.conns = hp.conns[:len(hp.conns)-1]

		if time.Since(pc.created) > p.cfg.MaxLifetime {
			p.closeConn(pc)
			continue
		}
		if p.isAlive(pc) {
			if pc.br.Buffered() > 0 {
				p.closeConn(pc)
			} else {
				pc.lastUsed = time.Now()
				hp.mu.Unlock()
				return pc, nil
			}
		} else {
			p.closeConn(pc)
		}
	}

	pc, err := p.dial(target)
	hp.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return pc, nil
}

func (p *ConnPool) Put(target string, pc *pooledConn) {
	if atomic.LoadInt32(&p.closed) == 1 {
		p.closeConn(pc)
		return
	}

	hp := p.getHost(target)
	hp.mu.Lock()
	defer hp.mu.Unlock()

	if len(hp.conns) >= p.cfg.MaxPerHost {
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
			if time.Since(pc.created) > p.cfg.MaxLifetime ||
				time.Since(pc.lastUsed) > p.cfg.MaxIdle ||
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
	ticker := time.NewTicker(p.cfg.JanitorInterval)
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

func (p *ConnPool) getHost(target string) *hostPool {
	p.mu.RLock()
	hp, ok := p.hosts[target]
	p.mu.RUnlock()
	if ok {
		return hp
	}

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
	for attempt := 0; attempt < 2; attempt++ {
		pc.conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		_, err := pc.br.Peek(1)
		pc.conn.SetReadDeadline(time.Time{})

		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				return true
			}
			if attempt == 0 {
				time.Sleep(5 * time.Millisecond)
				continue
			}
			return false
		}
		return false
	}
	return false
}

func (p *ConnPool) closeConn(pc *pooledConn) {
	pc.conn.Close()
	atomic.AddInt32(&p.totalConns, -1)
}

func (p *ConnPool) Close() {
	p.stopOnce.Do(func() {
		atomic.StoreInt32(&p.closed, 1)
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
	wg        sync.WaitGroup
	limiter   *ClientRateLimiter
}

func New(cfg Config, fp FingerMatcher, alert AlertSender, deps Deps) *Listener {
	cfg.ApplyDefaults()

	return &Listener{
		cfg:     cfg,
		fp:      fp,
		alert:   alert,
		deps:    deps,
		pool:    NewConnPool(&cfg),
		closeCh: make(chan struct{}),
		sem:     make(chan struct{}, cfg.MaxConns),
		limiter: NewClientRateLimiter(cfg.RateLimitPerSec, cfg.RateLimitBurst),
	}
}

func (l *Listener) Close() {
	l.closeOnce.Do(func() {
		close(l.closeCh)
		if l.ln != nil {
			l.ln.Close()
		}
		done := make(chan struct{})
		go func() {
			l.wg.Wait()
			close(done)
		}()
		select {
		case <-done:
			log.Printf("[tcplistener] all sessions drained")
		case <-time.After(10 * time.Second):
			log.Printf("[tcplistener] shutdown timeout, forcing close")
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

		select {
		case l.sem <- struct{}{}:
			l.wg.Add(1)
			go func() {
				defer func() { <-l.sem; l.wg.Done() }()
				l.handle(conn.(*tls.Conn))
			}()
		default:
			conn.Close()
			log.Printf("[tcplistener] connection rejected: at capacity")
		}
	}
}

// ============================================================
// handle
// ============================================================

func (l *Listener) handle(conn *tls.Conn) {
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(l.cfg.TLSHandshakeTimeout))

	if err := conn.Handshake(); err != nil {
		log.Printf("[tcplistener] TLS handshake failed: %v", err)
		return
	}
	remote := conn.RemoteAddr().String()

	raw, err := readFrame(conn, l.cfg.MaxPayloadSize)
	if err != nil {
		log.Printf("[tcplistener] read handshake: %v", err)
		writeRespFrame(conn, StatusBlocked, nil)
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

	conn.SetWriteDeadline(time.Now().Add(l.cfg.WriteTimeout))
	if err := writeRespFrame(conn, StatusOK, nil); err != nil {
		return
	}
	conn.SetWriteDeadline(time.Time{})

	connID := fmt.Sprintf("mode3-%s-%d", hs.UUID, time.Now().UnixNano())
	log.Printf("[tcplistener] session: connID=%s uuid=%s → %s", connID, hs.UUID, hs.Target)

	for {
		conn.SetReadDeadline(time.Now().Add(l.cfg.RequestReadTimeout))
		reqData, err := readFrame(conn, l.cfg.MaxPayloadSize)
		conn.SetReadDeadline(time.Time{})
		if err != nil {
			log.Printf("[tcplistener] session end: connID=%s err=%v", connID, err)
			return
		}

		if l.limiter != nil && !l.limiter.Allow(hs.UUID) {
			log.Printf("[tcplistener] rate limited: uuid=%s", hs.UUID)
			writeRespFrame(conn, StatusLimited, nil)
			continue
		}

		l.secureRoute(conn, connID, hs.UUID, hs.Target, remote, reqData)
	}
}

func (l *Listener) secureRoute(conn *tls.Conn, connID, deviceUUID, target, remote string, reqData []byte) {
	l.forwardWithPool(conn, target, reqData)
}

// ============================================================
// forwardWithPool: 通用 TCP 转发
// ============================================================

func (l *Listener) forwardWithPool(conn *tls.Conn, target string, reqData []byte) {
	respBytes, err := l.doRoundTrip(target, reqData)
	if err != nil {
		log.Printf("[tcplistener] roundtrip %s: %v", target, err)
		writeRespFrame(conn, StatusError, nil)
		return
	}

	writeRespFrame(conn, StatusOK, respBytes)
}

// doRoundTrip: 通用 TCP 请求-响应转发
// 不假设任何应用层协议，纯原始字节转发
//
// 流程:
//  1. dial 到后端
//  2. 写入 reqData
//  3. 读取响应（受 ReadTimeout + MaxResponseSize 约束）
//  4. 关闭后端连接
//
// 关闭连接而非复用的原因：
//
//	大多数 request-response 协议（Redis RESP, MySQL, 自定义 RPC）
//	服务端在发送完整响应后关闭连接或进入新状态。
//	在不解析应用层协议的前提下，无法安全判断「响应已完整且连接可复用」。
//	每次请求新建连接是最安全的选择。DialTimeout 默认 5s，开销可接受。
func (l *Listener) doRoundTrip(target string, reqData []byte) ([]byte, error) {
	conn, err := net.DialTimeout("tcp", target, l.cfg.DialTimeout)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", target, err)
	}
	defer conn.Close()

	// 写请求
	conn.SetWriteDeadline(time.Now().Add(l.cfg.WriteTimeout))
	if _, err := conn.Write(reqData); err != nil {
		return nil, fmt.Errorf("write to %s: %w", target, err)
	}

	// half-close: 关闭写端，通知后端「请求已发完，可以回了」
	// 这是通用 TCP request-response 的正确语义：
	// - Redis/MySQL/自定义 RPC 后端读到 EOF 后开始处理并响应
	// - 不影响读端，响应数据仍可正常接收
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.CloseWrite()
	}

	// 读响应：原始字节，不解析协议
	conn.SetReadDeadline(time.Now().Add(l.cfg.ReadTimeout))
	resp, err := io.ReadAll(io.LimitReader(conn, int64(l.cfg.MaxResponseSize+1)))
	if err != nil && len(resp) == 0 {
		return nil, fmt.Errorf("read from %s: %w", target, err)
	}

	if len(resp) > l.cfg.MaxResponseSize {
		return nil, fmt.Errorf("response too large: %d bytes (limit %d)", len(resp), l.cfg.MaxResponseSize)
	}
	if len(resp) == 0 {
		return nil, fmt.Errorf("empty response from %s", target)
	}

	return resp, nil
}

func strPtr(s string) *string {
	return &s
}
