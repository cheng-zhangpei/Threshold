// tools/bench/main.go
package main

import (
	"crypto/tls"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ============================================================
// 统计收集器
// ============================================================

type Stats struct {
	mu        sync.Mutex
	latencies []time.Duration
	errors    int64
}

func (s *Stats) Record(d time.Duration) {
	s.mu.Lock()
	s.latencies = append(s.latencies, d)
	s.mu.Unlock()
}

func (s *Stats) RecordError() {
	atomic.AddInt64(&s.errors, 1)
}

func (s *Stats) Report(total time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()

	n := len(s.latencies)
	if n == 0 {
		fmt.Println("No successful requests")
		return
	}

	sort.Slice(s.latencies, func(i, j int) bool {
		return s.latencies[i] < s.latencies[j]
	})

	var sum time.Duration
	for _, l := range s.latencies {
		sum += l
	}

	qps := float64(n) / total.Seconds()
	mean := sum / time.Duration(n)
	p50 := s.latencies[n*50/100]
	p95Idx := int(float64(n) * 0.95)
	if p95Idx >= n {
		p95Idx = n - 1
	}
	p95 := s.latencies[p95Idx]
	p99Idx := int(float64(n) * 0.99)
	if p99Idx >= n {
		p99Idx = n - 1
	}
	p99 := s.latencies[p99Idx]

	fmt.Println()
	fmt.Println("╔══════════════════════════════════════╗")
	fmt.Println("║          Benchmark Results           ║")
	fmt.Println("╠══════════════════════════════════════╣")
	fmt.Printf("║  Requests:       %-20d║\n", n)
	fmt.Printf("║  Errors:         %-20d║\n", s.errors)
	fmt.Printf("║  Duration:       %-20v║\n", total.Round(time.Millisecond))
	fmt.Printf("║  QPS:            %-20.2f║\n", qps)
	fmt.Println("╠══════════════════════════════════════╣")
	fmt.Printf("║  Latency Min:    %-20v║\n", s.latencies[0].Round(time.Microsecond))
	fmt.Printf("║  Latency Mean:   %-20v║\n", mean.Round(time.Microsecond))
	fmt.Printf("║  Latency P50:    %-20v║\n", p50.Round(time.Microsecond))
	fmt.Printf("║  Latency P95:    %-20v║\n", p95.Round(time.Microsecond))
	fmt.Printf("║  Latency P99:    %-20v║\n", p99.Round(time.Microsecond))
	fmt.Printf("║  Latency Max:    %-20v║\n", s.latencies[n-1].Round(time.Microsecond))
	fmt.Println("╚══════════════════════════════════════╝")
}

// ============================================================
// 主函数
// ============================================================

var totalTime time.Duration

func main() {
	var (
		mode     string
		addr     string
		target   string
		socks5   string
		uuid     string
		conc     int
		duration time.Duration
		reqType  string
	)
	flag.StringVar(&mode, "mode", "direct", "benchmark mode: direct | socks5 | tls")
	flag.StringVar(&addr, "addr", "127.0.0.1:8080", "backend address (direct) or proxy address (socks5/tls)")
	flag.StringVar(&target, "target", "127.0.0.1:8080", "real target address (for tls mode)")
	flag.StringVar(&socks5, "socks5", "127.0.0.1:1080", "SOCKS5 proxy address (for socks5 mode)")
	flag.StringVar(&uuid, "uuid", "bench-device", "device UUID (for tls mode)")
	flag.IntVar(&conc, "c", 10, "concurrency (number of goroutines)")
	flag.DurationVar(&duration, "d", 30*time.Second, "test duration")
	flag.StringVar(&reqType, "req", "get", "request type: get | set")
	flag.Parse()

	reqType = strings.ToLower(reqType)
	if reqType != "get" && reqType != "set" {
		fmt.Fprintf(os.Stderr, "invalid req type: %s (use get or set)\n", reqType)
		os.Exit(1)
	}

	fmt.Printf("Mode:         %s\n", mode)
	fmt.Printf("Address:      %s\n", addr)
	if mode == "tls" {
		fmt.Printf("Target:       %s\n", target)
		fmt.Printf("Device UUID:  %s\n", uuid)
	}
	if mode == "socks5" {
		fmt.Printf("SOCKS5:       %s\n", socks5)
	}
	fmt.Printf("Concurrency:  %d\n", conc)
	fmt.Printf("Duration:     %v\n", duration)
	fmt.Printf("Request type: %s\n", reqType)
	fmt.Println()

	var stats *Stats

	switch mode {
	case "direct":
		makeRequest := makeDirectRequest(addr, reqType)
		fmt.Print("Warming up... ")
		for i := 0; i < conc*5; i++ {
			key := fmt.Sprintf("key-%04d", rand.Intn(1000))
			makeRequest(key)
		}
		fmt.Println("done")
		stats = runBenchmarkSingle(makeRequest, conc, duration)

	case "socks5":
		makeRequest := makeSocks5Request(socks5, addr, reqType)
		fmt.Print("Warming up... ")
		for i := 0; i < conc*5; i++ {
			key := fmt.Sprintf("key-%04d", rand.Intn(1000))
			makeRequest(key)
		}
		fmt.Println("done")
		stats = runBenchmarkSingle(makeRequest, conc, duration)

	case "tls":
		funcs := makeTLSFuncs(addr, target, uuid, reqType, conc)
		fmt.Print("Warming up... ")
		for _, fn := range funcs {
			for i := 0; i < 5; i++ {
				key := fmt.Sprintf("key-%04d", rand.Intn(1000))
				if err := fn(key); err != nil {
					fmt.Fprintf(os.Stderr, "warmup error: %v\n", err)
					return
				}
			}
		}
		fmt.Println("done")
		stats = runBenchmarkMulti(funcs, duration)

	default:
		fmt.Fprintf(os.Stderr, "unknown mode: %s\n", mode)
		os.Exit(1)
	}

	stats.Report(totalTime)
}

// ============================================================
// 基准测试运行器
// ============================================================

// runBenchmarkSingle 所有 goroutine 共用一个请求函数（direct / socks5）
func runBenchmarkSingle(requestFunc func(key string) error, concurrency int, duration time.Duration) *Stats {
	stats := &Stats{}
	var wg sync.WaitGroup
	ctx := make(chan struct{})
	start := time.Now()

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rng := rand.New(rand.NewSource(time.Now().UnixNano()))
			for {
				select {
				case <-ctx:
					return
				default:
					key := fmt.Sprintf("key-%04d", rng.Intn(1000))
					reqStart := time.Now()
					err := requestFunc(key)
					latency := time.Since(reqStart)
					if err != nil {
						stats.RecordError()
					} else {
						stats.Record(latency)
					}
				}
			}
		}()
	}

	time.Sleep(duration)
	close(ctx)
	wg.Wait()
	totalTime = time.Since(start)
	return stats
}

// runBenchmarkMulti 每个 goroutine 独占一个请求函数（tls 模式）
func runBenchmarkMulti(requestFuncs []func(key string) error, duration time.Duration) *Stats {
	stats := &Stats{}
	var wg sync.WaitGroup
	ctx := make(chan struct{})
	start := time.Now()

	for _, fn := range requestFuncs {
		wg.Add(1)
		go func(rf func(string) error) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(time.Now().UnixNano()))
			for {
				select {
				case <-ctx:
					return
				default:
					key := fmt.Sprintf("key-%04d", rng.Intn(1000))
					reqStart := time.Now()
					err := rf(key)
					latency := time.Since(reqStart)
					if err != nil {
						stats.RecordError()
					} else {
						stats.Record(latency)
					}
				}
			}
		}(fn)
	}

	time.Sleep(duration)
	close(ctx)
	wg.Wait()
	totalTime = time.Since(start)
	return stats
}

// ============================================================
// direct 模式：直连后端（baseline）
// ============================================================

func makeDirectRequest(addr, reqType string) func(string) error {
	transport := &http.Transport{
		MaxIdleConns:        500,
		MaxIdleConnsPerHost: 500,
		MaxConnsPerHost:     500,
		IdleConnTimeout:     90 * time.Second,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}

	return func(key string) error {
		var resp *http.Response
		var err error

		if reqType == "set" {
			resp, err = client.Post(
				fmt.Sprintf("http://%s/set?key=%s&value=bench", addr, key),
				"text/plain", nil,
			)
		} else {
			resp, err = client.Get(
				fmt.Sprintf("http://%s/get?key=%s", addr, key),
			)
		}
		if err != nil {
			return err
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode >= 500 {
			return fmt.Errorf("status %d", resp.StatusCode)
		}
		return nil
	}
}

// ============================================================
// socks5 模式：通过 SOCKS5 代理（Mode 2）
// ============================================================

func makeSocks5Request(proxyAddr, targetAddr, reqType string) func(string) error {
	dialFunc := func(network, addr string) (net.Conn, error) {
		conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
		if err != nil {
			return nil, err
		}

		// SOCKS5 握手：认证方法选择
		conn.Write([]byte{0x05, 0x01, 0x00})
		resp := make([]byte, 2)
		if _, err := io.ReadFull(conn, resp); err != nil {
			conn.Close()
			return nil, err
		}
		if resp[0] != 0x05 || resp[1] != 0x00 {
			conn.Close()
			return nil, fmt.Errorf("socks5 auth failed")
		}

		// CONNECT 请求
		host, portStr, _ := net.SplitHostPort(addr)
		port := 80
		fmt.Sscanf(portStr, "%d", &port)

		req := []byte{0x05, 0x01, 0x00, 0x01}
		ip := net.ParseIP(host).To4()
		if ip == nil {
			req = []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
			req = append(req, []byte(host)...)
		} else {
			req = append(req, ip...)
		}
		req = append(req, byte(port>>8), byte(port&0xff))
		conn.Write(req)

		header := make([]byte, 4)
		if _, err := io.ReadFull(conn, header); err != nil {
			conn.Close()
			return nil, err
		}
		if header[1] != 0x00 {
			conn.Close()
			return nil, fmt.Errorf("socks5 connect failed: 0x%02x", header[1])
		}

		switch header[3] {
		case 0x01:
			io.ReadFull(conn, make([]byte, 4+2))
		case 0x03:
			lenBuf := make([]byte, 1)
			io.ReadFull(conn, lenBuf)
			io.ReadFull(conn, make([]byte, int(lenBuf[0])+2))
		case 0x04:
			io.ReadFull(conn, make([]byte, 16+2))
		}

		return conn, nil
	}

	transport := &http.Transport{
		Dial:            dialFunc,
		MaxIdleConns:    500,
		MaxConnsPerHost: 500,
		IdleConnTimeout: 90 * time.Second,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}

	return func(key string) error {
		var resp *http.Response
		var err error

		if reqType == "set" {
			resp, err = client.Post(
				fmt.Sprintf("http://%s/set?key=%s&value=bench", targetAddr, key),
				"text/plain", nil,
			)
		} else {
			resp, err = client.Get(
				fmt.Sprintf("http://%s/get?key=%s", targetAddr, key),
			)
		}
		if err != nil {
			return err
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode >= 500 {
			return fmt.Errorf("status %d", resp.StatusCode)
		}
		return nil
	}
}

// ============================================================
// tls 模式：Mode 3 协议直测
// 每个 goroutine 独占一条 TLS 长连接
// ============================================================

func makeTLSFuncs(proxyAddr, targetAddr, deviceUUID, reqType string, concurrency int) []func(string) error {
	funcs := make([]func(string) error, concurrency)
	for i := 0; i < concurrency; i++ {
		funcs[i] = makeSingleTLSFunc(proxyAddr, targetAddr, deviceUUID, reqType)
	}
	return funcs
}

func makeSingleTLSFunc(proxyAddr, targetAddr, deviceUUID, reqType string) func(string) error {
	conn := tlsConnect(proxyAddr, targetAddr, deviceUUID)

	return func(key string) error {
		// 连接断了就重连
		if conn == nil {
			conn = tlsConnect(proxyAddr, targetAddr, deviceUUID)
			if conn == nil {
				return fmt.Errorf("reconnect failed")
			}
		}

		// 构造 HTTP 请求
		var httpReq string
		if reqType == "set" {
			httpReq = fmt.Sprintf(
				"POST /set?key=%s&value=bench HTTP/1.1\r\nHost: %s\r\nContent-Length: 0\r\n\r\n",
				key, targetAddr,
			)
		} else {
			httpReq = fmt.Sprintf(
				"GET /get?key=%s HTTP/1.1\r\nHost: %s\r\n\r\n",
				key, targetAddr,
			)
		}

		// 发送请求帧
		if err := writeFrame(conn, []byte(httpReq)); err != nil {
			conn.Close()
			conn = nil
			return err
		}

		// 读取响应帧: [status:1][length:4][payload]
		var respStatus uint8
		if err := binary.Read(conn, binary.BigEndian, &respStatus); err != nil {
			conn.Close()
			conn = nil
			return err
		}
		var respLen uint32
		if err := binary.Read(conn, binary.BigEndian, &respLen); err != nil {
			conn.Close()
			conn = nil
			return err
		}
		if respLen > 0 {
			buf := make([]byte, respLen)
			if _, err := io.ReadFull(conn, buf); err != nil {
				conn.Close()
				conn = nil
				return err
			}
		}

		if respStatus != 0x00 {
			return fmt.Errorf("blocked: 0x%02x", respStatus)
		}
		return nil
	}
}

// tlsConnect 建立 TLS 连接 + 发送握手包
func tlsConnect(proxyAddr, targetAddr, deviceUUID string) *tls.Conn {
	conn, err := tls.Dial("tcp", proxyAddr, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil
	}

	hs := buildHandshake(deviceUUID, targetAddr)
	if err := writeFrame(conn, hs); err != nil {
		conn.Close()
		return nil
	}

	var status uint8
	if err := binary.Read(conn, binary.BigEndian, &status); err != nil {
		conn.Close()
		return nil
	}
	if status != 0x00 {
		conn.Close()
		return nil
	}

	return conn
}

// ============================================================
// 协议辅助函数
// ============================================================

func writeFrame(w io.Writer, payload []byte) error {
	if err := binary.Write(w, binary.BigEndian, uint32(len(payload))); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func buildHandshake(uuid, targetAddr string) []byte {
	host, portStr, _ := net.SplitHostPort(targetAddr)
	port := 80
	fmt.Sscanf(portStr, "%d", &port)

	uuidBytes := []byte(uuid)

	var buf []byte
	buf = append(buf, 0x54, 0x48, 0x01)
	buf = append(buf, byte(len(uuidBytes)))
	buf = append(buf, uuidBytes...)

	ip := net.ParseIP(host).To4()
	if ip != nil {
		buf = append(buf, 0x01)
	} else {
		ip = net.ParseIP(host)
		buf = append(buf, 0x02)
	}
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, uint16(port))
	buf = append(buf, portBuf...)
	buf = append(buf, ip...)

	return buf
}
