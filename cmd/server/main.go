package main

import (
	"Threshold/pkg/pki"
	"Threshold/pkg/waiter"
	"Threshold/server/router/router_v1"
	"Threshold/server/router/router_v2"
	"Threshold/server/tcp_listener"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"Threshold/pkg/config"
	"Threshold/pkg/storage"
	"Threshold/pkg/types"
	"Threshold/server/alert"
	"Threshold/server/decision"
	"Threshold/server/dispatch"
	"Threshold/server/fingerprint"
	servergrpc "Threshold/server/grpc"
	"Threshold/server/output"
	"Threshold/server/portrait"

	"google.golang.org/grpc/credentials"
)

func main() {
	var cfgPath string
	flag.StringVar(&cfgPath, "config", "./config/server.yaml", "path to client config file")
	flag.Parse()

	cfg, err := config.LoadServerConfig(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load configs: %v\n", err)
		os.Exit(1)
	}
	PrintServerConfig(cfg)
	file, err := os.OpenFile("./log/server.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Fatal(err)
	}
	log.SetOutput(io.MultiWriter(os.Stdout, file))
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	// --- 存储层 ---
	store, err := storage.NewBoltStore(cfg.Fingerprint.DBPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open store: %v\n", err)
		os.Exit(1)
	}
	defer store.Close()

	wal, err := storage.NewWAL(cfg.WALDir)
	if err != nil {
		panic("the wal dir is invalid")
	}
	wal.StartFlusher(store, 5*time.Second)

	// --- 指纹匹配引擎 ---
	fpTree, err := fingerprint.NewTree(store, wal, cfg.Fingerprint)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fingerprint tree: %v\n", err)
		os.Exit(1)
	}
	waiterInstance := waiter.NewWaiter(30 * time.Second)

	log.Printf("fingerprint tree is loaded\n%s", fpTree.Print())
	outputBuf := output.NewOutputBufferWithConfig(
		cfg.Output.MaxSize,
		cfg.Output.SenderWorkers,
		cfg.Output.SenderQueueSize,
		cfg.Output.SenderEnable,
		waiterInstance,
	)
	defer outputBuf.Stop()

	// --- 用户画像 + 决策引擎 ---
	var ps *portrait.Store
	if cfg.Portrait.Enable {
		ps = portrait.NewStore(store)
	}
	var engine *decision.Engine
	if cfg.Portrait.Enable {
		engine = decision.NewEngine(ps)
	}

	// --- 告警队列 ---
	alertQueue := alert.NewAlertQueue()

	// --- DispatchManager ---
	policy := dispatch.PolicyFromConfig(types.PoolPolicy{
		MinWorkers:             cfg.Dispatch.MinWorkers,
		MaxWorkers:             cfg.Dispatch.MaxWorkers,
		ScaleUpThreshold:       cfg.Dispatch.ScaleUpThreshold,
		ScaleUpStep:            cfg.Dispatch.ScaleUpStep,
		MaxQueueSize:           cfg.Dispatch.MaxQueueSize,
		IdleTimeoutSec:         cfg.Dispatch.IdleTimeoutSec,
		HealthCheckIntervalSec: cfg.Dispatch.HealthCheckIntervalSec,
	})
	var dm *dispatch.DispatchManager
	if cfg.Dispatch.Enabled {
		dm = dispatch.NewDispatchManager(dispatch.DispatcherConfig{
			Policy: policy,
			Store:  store,
			DecisionFn: func(ctx *types.ConnectionContext, history []*types.ConnectionSummary, riskLevel types.RiskLevel) *types.Decision {
				return engine.Evaluate(ctx, history, riskLevel)
			},
		}, outputBuf, alertQueue)
		defer dm.Shutdown()
	}

	// --- Router ---
	riskTable := router_v1.NewOperationRiskTable()
	var r *router_v1.Router
	var r2 *router_v2.Router
	if cfg.Router.Enabled {
		r = router_v1.NewRouter(riskTable, outputBuf, dm, cfg.Router.Consumers, cfg.Router.QueueSize)
		defer r.Shutdown()
		if cfg.Router.R2Config != "" {
			r2, err = router_v2.NewRouterFromFile(
				cfg.Router.R2Config,
				outputBuf,
				dm,
				3,
				4096,
			)
			defer r2.Shutdown()
		}
		if err != nil {
			log.Fatalf("init router_v2: %v", err)
		}
		log.Printf("router started: %d consumers, queue size %d\n", cfg.Router.Consumers, cfg.Router.QueueSize)
	}

	// ============================================================
	// gRPC TLS 配置（自动检测证书，有则 mTLS，无则降级）
	// ============================================================
	serverCertPath := "./data/certs/server.crt"
	serverKeyPath := "./data/certs/server.key"
	caCertPath := "./data/ca/ca.crt"

	var grpcCreds credentials.TransportCredentials
	if _, err := os.Stat(serverCertPath); err == nil {
		tlsCfg, err := pki.ServerTLSConfig(serverCertPath, serverKeyPath, caCertPath)
		if err != nil {
			log.Fatalf("server TLS config: %v", err)
		}
		grpcCreds = credentials.NewTLS(tlsCfg)
		log.Println("gRPC server: mTLS enabled")
	} else {
		log.Println("gRPC server: no TLS (dev mode)")
	}

	// --- gRPC Server ---
	grpcServer, err := servergrpc.New(cfg, fpTree, engine, r, r2, outputBuf, alertQueue, ps, waiterInstance, dm, store, grpcCreds)
	if err != nil {
		fmt.Fprintf(os.Stderr, "grpc server: %v\n", err)
		os.Exit(1)
	}

	go func() {
		log.Printf("Threshold gRPC server starting on %s\n", cfg.GRPC.ListenAddr)
		if err := grpcServer.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "grpc error: %v\n", err)
			os.Exit(1)
		}
	}()

	// ═══════════════════════════════════════════════════════
	//  Mode 3: 直连模式 (Direct Connect)
	// ═══════════════════════════════════════════════════════
	if cfg.DirectConnect.Enabled {
		dc := cfg.DirectConnect

		tcpCfg := tcplistener.Config{
			Enabled:    dc.Enabled,
			ListenAddr: dc.ListenAddr,
			CertFile:   dc.CertFile,
			KeyFile:    dc.KeyFile,
			CACertFile: "./data/ca/ca.crt",

			// 连接池
			MaxConns:    dc.MaxConns,
			MaxPerHost:  dc.MaxPerHost,
			MaxLifetime: config.ParseDuration(dc.MaxLifetime, 30*time.Minute),
			MaxIdle:     config.ParseDuration(dc.MaxIdle, 5*time.Minute),

			// 清理
			JanitorInterval: config.ParseDuration(dc.JanitorInterval, 30*time.Second),

			// 超时
			DialTimeout:         config.ParseDuration(dc.DialTimeout, 5*time.Second),
			TLSHandshakeTimeout: config.ParseDuration(dc.TLSHandshakeTimeout, 10*time.Second),
			RequestReadTimeout:  config.ParseDuration(dc.RequestReadTimeout, 60*time.Second),
			WriteTimeout:        config.ParseDuration(dc.WriteTimeout, 10*time.Second),
			ReadTimeout:         config.ParseDuration(dc.ReadTimeout, 10*time.Second),

			// 帧限制
			MaxPayloadSize:  dc.MaxPayloadSize,
			MaxResponseSize: dc.MaxResponseSize,
		}

		tcpListener := tcplistener.New(
			tcpCfg, fpTree, alertQueue,
			tcplistener.Deps{
				Router:   r2,
				Engine:   engine,
				Portrait: ps,
			},
		)

		go func() {
			log.Printf("Threshold direct-connect starting on %s\n", tcpCfg.ListenAddr)
			if err := tcpListener.Start(); err != nil {
				fmt.Fprintf(os.Stderr, "tcplistener error: %v\n", err)
				log.Printf("[tcplistener] FAILED: %v", err)
			}
		}()
	} else {
		fmt.Println("direct-connect mode disabled")
	}

	// --- 等待退出信号 ---
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	fmt.Println("Threshold server shutting down...")
	grpcServer.GracefulStop()
}

func PrintServerConfig(cfg *config.ServerConfig) {
	dc := cfg.DirectConnect

	banner := `
╔══════════════════════════════════════════════════════════════╗
║             Threshold Server - Configuration                 ║
╚══════════════════════════════════════════════════════════════╝`

	fmt.Println(banner)

	// gRPC
	printSection("gRPC Layer", []kv{
		{"Listen Addr", cfg.GRPC.ListenAddr},
		{"Rate Limit", fmt.Sprintf("%d req/s", cfg.GRPC.RateLimit)},
		{"Bucket Size", fmt.Sprintf("%d", cfg.GRPC.BucketSize)},
	})

	// Router
	printSection("Router", []kv{
		{"Enabled", fmt.Sprintf("%v", cfg.Router.Enabled)},
		{"V2 Rules File", cfg.Router.R2Config},
		{"Consumers", fmt.Sprintf("%d", cfg.Router.Consumers)},
		{"Queue Size", fmt.Sprintf("%d", cfg.Router.QueueSize)},
	})

	// Dispatch
	printSection("Dispatch", []kv{
		{"Enabled", fmt.Sprintf("%v", cfg.Dispatch.Enabled)},
		{"Worker Range", fmt.Sprintf("[%d, %d]", cfg.Dispatch.MinWorkers, cfg.Dispatch.MaxWorkers)},
		{"ScaleUp Threshold", fmt.Sprintf("%d", cfg.Dispatch.ScaleUpThreshold)},
		{"Max Queue Size", fmt.Sprintf("%d", cfg.Dispatch.MaxQueueSize)},
	})

	// Fingerprint
	printSection("Fingerprint Engine", []kv{
		{"DB Path", cfg.Fingerprint.DBPath},
		{"Match Mode", cfg.Fingerprint.MatchMode},
	})

	// Portrait
	printSection("Portrait Engine", []kv{
		{"Enabled", fmt.Sprintf("%v", cfg.Portrait.Enable)},
		{"DB Path", cfg.Portrait.DBPath},
		{"History Limit", fmt.Sprintf("%d", cfg.Portrait.HistoryLimit)},
	})

	// Output
	printSection("Output Layer", []kv{
		{"Buffer Size", fmt.Sprintf("%d", cfg.Output.MaxSize)},
		{"Sender Enabled", fmt.Sprintf("%v", cfg.Output.SenderEnable)},
		{"Sender Workers", fmt.Sprintf("%d", cfg.Output.SenderWorkers)},
		{"Sender Queue Size", fmt.Sprintf("%d", cfg.Output.SenderQueueSize)},
	})

	// TLS (gRPC)
	printSection("gRPC TLS", []kv{
		{"Enabled", fmt.Sprintf("%v", cfg.TLS.Enabled)},
		{"Cert File", cfg.TLS.CertFile},
		{"CA File", cfg.TLS.CAFile},
		{"Client Auth", fmt.Sprintf("%v", cfg.TLS.RequireClientAuth)},
	})

	// Mode 3: Direct Connect
	printSection("Mode 3 Direct Connect", []kv{
		{"Enabled", fmt.Sprintf("%v", dc.Enabled)},
		{"Listen Addr", dc.ListenAddr},
		{"Cert File", dc.CertFile},
		{"CA File", "./data/ca/ca.crt"},
		{"", ""},
		{"Max Conns", fmt.Sprintf("%d", dc.MaxConns)},
		{"Max Per Host", fmt.Sprintf("%d", dc.MaxPerHost)},
		{"Max Lifetime", dc.MaxLifetime},
		{"Max Idle", dc.MaxIdle},
		{"Janitor Interval", dc.JanitorInterval},
		{"", ""},
		{"Dial Timeout", dc.DialTimeout},
		{"TLS Handshake Timeout", dc.TLSHandshakeTimeout},
		{"Request Read Timeout", dc.RequestReadTimeout},
		{"Write Timeout", dc.WriteTimeout},
		{"Read Timeout", dc.ReadTimeout},
		{"", ""},
		{"Max Payload Size", fmtSize(dc.MaxPayloadSize)},
		{"Max Response Size", fmtSize(dc.MaxResponseSize)},
	})

	// WAL
	printSection("Storage", []kv{
		{"WAL Dir", cfg.WALDir},
	})

	fmt.Println("════════════════════════════════════════════════════════════")
}

// ============================================================
// helpers
// ============================================================

type kv struct {
	key string
	val string
}

func printSection(title string, items []kv) {
	fmt.Printf("\n  ┌─ %s\n", title)
	for _, item := range items {
		if item.key == "" && item.val == "" {
			fmt.Println("  │")
			continue
		}
		if item.val == "" {
			fmt.Printf("  │  %-24s  (not set)\n", item.key)
		} else {
			fmt.Printf("  │  %-24s  %s\n", item.key, item.val)
		}
	}
	fmt.Println("  └──────────────────────────────────────────")
}

func fmtSize(bytes int) string {
	switch {
	case bytes >= 1<<20:
		return fmt.Sprintf("%d MB (%d bytes)", bytes>>20, bytes)
	case bytes >= 1<<10:
		return fmt.Sprintf("%d KB (%d bytes)", bytes>>10, bytes)
	default:
		return fmt.Sprintf("%d bytes", bytes)
	}
}
