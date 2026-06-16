package main

import (
	"Threshold/server/router/router_v1"
	"Threshold/server/router/router_v2"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"

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
)

func main() {
	cfgPath := "configs/server.yaml"
	if len(os.Args) > 1 {
		cfgPath = os.Args[1]
	}

	cfg, err := config.LoadServerConfig(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load configs: %v\n", err)
		os.Exit(1)
	}
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

	wal := storage.NewWAL(store)
	recovered, _ := wal.Recover()
	if recovered > 0 {
		log.Printf("wal recovered %d entries\n", recovered)
	}

	// --- 指纹匹配引擎 ---
	fpTree, err := fingerprint.NewTree(store, wal)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fingerprint tree: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("fingerprint tree loaded\n%s", fpTree.Print())

	// --- 用户画像 + 决策引擎 ---
	var ps *portrait.Store
	if cfg.Portrait.Enable {
		ps = portrait.NewStore(store)
	}
	var engine *decision.Engine
	if cfg.Portrait.Enable {
		engine = decision.NewEngine(ps)
	}
	// --- 输出缓冲 + 告警队列 ---
	outputBuf := output.NewOutputBuffer()
	alertQueue := alert.NewAlertQueue()

	// --- DispatchManager: 异步调度 + 弹性 WorkerPool ---
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
		})
		defer dm.Shutdown()
	}

	// --- Router: 事件消费型路由 ---
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
				3,    // consumers
				4096, // queueSize
			)
			defer r2.Shutdown()
		}

		if err != nil {
			log.Fatalf("init router_v2: %v", err)
		}
		fmt.Printf("router started: %d consumers, queue size %d\n", cfg.Router.Consumers, cfg.Router.QueueSize)
	}

	// --- gRPC Server ---
	grpcServer, err := servergrpc.New(cfg, fpTree, engine, r, r2, outputBuf, alertQueue, ps)
	if err != nil {
		fmt.Fprintf(os.Stderr, "grpc server: %v\n", err)
		os.Exit(1)
	}

	go func() {
		fmt.Printf("Threshold server starting on %s\n", cfg.GRPC.ListenAddr)
		if err := grpcServer.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "grpc error: %v\n", err)
			os.Exit(1)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	fmt.Println("Threshold server shutting down...")
	grpcServer.GracefulStop()
}
