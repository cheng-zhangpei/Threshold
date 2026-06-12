package main

import (
	"fmt"

	"os"

	"os/signal"

	"syscall"

	"Threshold/pkg/config"

	"Threshold/pkg/storage"

	"Threshold/server/decision"

	"Threshold/server/fingerprint"

	"Threshold/server/portrait"

	servergrpc "Threshold/server/grpc"
)

func main() {

	cfgPath := "config/server.yaml"

	if len(os.Args) > 1 {
		cfgPath = os.Args[1]
	}

	cfg, err := config.LoadServerConfig(cfgPath)

	if err != nil {
		fmt.Fprintf(os.Stderr, "load config: %v\n", err)
		os.Exit(1)
	}

	store, err := storage.NewBoltStore(cfg.Fingerprint.DBPath)

	if err != nil {
		fmt.Fprintf(os.Stderr, "open store: %v\n", err)
		os.Exit(1)
	}

	defer store.Close()

	wal := storage.NewWAL(store)

	recovered, _ := wal.Recover()

	if recovered > 0 {
		fmt.Printf("wal recovered %d entries\n", recovered)
	}

	fpTree, err := fingerprint.NewTree(store, wal)

	if err != nil {
		fmt.Fprintf(os.Stderr, "fingerprint tree: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("fingerprint tree loaded\n%s", fpTree.Print())

	ps := portrait.NewStore(store)

	engine := decision.NewEngine(ps)

	grpcServer, err := servergrpc.New(cfg, fpTree, engine)

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
