package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"Threshold/pkg/config"
	"Threshold/client/proxy"
)

func main() {
	cfgPath := "config/client.yaml"
	if len(os.Args) > 1 {
		cfgPath = os.Args[1]
	}

	cfg, err := config.LoadClientConfig(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load config: %v\n", err)
		os.Exit(1)
	}

	p := proxy.New(proxy.Config{
		ListenAddr: cfg.Proxy.ListenAddr,
		ServerAddr: cfg.Proxy.ServerAddr,
		DeviceUUID: cfg.Proxy.DeviceUUID,
		UserID:     "default-user",
	})

	go func() {
		if err := p.Start(); err != nil {
			log.Fatalf("proxy error: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	fmt.Println("Threshold client shutting down...")
	p.Stop()
}