package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"

	"Threshold/client/proxy"
	"Threshold/pkg/config"
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
	file, err := os.OpenFile("/var/log/myapp.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Fatal(err)
	}
	log.SetOutput(io.MultiWriter(os.Stdout, file))
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
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
