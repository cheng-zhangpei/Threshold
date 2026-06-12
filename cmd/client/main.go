package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"Threshold/pkg/config"
)

func main() {
	cfgPath := "config/client.yaml"
	if len(os.Args) > 1 {
		cfgPath = os.Args[1]
	}

	cfg, err := config.LoadClientConfig(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(1)
	}

	_ = cfg // 后续用 cfg 初始化各组件
	fmt.Printf("Threshold client starting, proxy on %s\n", cfg.Proxy.ListenAddr)

	// TODO: 初始化重定向模块（将 IDV 客户端流量导向本地代理）
	// TODO: 初始化行为采集器
	// TODO: 初始化本地代理（附加指纹 + gRPC 转发到服务端）
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	fmt.Println("Threshold client shutting down...")
}
