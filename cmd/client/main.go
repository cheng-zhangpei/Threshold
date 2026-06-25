package main

import (
	"Threshold/client/configs"
	"Threshold/client/proxy"
	"Threshold/client/socks5"
	client "Threshold/client/utils"
	"Threshold/pkg/pki"
	pb "Threshold/pkg/proto/pb"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	var cfgPath string
	flag.StringVar(&cfgPath, "config", "./client/configs/clients.yaml", "path to client config file")
	flag.Parse()

	cfg, err := configs.LoadClientConfig(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load config: %v\n", err)
		os.Exit(1)
	}

	file, err := os.OpenFile("./log/client.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Fatal(err)
	}
	log.SetOutput(io.MultiWriter(os.Stdout, file))
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	deviceUUID, osType := client.GetDeviceInfo(cfg.Proxy.DeviceUUID, cfg.Proxy.OSType)
	localIP := client.GetLocalIP()
	log.Printf("Device: UUID=%s, OS=%s, IP=%s", deviceUUID, osType, localIP)

	globalUserID := cfg.UserID
	proxyUserID := cfg.Proxy.UserID
	if proxyUserID == "" {
		proxyUserID = globalUserID
	}
	socks5UserID := cfg.Socks5.UserID
	if socks5UserID == "" {
		socks5UserID = globalUserID
	}

	// ============================================================
	// gRPC 连接：自动检测客户端证书，有则 mTLS，无则降级
	// ============================================================
	grpcDialOpts := buildGRPCDialOpts(deviceUUID)

	var grpcClient pb.SecurityProxyClient
	if cfg.Socks5.Enabled {
		grpcConn, err := grpc.NewClient(cfg.Proxy.ServerAddr, grpcDialOpts...)
		if err != nil {
			log.Fatalf("dial server for socks5: %v", err)
		}
		defer grpcConn.Close()
		grpcClient = pb.NewSecurityProxyClient(grpcConn)
	}

	// 模式一：原生 gRPC 代理
	if cfg.Proxy.ListenAddr != "" {
		p := proxy.New(proxy.Config{
			ListenAddr: cfg.Proxy.ListenAddr,
			ServerAddr: cfg.Proxy.ServerAddr,
			DeviceUUID: deviceUUID,
			UserID:     proxyUserID,
			OSType:     osType,
			DialOpts:   grpcDialOpts,
		})
		go func() {
			if err := p.Start(); err != nil {
				log.Fatalf("proxy (mode 1) error: %v", err)
			}
		}()
		log.Printf("[Mode 1] gRPC proxy listening on %s", cfg.Proxy.ListenAddr)
	}

	// 模式二：SOCKS5 转 gRPC
	if cfg.Socks5.Enabled {
		gateway := socks5.NewGateway(
			cfg.Socks5.ListenAddr,
			socks5UserID,
			deviceUUID,
			osType,
			localIP,
			grpcClient,
		)
		go func() {
			if err := gateway.Start(); err != nil {
				log.Fatalf("socks5 (mode 2) error: %v", err)
			}
		}()
		log.Printf("[Mode 2] SOCKS5 proxy listening on %s", cfg.Socks5.ListenAddr)
	}

	if cfg.Proxy.ListenAddr == "" && !cfg.Socks5.Enabled {
		log.Println("WARNING: No proxy mode enabled. Check your config.")
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Threshold client shutting down...")
}

// buildGRPCDialOpts 构建 gRPC 连接选项，自动检测证书
func buildGRPCDialOpts(deviceUUID string) []grpc.DialOption {
	// 证书路径：优先用设备 UUID 命名的证书
	clientCertPath := fmt.Sprintf("./data/certs/%s.crt", deviceUUID)
	clientKeyPath := fmt.Sprintf("./data/certs/%s.key", deviceUUID)
	caCertPath := "./data/ca/ca.crt"

	// 如果设备证书不存在，尝试用默认客户端证书
	if _, err := os.Stat(clientCertPath); err != nil {
		clientCertPath = "./data/certs/client.crt"
		clientKeyPath = "./data/certs/client.key"
	}

	if _, err := os.Stat(clientCertPath); err == nil {
		// mTLS 模式
		tlsCfg, err := pki.ClientTLSConfig(clientCertPath, clientKeyPath, caCertPath)
		if err != nil {
			log.Printf("[WARN] client TLS config failed: %v, falling back to insecure", err)
			return []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
		}
		log.Printf("[Mode 1/2] mTLS enabled (cert=%s)", clientCertPath)
		return []grpc.DialOption{grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg))}
	}

	// 降级：无 TLS（开发模式）
	log.Println("[Mode 1/2] no client cert found, using insecure connection")
	return []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
}
