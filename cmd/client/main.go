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
	grpcDialOpts := buildGRPCDialOpts(cfg, deviceUUID)

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

// main.go 中替换 buildGRPCDialOpts 函数
func buildGRPCDialOpts(cfg *configs.ClientConfig, deviceUUID string) []grpc.DialOption {
	tlsCfg := cfg.TLS

	// ====== none 模式：直接跳过 TLS ======
	if tlsCfg.Mode == configs.TLSModeNone {
		log.Println("[Mode 1/2] TLS disabled (tls.mode=none)")
		return []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	}

	// ====== 确定证书路径（严格模式用配置值，宽容模式保持自动检测） ======
	caCertPath := tlsCfg.CACert
	clientCertPath := tlsCfg.ClientCert
	clientKeyPath := tlsCfg.ClientKey

	if clientCertPath == "" {
		// 自动检测：优先用设备 UUID 命名的证书，其次用默认证书
		autoCert := fmt.Sprintf("./data/certs/%s.crt", deviceUUID)
		autoKey := fmt.Sprintf("./data/certs/%s.key", deviceUUID)
		if _, err := os.Stat(autoCert); err == nil {
			clientCertPath = autoCert
			clientKeyPath = autoKey
		} else {
			clientCertPath = "./data/certs/client.crt"
			clientKeyPath = "./data/certs/client.key"
		}
	}
	if caCertPath == "" {
		caCertPath = "./data/ca/ca.crt"
	}

	tlsConfig, err := pki.ClientTLSConfig(caCertPath, clientCertPath, clientKeyPath)
	if err != nil {
		// strict 模式下 pki.ClientTLSConfig 已经返回 error
		log.Fatalf("[FATAL] TLS initialization failed: %v", err)
	}

	if tlsConfig != nil {
		log.Printf("[Mode 1/2] mTLS enabled (cert=%s, mode=%s)", clientCertPath, tlsCfg.Mode)
		return []grpc.DialOption{grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig))}
	}

	// permissive 模式降级到达这里
	log.Printf("[Mode 1/2] TLS degraded to insecure (mode=%s)", tlsCfg.Mode)
	return []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
}
