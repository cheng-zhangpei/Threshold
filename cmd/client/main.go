// client/main.go
package main

import (
	"Threshold/client/configs"
	"Threshold/client/proxy"
	"Threshold/client/socks5" // 新增 SOCKS5 包
	client "Threshold/client/utils"
	pb "Threshold/pkg/proto/pb"
	"flag"
	"fmt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	// 1. 解析命令行参数，加载配置
	var cfgPath string
	flag.StringVar(&cfgPath, "config", "./client/configs/clients.yaml", "path to client config file")
	flag.Parse()

	cfg, err := configs.LoadClientConfig(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load config: %v\n", err)
		os.Exit(1)
	}

	// 2. 设置日志（保留你原来的 MultiWriter）
	file, err := os.OpenFile("./log/client.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Fatal(err)
	}
	log.SetOutput(io.MultiWriter(os.Stdout, file))
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	// 3. 采集设备信息（优先配置，否则自动获取）
	deviceUUID, osType := client.GetDeviceInfo(cfg.Proxy.DeviceUUID, cfg.Proxy.OSType)
	localIP := client.GetLocalIP()
	log.Printf("Device: UUID=%s, OS=%s, IP=%s", deviceUUID, osType, localIP)

	// 4. 确定各模块使用的 UserID（优先模块专用，否则用全局）
	globalUserID := cfg.UserID
	proxyUserID := cfg.Proxy.UserID
	if proxyUserID == "" {
		proxyUserID = globalUserID
	}
	socks5UserID := cfg.Socks5.UserID
	if socks5UserID == "" {
		socks5UserID = globalUserID
	}

	// 5. 创建共享的 gRPC Client（供 SOCKS5 使用；proxy 模块内部自己创建，保持其独立性）
	//    注意：如果两种模式都启用，proxy 会额外创建一个连接，暂时可接受
	// TODO(CHENG) 注册设备（测试用，后续改为管理员权限）
	//=======================================================================================================================
	var grpcClient pb.SecurityProxyClient
	//var grpcConn *grpc.ClientConn
	//if cfg.Proxy.ListenAddr != "" || cfg.Socks5.Enabled {
	//	var err error
	//	grpcConn, err = grpc.NewClient(cfg.Proxy.ServerAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	//	if err != nil {
	//		log.Fatalf("dial server: %v", err)
	//	}
	//	defer grpcConn.Close()
	//	grpcClient = pb.NewSecurityProxyClient(grpcConn)
	//
	//	registerCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	//	defer cancel()
	//	registerResp, err := grpcClient.RegisterDevice(registerCtx, &pb.RegisterDeviceRequest{
	//		DeviceUuid: deviceUUID,
	//		OsType:     osType,
	//		Ip:         localIP,
	//	})
	//	if err != nil {
	//		log.Printf("[WARN] device registration error: %v", err)
	//	} else if registerResp.Success {
	//		log.Printf("[INFO] Device registered successfully: %s", deviceUUID)
	//	} else {
	//		log.Printf("[WARN] Device registration failed: %s", registerResp.Reason)
	//	}
	//}
	//========================================================================================================================
	if cfg.Socks5.Enabled {
		grpcConn, err := grpc.NewClient(cfg.Proxy.ServerAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			log.Fatalf("dial server for socks5: %v", err)
		}
		defer grpcConn.Close()
		grpcClient = pb.NewSecurityProxyClient(grpcConn)
	}

	// ================================================================
	// 模式一：原生 gRPC 代理（为 IDV Client 服务）
	// 条件：配置中 listen_addr 不为空（或者增加 enabled 字段）
	// ================================================================
	if cfg.Proxy.ListenAddr != "" {
		p := proxy.New(proxy.Config{
			ListenAddr: cfg.Proxy.ListenAddr,
			ServerAddr: cfg.Proxy.ServerAddr,
			DeviceUUID: deviceUUID,
			UserID:     proxyUserID,
			OSType:     osType,
		})
		go func() {
			if err := p.Start(); err != nil {
				log.Fatalf("proxy (mode 1) error: %v", err)
			}
		}()
		log.Printf("[Mode 1] gRPC proxy listening on %s", cfg.Proxy.ListenAddr)
	}

	// ================================================================
	// 模式二：SOCKS5 转 gRPC 代理（为通用应用服务）
	// 条件：配置中 socks5.enabled = true
	// ================================================================
	if cfg.Socks5.Enabled {
		// 注意：SOCKS5 网关需要目标服务器地址，我们复用 cfg.Proxy.ServerAddr
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

	// 如果没有启动任何模式，给出警告
	if cfg.Proxy.ListenAddr == "" && !cfg.Socks5.Enabled {
		log.Println("WARNING: No proxy mode enabled. Check your config.")
	}

	// 6. 等待退出信号
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Threshold client shutting down...")
}
