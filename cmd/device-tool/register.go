package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"Threshold/pkg/config"
	pb "Threshold/pkg/proto/pb"
)

func main() {
	// 命令行参数
	var (
		configPath string
		action     string
		deviceUUID string
		osType     string
		ip         string
	)
	flag.StringVar(&configPath, "config", "./config/client.yaml", "path to client config file")
	flag.StringVar(&action, "action", "device-tool", "action: device-tool or unregister")
	flag.StringVar(&deviceUUID, "uuid", "", "device UUID (if empty, use config value)")
	flag.StringVar(&osType, "os", "", "OS type (if empty, use config value)")
	flag.StringVar(&ip, "ip", "", "IP address (if empty, use config value)")
	flag.Parse()

	// 加载配置
	cfg, err := config.LoadClientConfig(configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	// 如果命令行未指定，从配置读取
	if deviceUUID == "" {
		deviceUUID = cfg.Proxy.DeviceUUID
	}
	if osType == "" {
		osType = "linux"
	}
	if ip == "" {
		// 自动获取本机 IP（简单实现）
		ip = getLocalIP()
	}

	if deviceUUID == "" {
		log.Fatal("device UUID is required (provide via -uuid or config)")
	}

	// 连接服务端
	conn, err := grpc.NewClient(cfg.Proxy.ServerAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("dial server: %v", err)
	}
	defer conn.Close()
	client := pb.NewSecurityProxyClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	switch action {
	case "device-tool":
		resp, err := client.RegisterDevice(ctx, &pb.RegisterDeviceRequest{
			DeviceUuid: deviceUUID,
			OsType:     osType,
			Ip:         ip,
		})
		if err != nil {
			log.Fatalf("device-tool error: %v", err)
		}
		if resp.Success {
			fmt.Printf("✅ Device registered: %s\n", deviceUUID)
		} else {
			fmt.Printf("❌ Register failed: %s\n", resp.Reason)
		}
	case "unregister":
		resp, err := client.UnregisterDevice(ctx, &pb.UnregisterDeviceRequest{
			DeviceUuid: deviceUUID,
			OsType:     osType,
			Ip:         ip,
		})
		if err != nil {
			log.Fatalf("unregister error: %v", err)
		}
		if resp.Success {
			fmt.Printf("✅ Device unregistered: %s\n", deviceUUID)
		} else {
			fmt.Printf("❌ Unregister failed: %s\n", resp.Reason)
		}
	default:
		log.Fatalf("unknown action: %s (use device-tool or unregister)", action)
	}
}

// getLocalIP 获取本机出口 IP
func getLocalIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}
