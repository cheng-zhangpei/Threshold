package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "Threshold/pkg/proto/pb"
)

const tokenFile = ".threshold_admin_token"

var serverAddr string

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	os.Args = os.Args[1:]

	switch cmd {
	case "init":
		cmdInit()
	case "login":
		cmdLogin()
	case "logout":
		cmdLogout()
	case "register":
		cmdRegister()
	case "unregister":
		cmdUnregister()
	case "list":
		cmdList()
	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`Threshold Admin CLI

Usage:
  adminctl <command> [flags]

Commands:
  init         Initialize admin account (first time only)
  login        Authenticate and save token locally
  logout       Remove saved token
  register     Register a device to fingerprint tree
  unregister   Remove a device from fingerprint tree
  list         List all registered devices

Common Flags:
  -server    Threshold server address (default: 127.0.0.1:50051)

Examples:
  adminctl init -server 127.0.0.1:50051 -user admin -pass mypassword
  adminctl login -server 127.0.0.1:50051 -user admin -pass mypassword -ttl 24h
  adminctl register -uuid my-device -os linux -ip 10.0.0.1
  adminctl list -limit 50
  adminctl logout`)
}

// ============================================================
// init — 首次初始化管理员
// ============================================================
func cmdInit() {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	server := fs.String("server", "127.0.0.1:50051", "server address")
	user := fs.String("user", "", "admin username")
	pass := fs.String("pass", "", "admin password")
	passcode := fs.String("passcode", "", "one-time passcode from server output")
	fs.Parse(os.Args[1:])

	if *user == "" || *pass == "" {
		log.Fatal("error: -user and -pass are required")
	}
	if *passcode == "" {
		log.Fatal("error: -passcode is required (check server console output)")
	}

	client, conn := connect(*server)
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.InitAdmin(ctx, &pb.InitAdminRequest{
		Passcode: *passcode,
		Username: *user,
		Password: *pass,
	})
	if err != nil {
		log.Fatalf("RPC error: %v", err)
	}
	if resp.Success {
		fmt.Println("Admin initialized successfully.")
		fmt.Println("Run 'adminctl login' to authenticate.")
	} else {
		fmt.Fprintf(os.Stderr, "Failed: %s\n", resp.Reason)
		os.Exit(1)
	}
}

// ============================================================
// login — 登录获取 Token 并保存到本地
// ============================================================

func cmdLogin() {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	server := fs.String("server", "127.0.0.1:50051", "server address")
	user := fs.String("user", "", "admin username")
	pass := fs.String("pass", "", "admin password")
	ttl := fs.String("ttl", "24h", "token TTL (e.g. 1h, 24h, 7d)")
	fs.Parse(os.Args[1:])

	if *user == "" || *pass == "" {
		log.Fatal("error: -user and -pass are required")
	}

	ttlDuration, err := time.ParseDuration(*ttl)
	if err != nil {
		log.Fatalf("invalid TTL: %v", err)
	}

	client, conn := connect(*server)
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.LoginAdmin(ctx, &pb.LoginAdminRequest{
		Username:   *user,
		Password:   *pass,
		TtlSeconds: int64(ttlDuration.Seconds()),
	})
	if err != nil {
		log.Fatalf("RPC error: %v", err)
	}
	if !resp.Success {
		fmt.Fprintf(os.Stderr, "Login failed: %s\n", resp.Reason)
		os.Exit(1)
	}

	if err := saveToken(resp.Token); err != nil {
		log.Fatalf("save token: %v", err)
	}

	expires := time.UnixMilli(resp.ExpiresAt).Format(time.RFC3339)
	fmt.Printf("Logged in as %s\n", *user)
	fmt.Printf("Token expires: %s\n", expires)
}

// ============================================================
// logout — 删除本地 Token
// ============================================================

func cmdLogout() {
	path := tokenFilePath()
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			fmt.Println("No saved token found.")
		} else {
			log.Fatalf("remove token: %v", err)
		}
		return
	}
	fmt.Println("Token removed. You have been logged out.")
}

// ============================================================
// register — 注册设备
// ============================================================

func cmdRegister() {
	fs := flag.NewFlagSet("register", flag.ExitOnError)
	server := fs.String("server", "127.0.0.1:50051", "server address")
	uuid := fs.String("uuid", "", "device UUID (required)")
	osType := fs.String("os", "linux", "OS type")
	ip := fs.String("ip", "", "device IP (auto-detect if empty)")
	fs.Parse(os.Args[1:])

	if *uuid == "" {
		log.Fatal("error: -uuid is required")
	}
	if *ip == "" {
		*ip = getLocalIP()
	}

	tk := mustLoadToken()
	client, conn := connect(*server)
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.RegisterDevice(ctx, &pb.RegisterDeviceRequest{
		Token:      tk,
		DeviceUuid: *uuid,
		OsType:     *osType,
		Ip:         *ip,
	})
	if err != nil {
		log.Fatalf("RPC error: %v", err)
	}
	if resp.Success {
		fmt.Printf("Device registered: %s (%s/%s)\n", *uuid, *osType, *ip)
	} else {
		fmt.Fprintf(os.Stderr, "Failed: %s\n", resp.Reason)
		os.Exit(1)
	}
}

// ============================================================
// unregister — 注销设备
// ============================================================

func cmdUnregister() {
	fs := flag.NewFlagSet("unregister", flag.ExitOnError)
	server := fs.String("server", "127.0.0.1:50051", "server address")
	uuid := fs.String("uuid", "", "device UUID (required)")
	osType := fs.String("os", "linux", "OS type")
	ip := fs.String("ip", "", "device IP")
	fs.Parse(os.Args[1:])

	if *uuid == "" {
		log.Fatal("error: -uuid is required")
	}

	tk := mustLoadToken()
	client, conn := connect(*server)
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.UnregisterDevice(ctx, &pb.UnregisterDeviceRequest{
		Token:      tk,
		DeviceUuid: *uuid,
		OsType:     *osType,
		Ip:         *ip,
	})
	if err != nil {
		log.Fatalf("RPC error: %v", err)
	}
	if resp.Success {
		fmt.Printf("Device unregistered: %s\n", *uuid)
	} else {
		fmt.Fprintf(os.Stderr, "Failed: %s\n", resp.Reason)
		os.Exit(1)
	}
}

// ============================================================
// list — 列出已注册设备
// ============================================================

func cmdList() {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	server := fs.String("server", "127.0.0.1:50051", "server address")
	limit := fs.Int("limit", 100, "max devices to list")
	fs.Parse(os.Args[1:])

	tk := mustLoadToken()
	client, conn := connect(*server)
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.ListDevices(ctx, &pb.ListDevicesRequest{
		Token: tk,
		Limit: int32(*limit),
	})
	if err != nil {
		log.Fatalf("RPC error: %v", err)
	}

	if len(resp.Devices) == 0 {
		fmt.Println("No registered devices.")
		return
	}

	fmt.Printf("%-40s %-10s %-15s\n", "UUID", "OS", "IP")
	fmt.Printf("%-40s %-10s %-15s\n", "----------------------------------------", "----------", "---------------")
	for _, d := range resp.Devices {
		fmt.Printf("%-40s %-10s %-15s\n", d.DeviceUuid, d.OsType, d.Ip)
	}
	fmt.Printf("\nTotal: %d device(s)\n", len(resp.Devices))
}

// ============================================================
// 辅助函数
// ============================================================

func connect(addr string) (pb.SecurityProxyClient, *grpc.ClientConn) {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("connect to %s: %v", addr, err)
	}
	return pb.NewSecurityProxyClient(conn), conn
}

func mustLoadToken() string {
	tk, err := loadToken()
	if err != nil {
		log.Fatalf("not logged in (run 'adminctl login'): %v", err)
	}
	return tk
}

func tokenFilePath() string {
	dir := "./data"
	os.MkdirAll(dir, 0700)
	return filepath.Join(dir, "admin.token")
}

func saveToken(token string) error {
	return os.WriteFile(tokenFilePath(), []byte(token), 0600)
}

func loadToken() (string, error) {
	data, err := os.ReadFile(tokenFilePath())
	if err != nil {
		return "", fmt.Errorf("no saved token: %w", err)
	}
	tk := string(data)
	if tk == "" {
		return "", fmt.Errorf("empty token file")
	}
	return tk, nil
}

func getLocalIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}
