package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"Threshold/pkg/pki"
	pb "Threshold/pkg/proto/pb"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

const tokenFile = "admin.token"

// 全局记录原始 args，子命令不再 shift os.Args
var originalArgs []string

func main() {
	originalArgs = os.Args
	if len(originalArgs) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := originalArgs[1]

	switch cmd {
	case "init":
		cmdInit(originalArgs[2:])
	case "login":
		cmdLogin(originalArgs[2:])
	case "logout":
		cmdLogout(originalArgs[2:])
	case "register":
		cmdRegister(originalArgs[2:])
	case "unregister":
		cmdUnregister(originalArgs[2:])
	case "list":
		cmdList(originalArgs[2:])
	case "ca":
		cmdCA(originalArgs[2:])
	case "cert":
		cmdCert(originalArgs[2:])
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
  ca init      Initialize Certificate Authority
  cert issue   Issue a TLS certificate

Examples:
  adminctl ca init
  adminctl cert issue -type server -hosts 127.0.0.1,localhost
  adminctl cert issue -type client -uuid my-device
  adminctl init -passcode <code> -user admin -pass mypassword
  adminctl login -server 127.0.0.1:50051 -user admin -pass mypassword -ttl 24h
  adminctl register -server 127.0.0.1:50051 -uuid my-device -os linux
  adminctl list -server 127.0.0.1:50051
  adminctl logout`)
}

// ============================================================
// ca — CA 管理
// ============================================================

func cmdCA(args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: adminctl ca init")
		os.Exit(1)
	}

	sub := args[0]
	switch sub {
	case "init":
		cmdCAInit(args[1:])
	default:
		fmt.Println("Usage: adminctl ca init")
		os.Exit(1)
	}
}

func cmdCAInit(args []string) {
	fs := flag.NewFlagSet("ca init", flag.ExitOnError)
	dir := fs.String("dir", "./data/ca", "CA output directory")
	fs.Parse(args)

	ca, err := pki.InitCA(*dir)
	if err != nil {
		log.Fatalf("CA init failed: %v", err)
	}

	fmt.Println("CA initialized successfully.")
	fmt.Printf("  CA cert: %s\n", ca.CertPath)
	fmt.Printf("  CA key:  %s\n", ca.KeyPath)
	fmt.Printf("  Valid until: %s\n", ca.Cert.NotAfter.Format("2006-01-02"))
}

// ============================================================
// cert — 证书管理
// ============================================================

func cmdCert(args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: adminctl cert issue [-type server|client] ...")
		os.Exit(1)
	}

	sub := args[0]
	switch sub {
	case "issue":
		cmdCertIssue(args[1:])
	default:
		fmt.Println("Usage: adminctl cert issue")
		os.Exit(1)
	}
}

func cmdCertIssue(args []string) {
	fs := flag.NewFlagSet("cert issue", flag.ExitOnError)
	certType := fs.String("type", "client", "certificate type: server or client")
	uuid := fs.String("uuid", "", "device UUID (required for client cert)")
	hosts := fs.String("hosts", "127.0.0.1", "comma-separated IPs/domains (for server cert)")
	days := fs.Int("days", 365, "validity in days")
	caDir := fs.String("ca-dir", "./data/ca", "CA directory")
	outDir := fs.String("out-dir", "./data/certs", "output directory")
	fs.Parse(args)

	ca, err := pki.LoadCA(*caDir)
	if err != nil {
		log.Fatalf("load CA: %v (run 'adminctl ca init' first)", err)
	}

	var req pki.CertRequest
	switch *certType {
	case "server":
		req = pki.CertRequest{
			Type:      pki.CertTypeServer,
			Hosts:     strings.Split(*hosts, ","),
			ValidDays: *days,
		}
	case "client":
		if *uuid == "" {
			log.Fatal("error: -uuid is required for client cert")
		}
		req = pki.CertRequest{
			Type:      pki.CertTypeClient,
			UUID:      *uuid,
			ValidDays: *days,
		}
	default:
		log.Fatalf("unknown type: %s (use server or client)", *certType)
	}

	bundle, err := ca.IssueCert(req, *outDir)
	if err != nil {
		log.Fatalf("issue cert: %v", err)
	}

	fmt.Printf("Certificate issued:\n")
	fmt.Printf("  Type: %s\n", *certType)
	if *certType == "client" {
		fmt.Printf("  UUID: %s\n", *uuid)
	}
	fmt.Printf("  Cert: %s\n", bundle.CertPath)
	fmt.Printf("  Key:  %s\n", bundle.KeyPath)
	fmt.Printf("  Valid until: %s\n", time.Now().AddDate(0, 0, *days).Format("2006-01-02"))
}

// ============================================================
// init — 初始化管理员
// ============================================================

func cmdInit(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	server := fs.String("server", "127.0.0.1:50051", "server address")
	user := fs.String("user", "", "admin username")
	pass := fs.String("pass", "", "admin password")
	passcode := fs.String("passcode", "", "one-time passcode from server")
	fs.Parse(args)

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
// login
// ============================================================

func cmdLogin(args []string) {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	server := fs.String("server", "127.0.0.1:50051", "server address")
	user := fs.String("user", "", "admin username")
	pass := fs.String("pass", "", "admin password")
	ttl := fs.String("ttl", "24h", "token TTL (e.g. 1h, 24h, 7d)")
	fs.Parse(args)

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
// logout
// ============================================================

func cmdLogout(args []string) {
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
// register
// ============================================================

func cmdRegister(args []string) {
	fs := flag.NewFlagSet("register", flag.ExitOnError)
	server := fs.String("server", "127.0.0.1:50051", "server address")
	uuid := fs.String("uuid", "", "device UUID (required)")
	osType := fs.String("os", "linux", "OS type")
	ip := fs.String("ip", "", "device IP (auto-detect if empty)")
	fs.Parse(args)

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
// unregister
// ============================================================

func cmdUnregister(args []string) {
	fs := flag.NewFlagSet("unregister", flag.ExitOnError)
	server := fs.String("server", "127.0.0.1:50051", "server address")
	uuid := fs.String("uuid", "", "device UUID (required)")
	osType := fs.String("os", "linux", "OS type")
	ip := fs.String("ip", "", "device IP")
	fs.Parse(args)

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
// list
// ============================================================

func cmdList(args []string) {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	server := fs.String("server", "127.0.0.1:50051", "server address")
	limit := fs.Int("limit", 100, "max devices to list")
	fs.Parse(args)

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
	clientCertPath := "./data/certs/adminctl-client.crt"
	clientKeyPath := "./data/certs/adminctl-client.key"
	caCertPath := "./data/ca/ca.crt"

	var opts []grpc.DialOption

	if _, err := os.Stat(clientCertPath); err == nil {
		tlsCfg, err := pki.ClientTLSConfig(clientCertPath, clientKeyPath, caCertPath)
		if err != nil {
			log.Fatalf("client TLS config: %v", err)
		}
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	conn, err := grpc.NewClient(addr, opts...)
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
	return filepath.Join(dir, tokenFile)
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
