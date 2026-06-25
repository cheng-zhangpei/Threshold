package pki

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestInitCA_Success(t *testing.T) {
	dir := t.TempDir()

	ca, err := InitCA(dir)
	if err != nil {
		t.Fatalf("InitCA: %v", err)
	}

	if ca.Cert == nil || ca.Key == nil {
		t.Fatal("expected non-nil cert and key")
	}
	if !ca.Cert.IsCA {
		t.Fatal("expected IsCA=true")
	}
	if ca.Cert.Subject.CommonName != "Threshold CA" {
		t.Errorf("CN: got %s", ca.Cert.Subject.CommonName)
	}
}

func TestInitCA_TwiceFails(t *testing.T) {
	dir := t.TempDir()

	_, err := InitCA(dir)
	if err != nil {
		t.Fatalf("first InitCA: %v", err)
	}

	_, err = InitCA(dir)
	if err == nil {
		t.Fatal("expected error on second init")
	}
}

func TestLoadCA_Success(t *testing.T) {
	dir := t.TempDir()

	ca1, _ := InitCA(dir)
	ca2, err := LoadCA(dir)
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}

	if ca1.Cert.SerialNumber.Cmp(ca2.Cert.SerialNumber) != 0 {
		t.Fatal("serial number mismatch")
	}
}

func TestIssueCert_Server(t *testing.T) {
	dir := t.TempDir()
	ca, _ := InitCA(dir)

	certDir := filepath.Join(dir, "certs")
	bundle, err := ca.IssueCert(CertRequest{
		Type:      CertTypeServer,
		Hosts:     []string{"127.0.0.1", "localhost"},
		ValidDays: 365,
	}, certDir)
	if err != nil {
		t.Fatalf("IssueCert: %v", err)
	}

	if _, err := os.Stat(bundle.CertPath); os.IsNotExist(err) {
		t.Fatal("cert file not created")
	}
	if _, err := os.Stat(bundle.KeyPath); os.IsNotExist(err) {
		t.Fatal("key file not created")
	}

	// 验证证书能加载
	_, err = tls.LoadX509KeyPair(bundle.CertPath, bundle.KeyPath)
	if err != nil {
		t.Fatalf("LoadX509KeyPair: %v", err)
	}
}

func TestIssueCert_Client(t *testing.T) {
	dir := t.TempDir()
	ca, _ := InitCA(dir)

	certDir := filepath.Join(dir, "certs")
	bundle, err := ca.IssueCert(CertRequest{
		Type:      CertTypeClient,
		UUID:      "test-device-001",
		ValidDays: 365,
	}, certDir)
	if err != nil {
		t.Fatalf("IssueCert: %v", err)
	}

	// 验证证书 CN 是 UUID
	certPEM, _ := os.ReadFile(bundle.CertPath)
	block, _ := pem.Decode(certPEM)
	cert, _ := x509.ParseCertificate(block.Bytes)

	if cert.Subject.CommonName != "test-device-001" {
		t.Errorf("CN: got %s, want test-device-001", cert.Subject.CommonName)
	}
}

func TestIssueCert_ClientNoUUID_Fails(t *testing.T) {
	dir := t.TempDir()
	ca, _ := InitCA(dir)

	_, err := ca.IssueCert(CertRequest{
		Type: CertTypeClient,
		UUID: "",
	}, filepath.Join(dir, "certs"))
	if err == nil {
		t.Fatal("expected error for empty UUID")
	}
}

func TestMTLS_Handshake(t *testing.T) {
	dir := t.TempDir()
	ca, _ := InitCA(dir)

	certDir := filepath.Join(dir, "certs")

	// 签发服务端证书
	serverBundle, _ := ca.IssueCert(CertRequest{
		Type:  CertTypeServer,
		Hosts: []string{"127.0.0.1"},
	}, certDir)

	// 签发客户端证书
	clientBundle, _ := ca.IssueCert(CertRequest{
		Type: CertTypeClient,
		UUID: "test-device",
	}, certDir)

	// 构建 mTLS 配置
	serverTLS, err := ServerTLSConfig(serverBundle.CertPath, serverBundle.KeyPath, ca.CertPath)
	if err != nil {
		t.Fatalf("ServerTLSConfig: %v", err)
	}

	clientTLS, err := ClientTLSConfig(clientBundle.CertPath, clientBundle.KeyPath, ca.CertPath)
	if err != nil {
		t.Fatalf("ClientTLSConfig: %v", err)
	}

	// 启动 TLS 服务端
	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer ln.Close()

	// 服务端接受一个连接
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// 读一个字节确认连接正常
		buf := make([]byte, 1)
		conn.Read(buf)
	}()

	// 客户端连接
	conn, err := tls.Dial("tcp", ln.Addr().String(), clientTLS)
	if err != nil {
		t.Fatalf("tls.Dial: %v", err)
	}
	defer conn.Close()

	// 验证连接成功
	if conn.ConnectionState().PeerCertificates == nil {
		t.Fatal("expected peer certificates")
	}
}
