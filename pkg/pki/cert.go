package pki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// CertType 证书类型
type CertType string

const (
	CertTypeServer CertType = "server"
	CertTypeClient CertType = "client"
)

// CertRequest 证书签发请求
type CertRequest struct {
	Type      CertType
	UUID      string   // 客户端证书：设备 UUID（写入 CN）
	Hosts     []string // 服务端证书：IP 或域名（写入 SAN）
	ValidDays int      // 有效期（天）
}

// CertBundle 签发结果
type CertBundle struct {
	CertPath string
	KeyPath  string
}

// IssueCert 用 CA 签发证书
func (ca *CA) IssueCert(req CertRequest, outputDir string) (*CertBundle, error) {
	// 生成私钥
	certKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	// 序列号
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}

	validDays := req.ValidDays
	if validDays <= 0 {
		validDays = 365
	}

	// 构建证书模板
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Duration(validDays) * 24 * time.Hour),
	}

	switch req.Type {
	case CertTypeServer:
		template.Subject = pkix.Name{
			CommonName:   "Threshold Server",
			Organization: []string{"Threshold"},
		}
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment

		// SAN: IP 和域名
		for _, host := range req.Hosts {
			if ip := net.ParseIP(host); ip != nil {
				template.IPAddresses = append(template.IPAddresses, ip)
			} else {
				template.DNSNames = append(template.DNSNames, host)
			}
		}

	case CertTypeClient:
		uuid := req.UUID
		if uuid == "" {
			return nil, fmt.Errorf("client cert requires UUID")
		}
		template.Subject = pkix.Name{
			CommonName:   uuid,
			Organization: []string{"Threshold"},
		}
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		template.KeyUsage = x509.KeyUsageDigitalSignature

	default:
		return nil, fmt.Errorf("unknown cert type: %s", req.Type)
	}

	// 用 CA 签发
	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.Cert, &certKey.PublicKey, ca.Key)
	if err != nil {
		return nil, fmt.Errorf("create cert: %w", err)
	}

	// 确定文件名
	var certName string
	switch req.Type {
	case CertTypeServer:
		certName = "server"
	case CertTypeClient:
		certName = req.UUID
	}

	// 写入文件
	if err := os.MkdirAll(outputDir, 0700); err != nil {
		return nil, err
	}

	certPath := filepath.Join(outputDir, certName+".crt")
	keyPath := filepath.Join(outputDir, certName+".key")

	if err := writeCertPEM(certPath, certDER); err != nil {
		return nil, err
	}
	if err := writeKeyPEM(keyPath, certKey); err != nil {
		return nil, err
	}

	return &CertBundle{CertPath: certPath, KeyPath: keyPath}, nil
}
