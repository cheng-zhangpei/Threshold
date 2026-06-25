package pki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// CA 证书颁发机构
type CA struct {
	Cert     *x509.Certificate
	Key      *rsa.PrivateKey
	CertPath string
	KeyPath  string
}

// InitCA 生成 CA 自签名证书（仅首次）
func InitCA(caDir string) (*CA, error) {
	certPath := filepath.Join(caDir, "ca.crt")
	keyPath := filepath.Join(caDir, "ca.key")

	// 检查是否已存在
	if _, err := os.Stat(certPath); err == nil {
		return nil, fmt.Errorf("CA already exists at %s", certPath)
	}

	// 生成 CA 私钥（RSA 2048）
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}

	// 生成随机序列号
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}

	// CA 证书模板
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "Threshold CA",
			Organization: []string{"Threshold"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour), // 10 年
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	// 自签名
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("create CA cert: %w", err)
	}

	// 解析回 x509.Certificate（用于后续签发）
	caCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse CA cert: %w", err)
	}

	// 写入文件
	if err := os.MkdirAll(caDir, 0700); err != nil {
		return nil, err
	}

	if err := writeCertPEM(certPath, certDER); err != nil {
		return nil, err
	}
	if err := writeKeyPEM(keyPath, caKey); err != nil {
		return nil, err
	}

	return &CA{Cert: caCert, Key: caKey, CertPath: certPath, KeyPath: keyPath}, nil
}

// LoadCA 从文件加载已有 CA
func LoadCA(caDir string) (*CA, error) {
	certPath := filepath.Join(caDir, "ca.crt")
	keyPath := filepath.Join(caDir, "ca.key")

	// 加载证书
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("invalid CA cert PEM")
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA cert: %w", err)
	}

	// 加载私钥
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read CA key: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("invalid CA key PEM")
	}
	caKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA key: %w", err)
	}

	return &CA{Cert: caCert, Key: caKey, CertPath: certPath, KeyPath: keyPath}, nil
}

// ============================================================
// PEM 写入辅助
// ============================================================

func writeCertPEM(path string, certDER []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
}

func writeKeyPEM(path string, key *rsa.PrivateKey) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}
