package pki

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// ServerTLSConfig 构建服务端 mTLS 配置
// certFile/keyFile: 服务端证书和私钥
// caFile: CA 证书（用于验证客户端证书）
// 如果 caFile 为空，退化为单向 TLS（不验证客户端）
func ServerTLSConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
	serverCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load server cert: %w", err)
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS12,
	}

	if caFile != "" {
		caCert, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read CA cert: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA cert")
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return cfg, nil
}

// ClientTLSConfig 构建客户端 mTLS 配置
// certFile/keyFile: 客户端证书和私钥
// caFile: CA 证书（用于验证服务端证书）
// 如果 certFile/keyFile 为空，退化为单向 TLS（不提供客户端证书）
func ClientTLSConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	// 加载 CA 证书（验证服务端）
	if caFile != "" {
		caCert, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read CA cert: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA cert")
		}
		cfg.RootCAs = pool
	}

	// 加载客户端证书（向服务端证明身份）
	if certFile != "" && keyFile != "" {
		clientCert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("load client cert: %w", err)
		}
		cfg.Certificates = []tls.Certificate{clientCert}
	}

	return cfg, nil
}
