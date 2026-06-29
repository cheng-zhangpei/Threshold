package configs

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// ClientConfig 是客户端的完整配置结构
type TLSMode string

const (
	TLSModeStrict     TLSMode = "strict"     // 严格模式：证书缺失直接退出
	TLSModePermissive TLSMode = "permissive" // 宽容模式：证书缺失则降级（当前行为）
	TLSModeNone       TLSMode = "none"       // 关闭 TLS
)

type ClientConfig struct {
	// 全局用户ID，若各模块未单独指定，则使用此值
	UserID string `yaml:"user_id"`

	// TLS 配置（全局生效）
	TLS TLSConfig `yaml:"tls"`

	// 模式一：原生 gRPC 代理（为 IDV Client 服务）
	Proxy struct {
		ListenAddr string `yaml:"listen_addr"` // 监听地址，如 "127.0.0.1:9090"
		ServerAddr string `yaml:"server_addr"` // 服务端 gRPC 地址
		DeviceUUID string `yaml:"device_uuid"` // 设备 UUID，留空则自动采集
		OSType     string `yaml:"os_type"`     // 操作系统类型，留空则自动检测
		UserID     string `yaml:"user_id"`     // 若为空，则使用全局 UserID
	} `yaml:"proxy"`

	// 模式二：SOCKS5 转 gRPC 代理（为通用应用服务）
	Socks5 struct {
		Enabled    bool   `yaml:"enabled"`     // 是否启用
		ListenAddr string `yaml:"listen_addr"` // SOCKS5 监听地址，如 "127.0.0.1:1080"
		UserID     string `yaml:"user_id"`     // 若为空，则使用全局 UserID
	} `yaml:"socks5"`
}

type TLSConfig struct {
	Mode       TLSMode `yaml:"mode"`        // strict / permissive / none
	CACert     string  `yaml:"ca_cert"`     // CA 证书路径
	ClientCert string  `yaml:"client_cert"` // 客户端证书路径，留空则自动检测
	ClientKey  string  `yaml:"client_key"`  // 客户端私钥路径，留空则自动检测
}

// Validate 校验 TLS 配置合法性
func (t *TLSConfig) Validate() error {
	switch t.Mode {
	case TLSModeStrict, TLSModePermissive, TLSModeNone:
	default:
		return fmt.Errorf("invalid tls.mode: %q, must be strict, permissive, or none", t.Mode)
	}
	if t.Mode == TLSModeStrict {
		if t.CACert == "" {
			return fmt.Errorf("tls.mode=strict requires ca_cert")
		}
		// client_cert 和 client_key 允许留空，下面 load 时会自动兜底检测
	}
	return nil
}

func LoadClientConfig(path string) (*ClientConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}
	var cfg ClientConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	// 默认值：未配置 tls 时保持 permissive 向后兼容
	if cfg.TLS.Mode == "" {
		cfg.TLS.Mode = TLSModePermissive
	}
	if err := cfg.TLS.Validate(); err != nil {
		return nil, fmt.Errorf("tls config invalid: %w", err)
	}
	// 设置默认值（若字段为零值）
	if cfg.Proxy.ListenAddr == "" {
		cfg.Proxy.ListenAddr = "127.0.0.1:9090"
	}
	if cfg.Proxy.ServerAddr == "" {
		cfg.Proxy.ServerAddr = "127.0.0.1:50051"
	}
	if cfg.Socks5.ListenAddr == "" {
		cfg.Socks5.ListenAddr = "127.0.0.1:1080"
	}
	if cfg.UserID == "" {
		cfg.UserID = "default-user"
	}
	return &cfg, nil
}
