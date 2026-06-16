package configs

import (
	"os"

	"gopkg.in/yaml.v3"
)

// ClientConfig 是客户端的完整配置结构
type ClientConfig struct {
	// 全局用户ID，若各模块未单独指定，则使用此值
	UserID string `yaml:"user_id"`

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

// LoadClientConfig 从 YAML 文件加载配置，并填充默认值
func LoadClientConfig(path string) (*ClientConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg ClientConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
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
