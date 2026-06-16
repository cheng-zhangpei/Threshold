package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

// ============================================================
// ServerConfig 服务端配置
// ============================================================

type ServerConfig struct {
	GRPC        GRPCConfig        `yaml:"grpc"`
	Router      RouterConfig      `yaml:"router"`
	Dispatch    DispatchConfig    `yaml:"dispatch"`
	Fingerprint FingerprintConfig `yaml:"fingerprint"`
	Portrait    PortraitConfig    `yaml:"portrait"`
	Output      OutputConfig      `yaml:"output"`
	Alert       AlertConfig       `yaml:"alert"`
	TLS         TLSConfig         `yaml:"tls"`
}

type GRPCConfig struct {
	ListenAddr string `yaml:"listen_addr"`
	RateLimit  int    `yaml:"rate_limit"`
	BucketSize int    `yaml:"bucket_size"`
}

// RouterConfig Router 路由配置

type DispatchConfig struct {
	Enabled                bool `yaml:"enabled"`
	MinWorkers             int  `yaml:"min_workers"`
	MaxWorkers             int  `yaml:"max_workers"`
	ScaleUpThreshold       int  `yaml:"scale_up_threshold"`
	ScaleUpStep            int  `yaml:"scale_up_step"`
	MaxQueueSize           int  `yaml:"max_queue_size"`
	IdleTimeoutSec         int  `yaml:"idle_timeout_sec"`
	HealthCheckIntervalSec int  `yaml:"health_check_interval_sec"`
}

type FingerprintConfig struct {
	DBPath string `yaml:"db_path"`
}

type PortraitConfig struct {
	Enable       bool   `yaml:"enable"`
	DBPath       string `yaml:"db_path"`
	HistoryLimit int    `yaml:"history_limit"`
}

type OutputConfig struct {
	MaxSize int `yaml:"max_size"`
}

type AlertConfig struct {
}

type TLSConfig struct {
	Enabled           bool   `yaml:"enabled"`
	CertFile          string `yaml:"cert_file"`
	KeyFile           string `yaml:"key_file"`
	CAFile            string `yaml:"ca_file"`
	RequireClientAuth bool   `yaml:"require_client_auth"`
}

// ============================================================
// ClientConfig 客户端配置
// ============================================================

type ClientConfig struct {
	Redirect  RedirectConfig  `yaml:"redirect"`
	Collector CollectorConfig `yaml:"collector"`
	Proxy     ProxyConfig     `yaml:"proxy"`
	TLS       TLSConfig       `yaml:"tls"`
}

type RedirectConfig struct {
	LocalPort  int    `yaml:"local_port"`
	TargetHost string `yaml:"target_host"`
	TargetPort int    `yaml:"target_port"`
}

type CollectorConfig struct {
}

type ProxyConfig struct {
	ListenAddr string `yaml:"listen_addr"`
	ServerAddr string `yaml:"server_addr"`
	DeviceUUID string `yaml:"device_uuid"`
}

func LoadServerConfig(path string) (*ServerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := DefaultServerConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func LoadClientConfig(path string) (*ClientConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := DefaultClientConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func DefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		GRPC: GRPCConfig{
			ListenAddr: ":50051",
			RateLimit:  1000,
			BucketSize: 2000,
		},
		Router: RouterConfig{
			Enabled:           true,
			R2Config:          "configs/router_rules.yaml", // 默认配置文件路径
			Rules:             nil,                         // 规则通过文件加载
			Consumers:         4,
			QueueSize:         4096,
			OperationRiskFile: "", // 旧的硬编码方式，留空表示使用 R2Config
		},
		Dispatch: DispatchConfig{
			Enabled:                true,
			MinWorkers:             2,
			MaxWorkers:             64,
			ScaleUpThreshold:       100,
			ScaleUpStep:            4,
			MaxQueueSize:           10000,
			IdleTimeoutSec:         30,
			HealthCheckIntervalSec: 5,
		},
		Fingerprint: FingerprintConfig{
			DBPath: "data/fingerprint.db",
		},
		Portrait: PortraitConfig{
			Enable:       true,
			DBPath:       "data/portrait.db",
			HistoryLimit: 10,
		},
		Output: OutputConfig{
			MaxSize: 10000,
		},
		Alert: AlertConfig{
			// 空结构，无需设置
		},
		TLS: TLSConfig{
			Enabled:           false,
			CertFile:          "",
			KeyFile:           "",
			CAFile:            "",
			RequireClientAuth: false,
		},
	}
}

func DefaultClientConfig() *ClientConfig {
	return &ClientConfig{
		Redirect: RedirectConfig{
			LocalPort: 8080,
		},
		Proxy: ProxyConfig{
			ListenAddr: ":9090",
			ServerAddr: "localhost:50051",
		},
		TLS: TLSConfig{
			Enabled: false,
		},
	}
}
