package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

// ============================================================
// ServerConfig 服务端配置
// 从 YAML 文件加载，包含 gRPC 接入层、路由、调度、存储等所有组件的参数。
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

// GRPCConfig gRPC 接入层配置
type GRPCConfig struct {
	ListenAddr string `yaml:"listen_addr"` // 监听地址，如 ":50051"
	RateLimit  int    `yaml:"rate_limit"`  // 令牌桶每秒产生令牌数
	BucketSize int    `yaml:"bucket_size"` // 令牌桶容量
}

// RouterConfig Router 路由配置
type RouterConfig struct {
	// OperationRiskFile 静态风险映射表文件路径（YAML/JSON）
	// 原型阶段使用内置映射，生产阶段从此文件加载
	OperationRiskFile string `yaml:"operation_risk_file"`
}

// DispatchConfig DispatchManager + WorkerPool 配置
type DispatchConfig struct {
	MinWorkers             int `yaml:"min_workers"`
	MaxWorkers             int `yaml:"max_workers"`
	ScaleUpThreshold       int `yaml:"scale_up_threshold"`
	ScaleUpStep            int `yaml:"scale_up_step"`
	MaxQueueSize           int `yaml:"max_queue_size"`
	IdleTimeoutSec         int `yaml:"idle_timeout_sec"`
	HealthCheckIntervalSec int `yaml:"health_check_interval_sec"`
}

// FingerprintConfig 指纹匹配引擎配置
type FingerprintConfig struct {
	DBPath string `yaml:"db_path"` // bbolt 数据库文件路径
}

// PortraitConfig 用户画像存储配置
type PortraitConfig struct {
	DBPath       string `yaml:"db_path"`       // bbolt 数据库文件路径
	HistoryLimit int    `yaml:"history_limit"` // 加载最近 N 次连接摘要
}

// OutputConfig OutputBuffer 配置
type OutputConfig struct {
	MaxSize int `yaml:"max_size"` // 队列最大容量
}

// AlertConfig AlertQueue 配置
type AlertConfig struct {
	// 暂无特殊配置，告警推送地址由 gRPC 连接决定
}

// TLSConfig TLS/mTLS 配置
type TLSConfig struct {
	Enabled           bool   `yaml:"enabled"`             // 是否启用 TLS
	CertFile          string `yaml:"cert_file"`           // 服务端证书路径
	KeyFile           string `yaml:"key_file"`            // 服务端私钥路径
	CAFile            string `yaml:"ca_file"`             // CA 证书路径（mTLS 时使用）
	RequireClientAuth bool   `yaml:"require_client_auth"` // 是否要求客户端证书（mTLS）
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

// RedirectConfig 重定向模块配置
type RedirectConfig struct {
	LocalPort  int    `yaml:"local_port"`  // 本地代理监听端口
	TargetHost string `yaml:"target_host"` // OpenStack 服务端地址
	TargetPort int    `yaml:"target_port"` // OpenStack 服务端端口
}

// CollectorConfig 行为采集器配置
type CollectorConfig struct {
	// 暂无特殊配置，后续可扩展采集策略
}

// ProxyConfig 本地代理配置
type ProxyConfig struct {
	ListenAddr string `yaml:"listen_addr"` // 本地代理监听地址
	ServerAddr string `yaml:"server_addr"` // 安全代理服务端地址
	DeviceUUID string `yaml:"device_uuid"` // 设备 UUID（首次启动时自动采集）
}

// ============================================================
// LoadServerConfig 从 YAML 文件加载服务端配置
// ============================================================

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

// ============================================================
// LoadClientConfig 从 YAML 文件加载客户端配置
// ============================================================

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

// DefaultServerConfig 返回服务端默认配置
func DefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		GRPC: GRPCConfig{
			ListenAddr: ":50051",
			RateLimit:  1000,
			BucketSize: 2000,
		},
		Dispatch: DispatchConfig{
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
			DBPath:       "data/portrait.db",
			HistoryLimit: 10,
		},
		Output: OutputConfig{
			MaxSize: 10000,
		},
		TLS: TLSConfig{
			Enabled: false,
		},
	}
}

// DefaultClientConfig 返回客户端默认配置
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
