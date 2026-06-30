package config

import (
	"log"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// ============================================================
// ServerConfig 服务端配置
// ============================================================

type ServerConfig struct {
	GRPC          GRPCConfig          `yaml:"grpc"`
	Router        RouterConfig        `yaml:"router"`
	Dispatch      DispatchConfig      `yaml:"dispatch"`
	Fingerprint   FingerprintConfig   `yaml:"fingerprint"`
	Portrait      PortraitConfig      `yaml:"portrait"`
	Output        OutputConfig        `yaml:"output"`
	Alert         AlertConfig         `yaml:"alert"`
	TLS           TLSConfig           `yaml:"tls"`
	DirectConnect DirectConnectConfig `yaml:"direct_connect"` // ← 新增
	WALDir        string              `yaml:"wal_dir"`        // WAL 日志目录

}

// ============
// DirectConnectConfig 模式三：直连模式配置
// 客户端通过 LD_PRELOAD 劫持 TCP 连接，经 TLS 直连安全代理
// ============

type DirectConnectConfig struct {
	Enabled    bool   `yaml:"enabled"`
	ListenAddr string `yaml:"listen_addr"`
	CertFile   string `yaml:"cert_file"`
	KeyFile    string `yaml:"key_file"`

	// 连接池
	MaxConns    int    `yaml:"max_conns"`
	MaxPerHost  int    `yaml:"max_per_host"`
	MaxLifetime string `yaml:"max_lifetime"` // YAML 里用字符串 "30m"，加载时解析
	MaxIdle     string `yaml:"max_idle"`

	// 清理
	JanitorInterval string `yaml:"janitor_interval"`

	// 超时
	DialTimeout         string `yaml:"dial_timeout"`
	TLSHandshakeTimeout string `yaml:"tls_handshake_timeout"`
	RequestReadTimeout  string `yaml:"request_read_timeout"`
	WriteTimeout        string `yaml:"write_timeout"`
	ReadTimeout         string `yaml:"read_timeout"`

	// 帧限制
	MaxPayloadSize  int `yaml:"max_payload_size"`
	MaxResponseSize int `yaml:"max_response_size"`
}
type OutputConfig struct {
	MaxSize         int  `yaml:"max_size"`          // Pull 队列最大容量
	SenderEnable    bool `yaml:"sender_enable"`     // 是否启用 Sender 转发（默认 true）
	SenderWorkers   int  `yaml:"sender_workers"`    // Sender Worker 并发数（默认 4）
	SenderQueueSize int  `yaml:"sender_queue_size"` // 每个 Worker 队列容量（默认 1024）
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

// FingerprintConfig 指纹匹配配置
type FingerprintConfig struct {
	DBPath string `yaml:"db_path"`
	// 预设模式，不填则逐维度自定义
	// "strict" = 全部 block（等同于原行为）
	// "standard" = uuid/os block + ip/port/protocol audit（推荐）
	// "relaxed" = uuid block + 其余全部 audit
	// 留空或 "custom" = 用下面 Dimensions 逐项配置
	MatchMode  string            `yaml:"match_mode"`
	Dimensions []DimensionPolicy `yaml:"dimensions"` // 自定义逐维度策略
}

// 标准预设表
var presetModes = map[string]map[string]string{
	"strict": {
		"os": "block", "ip": "block", "port": "block", "protocol": "block",
	},
	"standard": {
		"os": "block", "ip": "audit", "port": "audit", "protocol": "audit",
	},
	"relaxed": {
		"os": "audit", "ip": "audit", "port": "audit", "protocol": "audit",
	},
}

// DimensionPolicy 单个维度的匹配策略
type DimensionPolicy struct {
	Name   string `yaml:"name"`   // os | ip | port | protocol
	Action string `yaml:"action"` // block | audit | ignore
}
type PortraitConfig struct {
	Enable       bool   `yaml:"enable"`
	DBPath       string `yaml:"db_path"`
	HistoryLimit int    `yaml:"history_limit"`
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
			DBPath:    "data/fingerprint.db",
			MatchMode: "standard",
		},
		Portrait: PortraitConfig{
			Enable:       true,
			DBPath:       "data/portrait.db",
			HistoryLimit: 10,
		},
		Output: OutputConfig{
			MaxSize:         10000,
			SenderEnable:    true,
			SenderWorkers:   4,
			SenderQueueSize: 1024,
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
		DirectConnect: DirectConnectConfig{
			Enabled:             false,
			ListenAddr:          ":9999",
			CertFile:            "certs/server.crt",
			KeyFile:             "certs/server.key",
			MaxConns:            1000,
			MaxPerHost:          20,
			MaxLifetime:         "30m",
			MaxIdle:             "5m",
			JanitorInterval:     "30s",
			DialTimeout:         "5s",
			TLSHandshakeTimeout: "10s",
			RequestReadTimeout:  "60s",
			WriteTimeout:        "10s",
			ReadTimeout:         "10s",
			MaxPayloadSize:      1 << 20,  // 1MB
			MaxResponseSize:     10 << 20, // 10MB
		},
		WALDir: "./data/wal",
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

// ParseDuration 解析时间字符串，空字符串或解析失败返回默认值
func ParseDuration(s string, defaultVal time.Duration) time.Duration {
	if s == "" {
		return defaultVal
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		log.Printf("WARN: invalid duration %q, using default %v", s, defaultVal)
		return defaultVal
	}
	return d
}
