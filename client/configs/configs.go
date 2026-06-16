package configs

import (
	"encoding/json"
	"os"
)

type Config struct {
	// gRPC 服务端地址
	ServerAddr string `json:"server_addr"`
	// 客户端 gRPC 监听地址（模式一）
	GRPCListenAddr string `json:"grpc_listen_addr"`
	// SOCKS5 监听地址（模式二）
	Socks5ListenAddr string `json:"socks5_listen_addr"`
	// 设备信息
	DeviceUUID string `json:"device_uuid"` // 留空则自动采集
	OSType     string `json:"os_type"`     // 留空则自动检测
	UserID     string `json:"user_id"`     // 写死，如 "socks5_user"
}

// LoadConfig 从文件加载配置，或使用默认值
func LoadConfig(path string) (*Config, error) {
	cfg := &Config{
		ServerAddr:       "127.0.0.1:50051",
		GRPCListenAddr:   "127.0.0.1:9090",
		Socks5ListenAddr: "127.0.0.1:1080",
		UserID:           "socks5_user", // 默认写死
	}
	if path == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}
