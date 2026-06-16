package router_v2

import (
	"os"

	"gopkg.in/yaml.v3"
)

// MatchRule 匹配规则
type MatchRule struct {
	Method string `yaml:"method"` // HTTP方法 或 "TCP" 或 "*"
	Path   string `yaml:"path"`   // 路径模式，支持 * 通配符
}

// Rule 单条规则
type Rule struct {
	ID        string    `yaml:"id"`
	Match     MatchRule `yaml:"match"`
	RiskLevel string    `yaml:"risk_level"` // "L0","L1","L2","L3"
	Priority  int       `yaml:"priority"`
}

// Config 路由器配置
type Config struct {
	Rules []Rule `yaml:"rules"`
}

// LoadConfig 从 YAML 文件加载配置
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
