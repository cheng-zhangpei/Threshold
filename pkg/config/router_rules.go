package config

type MatchRule struct {
	Method string `yaml:"method"`
	Path   string `yaml:"path"`
}
type Rule struct {
	ID        string    `yaml:"id"`
	Match     MatchRule `yaml:"match"`
	RiskLevel string    `yaml:"risk_level"` // "L0","L1","L2","L3"
	Priority  int       `yaml:"priority"`
}
type RouterConfig struct {
	Enabled   bool   `yaml:"enabled"`
	R2Config  string `yaml:"r2_config"`
	Rules     []Rule `yaml:"rules"`
	Consumers int    `yaml:"consumers"`
	// QueueSize 缓冲队列容量，超过则触发背压
	QueueSize int `yaml:"queue_size"`
	// OperationRiskFile 静态风险映射表文件路径
	OperationRiskFile string `yaml:"operation_risk_file"`
}
